#!/usr/bin/env python3
"""
lambda_inventory_download.py

Enumerate AWS Lambda functions across AWS CLI profiles and enabled regions,
collect detailed configuration, and download ZIP deployment packages.

Profiles:
  - With --profiles: scans only the supplied profile names.
  - Without --profiles: scans all named AWS CLI profiles.
  - If no named profiles exist: uses the default credential provider chain,
    including an EC2 instance profile/role when available.

Container-image functions are inventoried but are not pulled from ECR.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound
except ImportError:
    print("Missing dependency: boto3. Install with: python3 -m pip install boto3", file=sys.stderr)
    raise SystemExit(2)

LOG = logging.getLogger("lambda-inventory")
BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:180] or "unknown"


def write_jsonl(handle, item: Dict[str, Any]) -> None:
    handle.write(json.dumps(item, ensure_ascii=False, default=json_default) + "\n")
    handle.flush()


def error_details(exc: Exception) -> Dict[str, str]:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return {
            "error_code": str(error.get("Code", "ClientError")),
            "error_message": str(error.get("Message", exc)),
        }
    return {"error_code": type(exc).__name__, "error_message": str(exc)}


def profiles_to_scan(requested: Optional[List[str]]) -> List[Optional[str]]:
    if requested:
        return list(dict.fromkeys(requested))
    named = boto3.Session().available_profiles
    if named:
        return named
    LOG.info("No named AWS profiles found; using the default credential chain (including an EC2 role, if attached).")
    return [None]


def make_session(profile: Optional[str]) -> boto3.Session:
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def identity(session: boto3.Session) -> Dict[str, str]:
    result = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
    return {
        "account_id": str(result.get("Account", "unknown")),
        "principal_arn": str(result.get("Arn", "unknown")),
        "principal_id": str(result.get("UserId", "unknown")),
    }


def enabled_regions(session: boto3.Session) -> List[str]:
    bootstrap_region = session.region_name or "us-east-1"
    ec2 = session.client("ec2", region_name=bootstrap_region, config=BOTO_CONFIG)
    response = ec2.describe_regions(AllRegions=False)
    return sorted(region["RegionName"] for region in response.get("Regions", []))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_file(url: str, destination: Path, timeout: int) -> Dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_name = tempfile.mkstemp(prefix="lambda-", suffix=".part", dir=str(destination.parent))
    os.close(temp_fd)
    temp_path = Path(temp_name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "lambda-audit-downloader/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response, temp_path.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        temp_path.replace(destination)
        return {
            "status": "downloaded",
            "path": str(destination),
            "bytes": destination.stat().st_size,
            "sha256": sha256_file(destination),
        }
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def csv_record(record: Dict[str, Any]) -> Dict[str, Any]:
    cfg = record.get("configuration", {})
    code = record.get("code", {})
    dl = record.get("download", {})
    return {
        "collected_at": record.get("collected_at"),
        "profile": record.get("profile"),
        "account_id": record.get("account_id"),
        "principal_arn": record.get("principal_arn"),
        "region": record.get("region"),
        "function_name": cfg.get("FunctionName"),
        "function_arn": cfg.get("FunctionArn"),
        "package_type": cfg.get("PackageType", "Zip"),
        "runtime": cfg.get("Runtime"),
        "handler": cfg.get("Handler"),
        "role": cfg.get("Role"),
        "version": cfg.get("Version"),
        "architectures": json.dumps(cfg.get("Architectures", [])),
        "memory_mb": cfg.get("MemorySize"),
        "timeout_seconds": cfg.get("Timeout"),
        "code_size": cfg.get("CodeSize"),
        "code_sha256_aws": cfg.get("CodeSha256"),
        "last_modified": cfg.get("LastModified"),
        "state": cfg.get("State"),
        "last_update_status": cfg.get("LastUpdateStatus"),
        "kms_key_arn": cfg.get("KMSKeyArn"),
        "signing_profile_version_arn": cfg.get("SigningProfileVersionArn"),
        "image_uri": code.get("ImageUri"),
        "download_status": dl.get("status"),
        "download_path": dl.get("path"),
        "download_bytes": dl.get("bytes"),
        "download_sha256": dl.get("sha256"),
        "download_error_code": dl.get("error_code"),
        "download_error_message": dl.get("error_message"),
        "tags_json": json.dumps(record.get("tags", {}), ensure_ascii=False),
        "layers_json": json.dumps(cfg.get("Layers", []), ensure_ascii=False, default=json_default),
        "environment_keys_json": json.dumps(sorted((cfg.get("Environment", {}).get("Variables") or {}).keys())),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inventory Lambda functions and download ZIP deployment packages across AWS profiles and regions.")
    parser.add_argument("--profiles", nargs="+", help="Named AWS CLI profiles. Default: all named profiles, or default credential chain if none exist.")
    parser.add_argument("--regions", nargs="+", help="Regions to scan. Default: all enabled regions per account.")
    parser.add_argument("--output-dir", default="lambda_audit", help="Output directory.")
    parser.add_argument("--include-versions", action="store_true", help="Also inventory and download published versions. Default: only $LATEST per function.")
    parser.add_argument("--no-download", action="store_true", help="Inventory only; do not download ZIP packages.")
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing ZIP instead of recording it as already present.")
    parser.add_argument("--download-timeout", type=int, default=120, help="Download timeout in seconds. Default: 120.")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    root = Path(args.output_dir).expanduser().resolve()
    packages = root / "packages"
    root.mkdir(parents=True, exist_ok=True)
    packages.mkdir(parents=True, exist_ok=True)

    inventory_jsonl = root / "lambda_inventory.jsonl"
    inventory_csv = root / "lambda_inventory.csv"
    errors_jsonl = root / "lambda_errors.jsonl"
    summary_json = root / "lambda_summary.json"

    profiles = profiles_to_scan(args.profiles)
    summary = {
        "started_at": now_utc(),
        "profiles_requested": [p or "<default-credential-chain>" for p in profiles],
        "profiles_completed": 0,
        "profiles_failed": 0,
        "regions_attempted": 0,
        "regions_failed": 0,
        "functions_inventory_records": 0,
        "zip_packages_downloaded": 0,
        "zip_packages_already_present": 0,
        "container_image_functions": 0,
        "download_failures": 0,
    }

    sample = {"configuration": {}, "code": {}, "download": {}}
    fields = list(csv_record(sample).keys())

    with inventory_jsonl.open("w", encoding="utf-8") as inventory_handle, \
         inventory_csv.open("w", encoding="utf-8", newline="") as csv_handle, \
         errors_jsonl.open("w", encoding="utf-8") as error_handle:
        writer = csv.DictWriter(csv_handle, fieldnames=fields)
        writer.writeheader()

        for profile in profiles:
            display_profile = profile or "<default-credential-chain>"
            LOG.info("Processing profile: %s", display_profile)
            try:
                session = make_session(profile)
                who = identity(session)
            except Exception as exc:
                details = error_details(exc)
                write_jsonl(error_handle, {"time": now_utc(), "scope": "profile", "profile": display_profile, **details})
                summary["profiles_failed"] += 1
                LOG.error("Skipping profile %s: %s", display_profile, details["error_message"])
                continue

            try:
                regions = args.regions or enabled_regions(session)
            except Exception as exc:
                details = error_details(exc)
                if session.region_name:
                    regions = [session.region_name]
                    write_jsonl(error_handle, {"time": now_utc(), "scope": "region-discovery", "profile": display_profile, "fallback_region": session.region_name, **details})
                else:
                    write_jsonl(error_handle, {"time": now_utc(), "scope": "region-discovery", "profile": display_profile, **details})
                    summary["profiles_failed"] += 1
                    continue

            profile_success = False
            for region in regions:
                summary["regions_attempted"] += 1
                try:
                    client = session.client("lambda", region_name=region, config=BOTO_CONFIG)
                    paginator = client.get_paginator("list_functions")
                    paginate_args = {"FunctionVersion": "ALL"} if args.include_versions else {}
                    for page in paginator.paginate(**paginate_args):
                        for listed in page.get("Functions", []):
                            function_name = listed["FunctionName"]
                            qualifier = listed.get("Version") if args.include_versions and listed.get("Version") not in (None, "$LATEST") else None
                            get_args = {"FunctionName": function_name}
                            if qualifier:
                                get_args["Qualifier"] = qualifier

                            try:
                                detail = client.get_function(**get_args)
                                configuration = detail.get("Configuration", listed)
                                code = detail.get("Code", {})
                            except Exception as exc:
                                details = error_details(exc)
                                write_jsonl(error_handle, {"time": now_utc(), "scope": "get-function", "profile": display_profile, "account_id": who["account_id"], "region": region, "function_name": function_name, "qualifier": qualifier, **details})
                                configuration, code = listed, {}

                            try:
                                tags = client.list_tags(Resource=configuration.get("FunctionArn", listed.get("FunctionArn"))).get("Tags", {})
                            except Exception as exc:
                                tags = {}
                                details = error_details(exc)
                                write_jsonl(error_handle, {"time": now_utc(), "scope": "list-tags", "profile": display_profile, "account_id": who["account_id"], "region": region, "function_name": function_name, **details})

                            package_type = configuration.get("PackageType", "Zip")
                            download: Dict[str, Any]
                            if args.no_download:
                                download = {"status": "not_requested"}
                            elif package_type == "Image":
                                download = {"status": "container_image_not_downloaded"}
                                summary["container_image_functions"] += 1
                            elif not code.get("Location"):
                                download = {"status": "unavailable", "error_code": "NoCodeLocation", "error_message": "GetFunction did not return a ZIP download location."}
                                summary["download_failures"] += 1
                            else:
                                version_label = qualifier or "$LATEST"
                                destination = packages / safe_name(display_profile) / who["account_id"] / region / safe_name(function_name) / f"{safe_name(version_label)}.zip"
                                if destination.exists() and not args.overwrite:
                                    download = {"status": "already_present", "path": str(destination.relative_to(root)), "bytes": destination.stat().st_size, "sha256": sha256_file(destination)}
                                    summary["zip_packages_already_present"] += 1
                                else:
                                    try:
                                        download = download_file(code["Location"], destination, args.download_timeout)
                                        download["path"] = str(destination.relative_to(root))
                                        summary["zip_packages_downloaded"] += 1
                                    except Exception as exc:
                                        details = error_details(exc)
                                        download = {"status": "error", **details}
                                        summary["download_failures"] += 1
                                        write_jsonl(error_handle, {"time": now_utc(), "scope": "download", "profile": display_profile, "account_id": who["account_id"], "region": region, "function_name": function_name, "qualifier": qualifier, **details})

                            # Do not persist the temporary presigned Code.Location URL.
                            safe_code = {key: value for key, value in code.items() if key != "Location"}
                            record = {
                                "schema_version": "1.0",
                                "collected_at": now_utc(),
                                "profile": display_profile,
                                **who,
                                "region": region,
                                "configuration": configuration,
                                "code": safe_code,
                                "tags": tags,
                                "download": download,
                            }
                            write_jsonl(inventory_handle, record)
                            writer.writerow(csv_record(record))
                            csv_handle.flush()
                            summary["functions_inventory_records"] += 1
                    profile_success = True
                except Exception as exc:
                    details = error_details(exc)
                    summary["regions_failed"] += 1
                    write_jsonl(error_handle, {"time": now_utc(), "scope": "region", "profile": display_profile, "account_id": who["account_id"], "region": region, **details})
                    LOG.error("Skipping profile=%s region=%s: %s", display_profile, region, details["error_message"])

            if profile_success:
                summary["profiles_completed"] += 1
            else:
                summary["profiles_failed"] += 1

    summary["completed_at"] = now_utc()
    summary["outputs"] = {
        "inventory_jsonl": str(inventory_jsonl),
        "inventory_csv": str(inventory_csv),
        "errors_jsonl": str(errors_jsonl),
        "packages_root": str(packages),
    }
    summary_json.write_text(json.dumps(summary, indent=2, default=json_default), encoding="utf-8")
    LOG.info("Completed: %s", json.dumps(summary, default=json_default))
    return 0 if summary["profiles_completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
