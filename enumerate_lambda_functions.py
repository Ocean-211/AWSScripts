#!/usr/bin/env python3
"""Enumerate and download AWS Lambda code across AWS CLI profiles and regions.

Output layout:
  <output>/<profile>/<region>/<function>/
      metadata.json
      deployment-package.zip          # Zip functions only
      extracted/                       # if --extract is used
      container-image.txt              # Image functions only
  <output>/lambda_summary.csv
  <output>/lambda_inventory.csv
  <output>/lambda_errors.csv

Requirements:
  Python 3.9+
  boto3

Examples:
  python3 enumerate_lambda_functions.py
  python3 enumerate_lambda_functions.py -o lambda-export --extract
  python3 enumerate_lambda_functions.py -p SEC01 DEV01 -r eu-west-1 us-east-1
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shutil
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound
except ImportError:
    sys.exit("[FATAL] boto3 is required. Install it with: python3 -m pip install boto3")

LOG = logging.getLogger("lambda-enumerator")
UTC_NOW = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

SUMMARY_FIELDS = [
    "Profile", "AccountId", "RegionsAttempted", "RegionsSucceeded",
    "FunctionsEnumerated", "ZipPackagesDownloaded", "ContainerImageFunctions",
    "DownloadErrors", "ApiErrors", "TotalErrors", "Status", "OutputDirectory",
]
INVENTORY_FIELDS = [
    "Profile", "AccountId", "Region", "FunctionName", "FunctionArn", "PackageType",
    "Runtime", "Handler", "Role", "CodeSize", "LastModified", "Version",
    "CodeSha256", "DownloadStatus", "LocalPath", "Error",
]
ERROR_FIELDS = ["Timestamp", "Profile", "Region", "Operation", "Target", "ErrorCode", "Error"]


def safe_name(value: str) -> str:
    value = re.sub(r"[\\/:*?\"<>|\s]+", "_", value.strip())
    return value[:180] or "unnamed"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, default=str)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def write_csv(path: Path, fields: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)


def classify_error(exc: Exception) -> Tuple[str, str]:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return str(err.get("Code", "ClientError")), str(err.get("Message", exc))
    return type(exc).__name__, str(exc)


def add_error(errors: List[Dict[str, str]], profile: str, region: str,
              operation: str, target: str, exc: Exception) -> None:
    code, message = classify_error(exc)
    errors.append({
        "Timestamp": UTC_NOW(), "Profile": profile, "Region": region,
        "Operation": operation, "Target": target, "ErrorCode": code, "Error": message,
    })
    LOG.warning("%s | %s | %s | %s: %s", profile, region or "global", operation, code, message)


def get_profiles(requested: Optional[List[str]]) -> List[str]:
    if requested:
        return list(dict.fromkeys(requested))
    return boto3.session.Session().available_profiles


def discover_regions(session: boto3.session.Session, profile: str,
                     requested: Optional[List[str]], config: Config,
                     errors: List[Dict[str, str]]) -> List[str]:
    if requested:
        return list(dict.fromkeys(requested))

    # DescribeRegions returns regions enabled/available to the account. If permission or
    # connectivity blocks it, use the SDK Lambda region catalogue as a safe fallback.
    home = session.region_name or "us-east-1"
    try:
        ec2 = session.client("ec2", region_name=home, config=config)
        response = ec2.describe_regions(AllRegions=False)
        regions = sorted(r["RegionName"] for r in response.get("Regions", []) if r.get("RegionName"))
        if regions:
            return regions
    except Exception as exc:
        add_error(errors, profile, home, "ec2:DescribeRegions", profile, exc)

    fallback = sorted(session.get_available_regions("lambda", partition_name=session.get_partition_for_region(home)))
    LOG.info("%s | using SDK Lambda region catalogue (%d regions)", profile, len(fallback))
    return fallback


def iter_functions(client) -> Iterable[Dict[str, Any]]:
    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        yield from page.get("Functions", [])


def download_file(url: str, destination: Path, timeout: int) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".part", dir=str(destination.parent))
    os.close(fd)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "aws-lambda-audit-export/1.0"})
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response, open(tmp_name, "wb") as out:
            shutil.copyfileobj(response, out, length=1024 * 1024)
        size = os.path.getsize(tmp_name)
        os.replace(tmp_name, destination)
        return size
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def safely_extract(zip_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    base = destination.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            target = (destination / member.filename).resolve()
            if target != base and base not in target.parents:
                raise ValueError(f"Unsafe ZIP path: {member.filename}")
        archive.extractall(destination)


def process_region(session, profile: str, account_id: str, region: str, profile_dir: Path,
                   config: Config, args, inventory: List[Dict[str, Any]],
                   errors: List[Dict[str, str]], stats: Dict[str, int]) -> bool:
    try:
        client = session.client("lambda", region_name=region, config=config)
        functions = list(iter_functions(client))
    except Exception as exc:
        stats["api_errors"] += 1
        add_error(errors, profile, region, "lambda:ListFunctions", region, exc)
        return False

    LOG.info("%s | %s | %d function(s)", profile, region, len(functions))

    for listed in functions:
        function_name = listed.get("FunctionName", "unknown")
        function_dir = profile_dir / safe_name(region) / safe_name(function_name)
        function_dir.mkdir(parents=True, exist_ok=True)
        stats["functions"] += 1

        row = {
            "Profile": profile, "AccountId": account_id, "Region": region,
            "FunctionName": function_name, "FunctionArn": listed.get("FunctionArn", ""),
            "PackageType": listed.get("PackageType", "Zip"), "Runtime": listed.get("Runtime", ""),
            "Handler": listed.get("Handler", ""), "Role": listed.get("Role", ""),
            "CodeSize": listed.get("CodeSize", ""), "LastModified": listed.get("LastModified", ""),
            "Version": listed.get("Version", ""), "CodeSha256": listed.get("CodeSha256", ""),
            "DownloadStatus": "", "LocalPath": "", "Error": "",
        }

        try:
            details = client.get_function(FunctionName=function_name)
            # Preserve the complete API response except the short-lived presigned URL.
            metadata = dict(details)
            code = dict(metadata.get("Code", {}))
            location = code.pop("Location", None)
            metadata["Code"] = code
            atomic_json(function_dir / "metadata.json", metadata)

            package_type = details.get("Configuration", {}).get("PackageType", row["PackageType"])
            row["PackageType"] = package_type

            if package_type == "Image":
                image_uri = details.get("Code", {}).get("ImageUri", "")
                (function_dir / "container-image.txt").write_text(image_uri + "\n", encoding="utf-8")
                row["DownloadStatus"] = "CONTAINER_IMAGE_REFERENCE_SAVED"
                row["LocalPath"] = str((function_dir / "container-image.txt").resolve())
                stats["images"] += 1
            elif location:
                zip_path = function_dir / "deployment-package.zip"
                download_file(location, zip_path, args.download_timeout)
                row["DownloadStatus"] = "DOWNLOADED"
                row["LocalPath"] = str(zip_path.resolve())
                stats["downloaded"] += 1
                if args.extract:
                    safely_extract(zip_path, function_dir / "extracted")
            else:
                raise RuntimeError("GetFunction returned no Code.Location for the Zip package")

        except Exception as exc:
            stats["download_errors"] += 1
            code, message = classify_error(exc)
            row["DownloadStatus"] = "ERROR"
            row["Error"] = f"{code}: {message}"
            add_error(errors, profile, region, "lambda:GetFunction/download", function_name, exc)
            # Preserve ListFunctions metadata even if GetFunction/download fails.
            try:
                atomic_json(function_dir / "list-functions-metadata.json", listed)
            except Exception as write_exc:
                add_error(errors, profile, region, "local:WriteMetadata", function_name, write_exc)

        inventory.append(row)

    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enumerate and download Lambda code across AWS CLI profiles.")
    parser.add_argument("-o", "--output", default="aws-lambda-enumeration", help="Output directory")
    parser.add_argument("-p", "--profiles", nargs="+", help="Profiles to process; default is all configured profiles")
    parser.add_argument("-r", "--regions", nargs="+", help="Regions to process; default is all enabled/discovered regions")
    parser.add_argument("--extract", action="store_true", help="Safely extract downloaded ZIP packages")
    parser.add_argument("--download-timeout", type=int, default=120, help="Seconds allowed for each ZIP download")
    parser.add_argument("--connect-timeout", type=int, default=10)
    parser.add_argument("--read-timeout", type=int, default=60)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def setup_logging(output: Path, verbose: bool) -> None:
    output.mkdir(parents=True, exist_ok=True)
    LOG.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%dT%H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    file_handler = logging.FileHandler(output / "run.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    LOG.handlers.clear()
    LOG.addHandler(console)
    LOG.addHandler(file_handler)


def main() -> int:
    args = parse_args()
    output = Path(args.output).expanduser().resolve()
    setup_logging(output, args.verbose)

    config = Config(
        retries={"max_attempts": max(1, args.max_attempts), "mode": "standard"},
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
    )

    profiles = get_profiles(args.profiles)
    if not profiles:
        LOG.error("No AWS CLI profiles found")
        return 1

    summary: List[Dict[str, Any]] = []
    inventory: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []

    LOG.info("Output directory: %s", output)
    LOG.info("Profiles: %s", ", ".join(profiles))

    for profile in profiles:
        profile_dir = output / safe_name(profile)
        profile_dir.mkdir(parents=True, exist_ok=True)
        stats = defaultdict(int)
        account_id = "UNKNOWN"
        regions: List[str] = []
        succeeded_regions = 0

        LOG.info("=" * 72)
        LOG.info("Processing profile: %s", profile)

        try:
            session = boto3.Session(profile_name=profile)
            home = session.region_name or "us-east-1"
            sts = session.client("sts", region_name=home, config=config)
            identity = sts.get_caller_identity()
            account_id = identity.get("Account", "UNKNOWN")
            atomic_json(profile_dir / "caller-identity.json", identity)
            regions = discover_regions(session, profile, args.regions, config, errors)
        except Exception as exc:
            stats["api_errors"] += 1
            add_error(errors, profile, "", "session/sts:GetCallerIdentity", profile, exc)
            regions = []

        for region in regions:
            if process_region(session, profile, account_id, region, profile_dir,
                              config, args, inventory, errors, stats):
                succeeded_regions += 1

        total_errors = stats["api_errors"] + stats["download_errors"]
        status = "COMPLETE" if total_errors == 0 else ("PARTIAL" if stats["functions"] else "FAILED")
        summary.append({
            "Profile": profile, "AccountId": account_id,
            "RegionsAttempted": len(regions), "RegionsSucceeded": succeeded_regions,
            "FunctionsEnumerated": stats["functions"],
            "ZipPackagesDownloaded": stats["downloaded"],
            "ContainerImageFunctions": stats["images"],
            "DownloadErrors": stats["download_errors"], "ApiErrors": stats["api_errors"],
            "TotalErrors": total_errors, "Status": status,
            "OutputDirectory": str(profile_dir),
        })

        # Continuously checkpoint all tables so interrupted runs retain evidence.
        write_csv(output / "lambda_summary.csv", SUMMARY_FIELDS, summary)
        write_csv(output / "lambda_inventory.csv", INVENTORY_FIELDS, inventory)
        write_csv(output / "lambda_errors.csv", ERROR_FIELDS, errors)

    print("\nLambda enumeration summary")
    print(f"{'Profile':<24}{'Account':<15}{'Regions':>9}{'Functions':>11}{'ZIPs':>8}{'Images':>8}{'Errors':>8}{'Status':>12}")
    for row in summary:
        region_text = f"{row['RegionsSucceeded']}/{row['RegionsAttempted']}"
        print(f"{row['Profile']:<24}{row['AccountId']:<15}{region_text:>9}"
              f"{row['FunctionsEnumerated']:>11}{row['ZipPackagesDownloaded']:>8}"
              f"{row['ContainerImageFunctions']:>8}{row['TotalErrors']:>8}{row['Status']:>12}")

    LOG.info("Summary: %s", output / "lambda_summary.csv")
    LOG.info("Inventory: %s", output / "lambda_inventory.csv")
    LOG.info("Errors: %s", output / "lambda_errors.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
