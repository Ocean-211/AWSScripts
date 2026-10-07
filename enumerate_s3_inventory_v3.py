#!/usr/bin/env python3
"""Enumerate S3 buckets, prefixes, and likely log/configuration objects across AWS profiles."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, TextIO

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

# JSON is intentionally retained. It may contain logs, configuration, policies,
# findings, events, or metadata. YAML/YML are treated as configuration candidates.
CONFIG_EXTENSIONS = {
    ".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".toml", ".ini",
    ".conf", ".config", ".cfg", ".properties", ".xml", ".env", ".tf",
    ".tfvars", ".hcl", ".template",
}
LOG_EXTENSIONS = {
    ".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv", ".tsv",
    ".xml", ".gz", ".gzip", ".zip", ".bz2", ".xz", ".snappy",
    ".parquet", ".avro", ".orc", ".evtx",
}
LOG_TERMS = re.compile(
    r"(^|[/_.-])(log|logs|logging|audit|audits|cloudtrail|cloudwatch|"
    r"vpcflow|vpc-flow|flowlog|flowlogs|accesslog|accesslogs|elb|alb|"
    r"nlb|waf|guardduty|firehose|splunk|security|events?)([/_.-]|$)",
    re.IGNORECASE,
)
CONFIG_TERMS = re.compile(
    r"(^|[/_.-])(config|configuration|settings|policy|policies|template|"
    r"manifest|inventory|metadata|terraform|cloudformation|cfn|ansible|"
    r"kubernetes|k8s|helm|docker|compose|env|environment|parameter|"
    r"parameters|secret|secrets|credential|credentials)([/_.-]|$)",
    re.IGNORECASE,
)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def profiles() -> list[str]:
    return list(dict.fromkeys(boto3.Session().available_profiles))


def region_for(s3, bucket: str) -> str:
    value = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    return "us-east-1" if value is None else "eu-west-1" if value == "EU" else str(value)


def parent_prefixes(key: str) -> Iterable[str]:
    parts = [x for x in key.split("/") if x]
    stop = len(parts) if key.endswith("/") else max(0, len(parts) - 1)
    for i in range(1, stop + 1):
        yield "/".join(parts[:i]) + "/"


def suffixes(key: str) -> set[str]:
    return {x.lower() for x in Path(key.lower()).suffixes}


def is_log_candidate(key: str) -> bool:
    exts = suffixes(key)
    return bool(LOG_TERMS.search(key)) or bool(exts & LOG_EXTENSIONS)


def is_config_candidate(key: str) -> bool:
    exts = suffixes(key)
    return bool(CONFIG_TERMS.search(key)) or bool(exts & CONFIG_EXTENSIONS)


def header(handle: TextIO, title: str) -> None:
    handle.write(f"{title}\nGenerated UTC: {now_utc()}\n{'=' * 110}\n")


def error_text(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        detail = exc.response.get("Error", {})
        return f"{detail.get('Code', 'ClientError')}: {detail.get('Message', str(exc))}"
    return f"{type(exc).__name__}: {exc}"


def scan_bucket(session, profile: str, account: str, bucket: str, region: str,
                folders_out: TextIO, logs_out: TextIO, configs_out: TextIO,
                errors_out: TextIO, max_objects: Optional[int]) -> None:
    """Walk S3 hierarchically and prune log-looking buckets/prefixes.

    S3 has no real folders, so Delimiter='/' is used to discover one prefix
    level at a time. Once a bucket name or prefix looks log-related, it gets
    recorded as a log location and is not listed any deeper.
    """
    s3 = session.client("s3", region_name=region, config=RETRY_CONFIG)
    common = f"PROFILE: {profile}\nACCOUNT: {account}\nBUCKET: {bucket}\nREGION: {region}\n"

    # If the bucket name itself indicates log storage, record and prune it.
    if LOG_TERMS.search(bucket):
        folders_out.write(common)
        folders_out.write("STATUS: SKIPPED - bucket name indicates log storage; contents not enumerated\n")
        folders_out.write("-" * 110 + "\n")
        logs_out.write(common)
        logs_out.write(f"BUCKET\t{bucket}\tSKIPPED_DEEP_SCAN\n")
        logs_out.write("-" * 110 + "\n")
        return

    discovered_folders: set[str] = set()
    skipped_log_folders: set[str] = set()
    log_keys: set[str] = set()
    config_keys: set[str] = set()
    prefixes_to_visit = [""]
    visited: set[str] = set()
    object_count = 0
    limit_reached = False

    try:
        while prefixes_to_visit and not limit_reached:
            prefix = prefixes_to_visit.pop()
            if prefix in visited:
                continue
            visited.add(prefix)

            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(
                Bucket=bucket,
                Prefix=prefix,
                Delimiter="/",
                PaginationConfig={"PageSize": 1000},
            ):
                # Objects directly within the current prefix only.
                for entry in page.get("Contents", []):
                    key = entry.get("Key", "")
                    if not key or key == prefix:  # ignore folder-marker objects
                        continue
                    object_count += 1
                    if is_log_candidate(key):
                        log_keys.add(key)
                    if is_config_candidate(key):
                        config_keys.add(key)
                    if max_objects is not None and object_count >= max_objects:
                        limit_reached = True
                        break

                if limit_reached:
                    break

                # Child prefixes are evaluated before traversal. Log-like ones
                # are recorded but deliberately not added to prefixes_to_visit.
                for item in page.get("CommonPrefixes", []):
                    child = item.get("Prefix", "")
                    if not child:
                        continue
                    discovered_folders.add(child)
                    if LOG_TERMS.search(child):
                        skipped_log_folders.add(child)
                    else:
                        prefixes_to_visit.append(child)

    except (ClientError, BotoCoreError) as exc:
        errors_out.write(f"profile={profile}\tbucket={bucket}\terror={error_text(exc)}\n")
        folders_out.write(common)
        folders_out.write(f"STATUS: ERROR - {error_text(exc)}\n{'-' * 110}\n")
        return

    folders_out.write(common)
    folders_out.write(f"OBJECTS EXAMINED OUTSIDE PRUNED LOG PREFIXES: {object_count}\n")
    folders_out.write(f"FOLDERS IDENTIFIED: {len(discovered_folders)}\n")
    folders_out.write(f"LOG FOLDERS PRUNED: {len(skipped_log_folders)}\n")
    if limit_reached:
        folders_out.write(f"NOTE: Limited by --max-objects {max_objects}; results may be incomplete.\n")
    for folder in sorted(discovered_folders):
        marker = "\t[LOG LOCATION - DEEP SCAN SKIPPED]" if folder in skipped_log_folders else ""
        folders_out.write(folder + marker + "\n")
    if not discovered_folders:
        folders_out.write("[No folder-like prefixes found]\n")
    folders_out.write("-" * 110 + "\n")

    if skipped_log_folders or log_keys:
        logs_out.write(common)
        for folder in sorted(skipped_log_folders):
            logs_out.write(f"FOLDER\t{folder}\tSKIPPED_DEEP_SCAN\n")
        for key in sorted(log_keys):
            logs_out.write(f"OBJECT\t{key}\n")
        logs_out.write("-" * 110 + "\n")

    if config_keys:
        configs_out.write(common)
        for key in sorted(config_keys):
            configs_out.write(f"OBJECT\t{key}\n")
        configs_out.write("-" * 110 + "\n")

def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory S3 buckets and prefixes while pruning log-storage locations.")
    parser.add_argument("--output-dir", default="s3_inventory")
    parser.add_argument("--profiles", nargs="+", help="Profiles to scan; default is every configured AWS profile")
    parser.add_argument("--max-objects", type=int, help="Optional per-bucket object limit")
    args = parser.parse_args()

    if args.max_objects is not None and args.max_objects < 1:
        parser.error("--max-objects must be at least 1")

    selected = args.profiles or profiles()
    if not selected:
        print("No configured AWS profiles were found.", file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "buckets": out_dir / "s3_buckets.txt",
        "folders": out_dir / "s3_folders.txt",
        "logs": out_dir / "s3_log_candidates.txt",
        "configs": out_dir / "s3_configuration_candidates.txt",
        "errors": out_dir / "s3_errors.txt",
    }

    with (paths["buckets"].open("w", encoding="utf-8") as buckets_out,
          paths["folders"].open("w", encoding="utf-8") as folders_out,
          paths["logs"].open("w", encoding="utf-8") as logs_out,
          paths["configs"].open("w", encoding="utf-8") as configs_out,
          paths["errors"].open("w", encoding="utf-8") as errors_out):
        header(buckets_out, "S3 BUCKET INVENTORY")
        header(folders_out, "S3 FOLDER/PREFIX INVENTORY")
        header(logs_out, "S3 LOG FILE CANDIDATES")
        header(configs_out, "S3 CONFIGURATION FILE CANDIDATES (JSON/YAML INCLUDED)")
        header(errors_out, "S3 ENUMERATION ERRORS")

        for profile in selected:
            print(f"[+] Scanning profile: {profile}")
            try:
                session = boto3.Session(profile_name=profile)
                account = str(session.client("sts", config=RETRY_CONFIG).get_caller_identity().get("Account", "UNKNOWN"))
                s3 = session.client("s3", config=RETRY_CONFIG)
                bucket_list = s3.list_buckets().get("Buckets", [])
            except (ProfileNotFound, ClientError, BotoCoreError) as exc:
                errors_out.write(f"profile={profile}\tscope=initialization\terror={error_text(exc)}\n")
                continue

            buckets_out.write(f"PROFILE: {profile}\nACCOUNT: {account}\nBUCKET COUNT: {len(bucket_list)}\n")
            for item in sorted(bucket_list, key=lambda x: x.get("Name", "")):
                bucket = item.get("Name", "")
                if not bucket:
                    continue
                try:
                    region = region_for(s3, bucket)
                except (ClientError, BotoCoreError) as exc:
                    region = session.region_name or "us-east-1"
                    errors_out.write(f"profile={profile}\tbucket={bucket}\tscope=get-location\terror={error_text(exc)}\n")
                created = item.get("CreationDate")
                created_text = created.isoformat() if created else "UNKNOWN"
                buckets_out.write(f"BUCKET\t{bucket}\tREGION\t{region}\tCREATED\t{created_text}\n")
                scan_bucket(session, profile, account, bucket, region, folders_out,
                            logs_out, configs_out, errors_out, args.max_objects)
            buckets_out.write("-" * 110 + "\n")

    for label, path in paths.items():
        print(f"[+] {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
