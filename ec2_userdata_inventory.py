#!/usr/bin/env python3
"""
ec2_userdata_inventory.py

Enumerate EC2 instances and retrieve the userData instance attribute across
multiple AWS CLI profiles/accounts and regions. Produces audit-friendly JSONL,
CSV, summary JSON, error JSONL, and one raw user-data file per instance.

Read-only AWS API calls used:
  sts:GetCallerIdentity
  ec2:DescribeRegions
  ec2:DescribeInstances
  ec2:DescribeInstanceAttribute (Attribute=userData)
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import logging
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound
except ImportError:
    print("Missing dependency: boto3. Install with: python3 -m pip install boto3", file=sys.stderr)
    raise SystemExit(2)

LOG = logging.getLogger("ec2-userdata-inventory")
RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return value[:180] or "unknown"


def write_jsonl(handle, obj: Dict[str, Any]) -> None:
    handle.write(json.dumps(obj, default=json_default, ensure_ascii=False) + "\n")
    handle.flush()


def tags_to_dict(tags: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    return {str(t.get("Key", "")): str(t.get("Value", "")) for t in (tags or [])}


def decode_user_data(encoded: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not encoded:
        return "", None
    try:
        raw = base64.b64decode(encoded, validate=True)
        return raw.decode("utf-8", errors="replace"), None
    except Exception as exc:
        return None, f"Base64 decode failed: {type(exc).__name__}: {exc}"


def client_error_details(exc: Exception) -> Dict[str, str]:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return {
            "error_code": str(err.get("Code", "ClientError")),
            "error_message": str(err.get("Message", exc)),
        }
    return {"error_code": type(exc).__name__, "error_message": str(exc)}


def boto_session(profile: str) -> boto3.Session:
    return boto3.Session(profile_name=profile)


def resolve_profiles(requested: Optional[List[str]]) -> List[str]:
    if requested:
        return list(dict.fromkeys(requested))
    profiles = boto3.Session().available_profiles
    if not profiles:
        LOG.warning("No named profiles found; using the default credential chain.")
        return ["default"]
    return profiles


def get_identity(session: boto3.Session) -> Dict[str, str]:
    result = session.client("sts", config=RETRY_CONFIG).get_caller_identity()
    return {
        "account_id": str(result.get("Account", "unknown")),
        "principal_arn": str(result.get("Arn", "unknown")),
        "principal_id": str(result.get("UserId", "unknown")),
    }


def enabled_regions(session: boto3.Session, fallback_region: Optional[str]) -> List[str]:
    region = fallback_region or session.region_name or "us-east-1"
    client = session.client("ec2", region_name=region, config=RETRY_CONFIG)
    response = client.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in response.get("Regions", []))


def selected_instance(inst: Dict[str, Any]) -> Dict[str, Any]:
    tags = tags_to_dict(inst.get("Tags"))
    return {
        "instance_id": inst.get("InstanceId"),
        "name": tags.get("Name", ""),
        "state": (inst.get("State") or {}).get("Name"),
        "instance_type": inst.get("InstanceType"),
        "architecture": inst.get("Architecture"),
        "platform": inst.get("Platform"),
        "platform_details": inst.get("PlatformDetails"),
        "launch_time": inst.get("LaunchTime"),
        "availability_zone": (inst.get("Placement") or {}).get("AvailabilityZone"),
        "tenancy": (inst.get("Placement") or {}).get("Tenancy"),
        "vpc_id": inst.get("VpcId"),
        "subnet_id": inst.get("SubnetId"),
        "private_ip": inst.get("PrivateIpAddress"),
        "private_dns": inst.get("PrivateDnsName"),
        "public_ip": inst.get("PublicIpAddress"),
        "public_dns": inst.get("PublicDnsName"),
        "image_id": inst.get("ImageId"),
        "key_name": inst.get("KeyName"),
        "iam_instance_profile": inst.get("IamInstanceProfile"),
        "metadata_options": inst.get("MetadataOptions"),
        "security_groups": inst.get("SecurityGroups", []),
        "network_interfaces": inst.get("NetworkInterfaces", []),
        "block_device_mappings": inst.get("BlockDeviceMappings", []),
        "ebs_optimized": inst.get("EbsOptimized"),
        "ena_support": inst.get("EnaSupport"),
        "hibernation_options": inst.get("HibernationOptions"),
        "capacity_reservation_specification": inst.get("CapacityReservationSpecification"),
        "cpu_options": inst.get("CpuOptions"),
        "tags": tags,
    }


def csv_row(record: Dict[str, Any]) -> Dict[str, Any]:
    i = record["instance"]
    ud = record["user_data"]
    return {
        "collected_at": record["collected_at"],
        "profile": record["profile"],
        "account_id": record["account_id"],
        "principal_arn": record["principal_arn"],
        "region": record["region"],
        "instance_id": i.get("instance_id"),
        "name": i.get("name"),
        "state": i.get("state"),
        "instance_type": i.get("instance_type"),
        "availability_zone": i.get("availability_zone"),
        "vpc_id": i.get("vpc_id"),
        "subnet_id": i.get("subnet_id"),
        "private_ip": i.get("private_ip"),
        "public_ip": i.get("public_ip"),
        "image_id": i.get("image_id"),
        "iam_instance_profile_arn": (i.get("iam_instance_profile") or {}).get("Arn"),
        "imds_http_tokens": (i.get("metadata_options") or {}).get("HttpTokens"),
        "imds_endpoint": (i.get("metadata_options") or {}).get("HttpEndpoint"),
        "tags_json": json.dumps(i.get("tags", {}), ensure_ascii=False),
        "user_data_present": ud.get("present"),
        "user_data_sha256": ud.get("sha256"),
        "user_data_bytes": ud.get("byte_length"),
        "user_data_file": ud.get("file"),
        "user_data_access_status": ud.get("access_status"),
        "user_data_error_code": ud.get("error_code"),
        "user_data_error_message": ud.get("error_message"),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Inventory EC2 instances and user data across AWS CLI profiles.")
    p.add_argument("--profiles", nargs="+", help="AWS CLI profiles. Default: every named profile.")
    p.add_argument("--regions", nargs="+", help="Regions to scan. Default: all enabled regions per profile.")
    p.add_argument("--output-dir", default="ec2_userdata_audit", help="Output directory.")
    p.add_argument("--include-stopped", action="store_true", help="Include stopped/terminated-state results. Default scans all states except terminated.")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    output_dir = Path(args.output_dir).expanduser().resolve()
    raw_dir = output_dir / "user_data"
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    inventory_path = output_dir / "ec2_userdata_inventory.jsonl"
    csv_path = output_dir / "ec2_userdata_inventory.csv"
    errors_path = output_dir / "ec2_userdata_errors.jsonl"
    summary_path = output_dir / "ec2_userdata_summary.json"

    profiles = resolve_profiles(args.profiles)
    summary: Dict[str, Any] = {
        "started_at": utc_now(),
        "profiles_requested": profiles,
        "profiles_completed": 0,
        "profiles_failed": 0,
        "regions_attempted": 0,
        "regions_failed": 0,
        "instances_seen": 0,
        "instances_with_user_data": 0,
        "user_data_access_errors": 0,
        "output_files": {
            "inventory_jsonl": str(inventory_path),
            "inventory_csv": str(csv_path),
            "errors_jsonl": str(errors_path),
            "raw_user_data_root": str(raw_dir),
        },
    }

    fieldnames = list(csv_row({
        "collected_at": "", "profile": "", "account_id": "", "principal_arn": "", "region": "",
        "instance": {}, "user_data": {}
    }).keys())

    with inventory_path.open("w", encoding="utf-8") as inv_f, \
         csv_path.open("w", encoding="utf-8", newline="") as csv_f, \
         errors_path.open("w", encoding="utf-8") as err_f:
        writer = csv.DictWriter(csv_f, fieldnames=fieldnames)
        writer.writeheader()

        for profile in profiles:
            LOG.info("Profile: %s", profile)
            try:
                session = boto_session(profile)
                identity = get_identity(session)
            except (ProfileNotFound, ClientError, BotoCoreError, Exception) as exc:
                details = client_error_details(exc)
                write_jsonl(err_f, {"time": utc_now(), "scope": "profile", "profile": profile, **details})
                summary["profiles_failed"] += 1
                LOG.error("Skipping profile %s: %s", profile, details["error_message"])
                continue

            try:
                regions = args.regions or enabled_regions(session, session.region_name)
            except Exception as exc:
                details = client_error_details(exc)
                fallback = session.region_name
                if fallback:
                    regions = [fallback]
                    write_jsonl(err_f, {"time": utc_now(), "scope": "region-discovery", "profile": profile, "fallback_region": fallback, **details})
                    LOG.warning("Region discovery failed for %s; using configured region %s", profile, fallback)
                else:
                    write_jsonl(err_f, {"time": utc_now(), "scope": "region-discovery", "profile": profile, **details})
                    summary["profiles_failed"] += 1
                    LOG.error("No region available for profile %s", profile)
                    continue

            profile_had_success = False
            for region in regions:
                summary["regions_attempted"] += 1
                LOG.info("Scanning profile=%s account=%s region=%s", profile, identity["account_id"], region)
                try:
                    ec2 = session.client("ec2", region_name=region, config=RETRY_CONFIG)
                    paginator = ec2.get_paginator("describe_instances")
                    filters = [] if args.include_stopped else [{"Name": "instance-state-name", "Values": ["pending", "running", "shutting-down", "stopping", "stopped"]}]
                    pages = paginator.paginate(Filters=filters) if filters else paginator.paginate()
                    for page in pages:
                        for reservation in page.get("Reservations", []):
                            for instance in reservation.get("Instances", []):
                                summary["instances_seen"] += 1
                                instance_id = instance["InstanceId"]
                                user_data: Dict[str, Any] = {
                                    "present": None, "base64": None, "text": None, "sha256": None,
                                    "byte_length": None, "file": None, "access_status": "not_attempted",
                                    "error_code": None, "error_message": None,
                                }
                                try:
                                    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
                                    encoded = (attr.get("UserData") or {}).get("Value")
                                    text, decode_error = decode_user_data(encoded)
                                    raw_bytes = (text or "").encode("utf-8")
                                    user_data.update({
                                        "present": bool(encoded),
                                        "base64": encoded or "",
                                        "text": text if text is not None else "",
                                        "sha256": hashlib.sha256(raw_bytes).hexdigest() if encoded else None,
                                        "byte_length": len(raw_bytes) if encoded else 0,
                                        "access_status": "success" if not decode_error else "decode_error",
                                        "error_message": decode_error,
                                    })
                                    if encoded:
                                        file_path = raw_dir / safe_name(profile) / identity["account_id"] / region / f"{instance_id}.txt"
                                        file_path.parent.mkdir(parents=True, exist_ok=True)
                                        file_path.write_text(text or "", encoding="utf-8")
                                        user_data["file"] = str(file_path.relative_to(output_dir))
                                        summary["instances_with_user_data"] += 1
                                except Exception as exc:
                                    details = client_error_details(exc)
                                    user_data.update({"access_status": "error", **details})
                                    summary["user_data_access_errors"] += 1
                                    write_jsonl(err_f, {
                                        "time": utc_now(), "scope": "user-data", "profile": profile,
                                        "account_id": identity["account_id"], "region": region,
                                        "instance_id": instance_id, **details,
                                    })

                                record = {
                                    "schema_version": "1.0",
                                    "collected_at": utc_now(),
                                    "profile": profile,
                                    **identity,
                                    "region": region,
                                    "instance": selected_instance(instance),
                                    "user_data": user_data,
                                }
                                write_jsonl(inv_f, record)
                                writer.writerow(csv_row(record))
                                csv_f.flush()
                    profile_had_success = True
                except Exception as exc:
                    details = client_error_details(exc)
                    summary["regions_failed"] += 1
                    write_jsonl(err_f, {
                        "time": utc_now(), "scope": "region", "profile": profile,
                        "account_id": identity["account_id"], "region": region, **details,
                    })
                    LOG.error("Skipping region profile=%s region=%s: %s", profile, region, details["error_message"])

            if profile_had_success:
                summary["profiles_completed"] += 1
            else:
                summary["profiles_failed"] += 1

    summary["completed_at"] = utc_now()
    summary_path.write_text(json.dumps(summary, indent=2, default=json_default), encoding="utf-8")
    LOG.info("Completed. Instances=%d, with user data=%d, access errors=%d", summary["instances_seen"], summary["instances_with_user_data"], summary["user_data_access_errors"])
    LOG.info("Output: %s", output_dir)
    return 0 if summary["profiles_completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
