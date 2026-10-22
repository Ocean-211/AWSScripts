#!/usr/bin/env python3
"""Find VPC endpoint Allow statements with wildcard principals and no AWS Organizations scoping."""

import argparse
import csv
import json
import sys
from pathlib import Path
from urllib.parse import unquote

import boto3
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

ORG_KEYS = {"aws:principalorgid", "aws:principalorgpaths"}


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Enumerate VPC endpoint policies containing Allow statements with a wildcard "
            "Principal and no aws:PrincipalOrgID/aws:PrincipalOrgPaths condition."
        )
    )
    p.add_argument("--profile", action="append", help="AWS profile; repeatable. Default: current/default profile")
    p.add_argument("--all-profiles", action="store_true", help="Scan every profile in ~/.aws/config and ~/.aws/credentials")
    p.add_argument("--region", action="append", help="AWS Region; repeatable. Default: all enabled/available EC2 Regions")
    p.add_argument("--output-dir", default=".", help="Directory for JSON and CSV reports")
    p.add_argument("--include-policy", action="store_true", help="Include the complete endpoint policy in JSON output")
    return p.parse_args()


def decode_policy(raw):
    if raw is None or raw == "":
        return None
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise ValueError(f"unsupported policy type: {type(raw).__name__}")
    candidates = [raw]
    decoded = unquote(raw)
    if decoded != raw:
        candidates.append(decoded)
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    raise ValueError("PolicyDocument is not valid JSON after URL decoding")


def wildcard_principal(principal):
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    aws_value = principal.get("AWS")
    if aws_value == "*":
        return True
    return isinstance(aws_value, list) and "*" in aws_value


def condition_keys(condition):
    keys = set()
    if not isinstance(condition, dict):
        return keys
    for operator_value in condition.values():
        if isinstance(operator_value, dict):
            keys.update(str(k).lower() for k in operator_value)
    return keys


def normalize_statements(policy):
    statements = policy.get("Statement", [])
    return [statements] if isinstance(statements, dict) else statements if isinstance(statements, list) else []


def matching_statements(policy):
    findings = []
    for index, statement in enumerate(normalize_statements(policy)):
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        if not wildcard_principal(statement.get("Principal")):
            continue
        keys = condition_keys(statement.get("Condition", {}))
        if keys.isdisjoint(ORG_KEYS):
            findings.append({"statement_index": index, "statement": statement})
    return findings


def get_profiles(args):
    if args.all_profiles:
        profiles = boto3.Session().available_profiles
        return profiles or [None]
    return args.profile or [None]


def get_regions(session, requested):
    if requested:
        return sorted(set(requested))
    return session.get_available_regions("ec2")


def scan(profile, region, include_policy):
    session = boto3.Session(profile_name=profile, region_name=region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_vpc_endpoints")
    results = []
    checked = 0
    for page in paginator.paginate():
        for endpoint in page.get("VpcEndpoints", []):
            checked += 1
            raw_policy = endpoint.get("PolicyDocument")
            try:
                policy = decode_policy(raw_policy)
            except ValueError as exc:
                print(f"[WARN] {profile or 'default'} {region} {endpoint.get('VpcEndpointId')}: {exc}", file=sys.stderr)
                continue
            if not policy:
                continue
            matches = matching_statements(policy)
            if not matches:
                continue
            item = {
                "profile": profile or "default",
                "account_id": account_id,
                "region": region,
                "vpc_endpoint_id": endpoint.get("VpcEndpointId"),
                "vpc_id": endpoint.get("VpcId"),
                "endpoint_type": endpoint.get("VpcEndpointType"),
                "service_name": endpoint.get("ServiceName"),
                "state": endpoint.get("State"),
                "matching_statement_count": len(matches),
                "matching_statements": matches,
            }
            if include_policy:
                item["policy_document"] = policy
            results.append(item)
    return account_id, checked, results


def write_reports(findings, errors, output_dir):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "vpc_endpoint_wildcard_principal_findings.json"
    csv_path = out / "vpc_endpoint_wildcard_principal_findings.csv"
    json_path.write_text(json.dumps({"findings": findings, "errors": errors}, indent=2, default=str), encoding="utf-8")
    fields = ["profile", "account_id", "region", "vpc_endpoint_id", "vpc_id", "endpoint_type", "service_name", "state", "matching_statement_count", "statement_indexes"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for item in findings:
            row = {k: item.get(k, "") for k in fields}
            row["statement_indexes"] = ",".join(str(x["statement_index"]) for x in item["matching_statements"])
            writer.writerow(row)
    return json_path, csv_path


def main():
    args = parse_args()
    findings, errors = [], []
    total_endpoints = 0
    try:
        profiles = get_profiles(args)
    except ProfileNotFound as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    for profile in profiles:
        try:
            session = boto3.Session(profile_name=profile)
            regions = get_regions(session, args.region)
        except (BotoCoreError, ClientError, ProfileNotFound) as exc:
            errors.append({"profile": profile or "default", "region": None, "error": str(exc)})
            continue
        for region in regions:
            try:
                account_id, checked, region_findings = scan(profile, region, args.include_policy)
                total_endpoints += checked
                findings.extend(region_findings)
                print(f"[OK] profile={profile or 'default'} account={account_id} region={region} endpoints={checked} findings={len(region_findings)}")
            except (BotoCoreError, ClientError, ProfileNotFound) as exc:
                errors.append({"profile": profile or "default", "region": region, "error": str(exc)})
                print(f"[ERROR] profile={profile or 'default'} region={region}: {exc}", file=sys.stderr)

    json_path, csv_path = write_reports(findings, errors, args.output_dir)
    print(f"\nScanned endpoints: {total_endpoints}")
    print(f"Findings: {len(findings)}")
    print(f"Errors/skipped regions: {len(errors)}")
    print(f"JSON report: {json_path}")
    print(f"CSV report: {csv_path}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
