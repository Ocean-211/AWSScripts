#!/usr/bin/env python3
"""Audit AWS EC2 instance profiles and their contained IAM roles.

Safe defaults:
- Requires explicit --profiles, unless --all-configured-profiles is supplied.
- Passive enumeration by default.
- Active STS validation requires an account allowlist, explicit role allowlist,
  and a confirmation phrase.
- Never stores SecretAccessKey or SessionToken.
- Creates protected, non-overwriting evidence files.

Static findings are heuristic and are labelled as potential until actively validated.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

VERSION = "2.0"
CONFIRMATION = "I_HAVE_AUTHORIZATION_TO_CREATE_STS_SESSIONS"

RETRY_CONFIG = Config(
    retries={"max_attempts": 4, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
    user_agent_extra=f"instance-profile-audit/{VERSION}",
)

PRIVILEGE_ACTIONS = {
    "iam:attachrolepolicy", "iam:putrolepolicy", "iam:updateassumerolepolicy",
    "iam:passrole", "iam:addroletoinstanceprofile", "iam:createrole",
    "iam:createpolicy", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml",
    "ec2:associateiaminstanceprofile", "ec2:replaceiaminstanceprofileassociation",
    "lambda:createfunction", "lambda:updatefunctionconfiguration",
    "cloudformation:createstack", "cloudformation:updatestack",
}

HIGH_IMPACT_PATTERNS = {
    "*", "iam:*", "sts:*", "organizations:*", "kms:*",
    "secretsmanager:getsecretvalue", "ssm:getparameter*", "s3:getobject",
    "cloudtrail:stoplogging", "cloudtrail:delete*", "ec2:runinstances",
}

SENSITIVE_KEYS = {
    "secretaccesskey", "sessiontoken", "webidentitytoken", "authorization",
    "password", "token", "credentials",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def listify(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def decode_policy(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        decoded = unquote(value)
        try:
            return json.loads(decoded)
        except json.JSONDecodeError:
            return {"_raw": decoded}
    return {"_raw": str(value)}


def safe_error(exc: Exception) -> Dict[str, str]:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return {"code": str(err.get("Code", "ClientError")),
                "message": str(err.get("Message", "AWS request failed"))}
    return {"code": exc.__class__.__name__, "message": str(exc)}


def redact(value: Any, key: str = "") -> Any:
    if key.lower().replace("_", "") in SENSITIVE_KEYS:
        return "REDACTED"
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def paginate(client: Any, operation: str, key: str, **kwargs: Any) -> Iterable[Any]:
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(key, [])


def account_from_arn(arn: str) -> Optional[str]:
    parts = arn.split(":")
    return parts[4] if len(parts) >= 6 and parts[4] else None


def conditions(condition: Any) -> Iterable[Tuple[str, str, Any]]:
    if not isinstance(condition, dict):
        return
    for operator, entries in condition.items():
        if isinstance(entries, dict):
            for key, value in entries.items():
                yield str(operator), str(key), value


def condition_values(condition: Any, suffix: str) -> List[str]:
    wanted = suffix.lower()
    out: List[str] = []
    for _, key, value in conditions(condition):
        if key.lower() == wanted or key.lower().endswith(wanted):
            out.extend(str(v) for v in listify(value))
    return out


def has_condition(condition: Any, suffix: str) -> bool:
    return bool(condition_values(condition, suffix))


def finding(severity: str, category: str, title: str,
            evidence: Any, rationale: str) -> Dict[str, Any]:
    return {"severity": severity, "status": "POTENTIAL_REQUIRES_REVIEW",
            "category": category, "title": title,
            "evidence": redact(evidence), "rationale": rationale}


def analyze_trust(policy: Dict[str, Any], account_id: str,
                  role_arn: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    allowed_services: Set[str] = set()

    for index, statement in enumerate(listify(policy.get("Statement"))):
        if not isinstance(statement, dict) or str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = {str(a).lower() for a in listify(statement.get("Action"))}
        if not actions.intersection({"sts:assumerole", "sts:assumerolewithwebidentity",
                                     "sts:assumerolewithsaml", "sts:*", "*"}):
            continue
        principal = statement.get("Principal")
        condition = statement.get("Condition", {})
        base = {"statement_index": index, "action": sorted(actions),
                "principal": principal, "condition": condition}

        if principal == "*":
            findings.append(finding("CRITICAL", "TrustPolicy", "Wildcard principal",
                                    base, "An Allow trust statement uses Principal '*'."))
            continue
        if not isinstance(principal, dict):
            findings.append(finding("HIGH", "TrustPolicy", "Unrecognized principal structure",
                                    base, "Manual review is required."))
            continue

        aws_principals = [str(x) for x in listify(principal.get("AWS"))]
        services = [str(x).lower() for x in listify(principal.get("Service"))]
        federated = [str(x) for x in listify(principal.get("Federated"))]
        allowed_services.update(services)

        for p in aws_principals:
            p_account = account_from_arn(p)
            if p == "*":
                sev, title = "CRITICAL", "Wildcard AWS principal"
            elif p.endswith(":root") and p_account != account_id:
                sev, title = ("MEDIUM" if has_condition(condition, "sts:ExternalId") else "HIGH"), "External account trust"
            elif p.endswith(":root"):
                sev, title = "MEDIUM", "Current account root trust"
            elif ":user/" in p:
                sev, title = "HIGH", "Explicit IAM user trust"
            elif ":role/" in p:
                sev, title = ("HIGH" if p_account and p_account != account_id else "MEDIUM"), "IAM role trust"
            else:
                sev, title = "MEDIUM", "Additional AWS principal trust"
            findings.append(finding(sev, "TrustPolicy", title, p,
                                    "The EC2-associated role can also be reached through an AWS principal trust path."))
            if p == role_arn:
                findings.append(finding("MEDIUM", "SelfAssumption", "Role trusts itself", p,
                                        "Self-assumption is possible only if identity authorization also permits it."))

        for service in services:
            if service != "ec2.amazonaws.com":
                findings.append(finding("MEDIUM", "ServiceTrust", "Additional service principal",
                                        service, "A service other than EC2 can assume the role."))

        for provider in federated:
            lower = provider.lower()
            if "token.actions.githubusercontent.com" in lower or "sts:assumerolewithwebidentity" in actions:
                aud = condition_values(condition, ":aud")
                subs = condition_values(condition, ":sub")
                if not aud:
                    findings.append(finding("HIGH", "OIDCTrust", "OIDC audience is not constrained",
                                            provider, "No audience condition was identified."))
                if not subs:
                    findings.append(finding("CRITICAL", "OIDCTrust", "OIDC subject is not constrained",
                                            provider, "No subject condition was identified."))
                for subject in subs:
                    if "*" in subject or "?" in subject:
                        findings.append(finding("HIGH", "OIDCTrust", "OIDC subject contains a wildcard",
                                                subject, "The wildcard may authorize unintended workloads."))
            elif "saml-provider/" in lower:
                findings.append(finding("MEDIUM", "SAMLTrust", "SAML provider trust", provider,
                                        "The EC2-associated role is also available through SAML federation."))
            else:
                findings.append(finding("MEDIUM", "FederatedTrust", "Federated provider trust", provider,
                                        "A federated identity provider can assume the role."))

        for principal_arn in condition_values(condition, "aws:PrincipalArn"):
            if "*" in principal_arn or "?" in principal_arn:
                findings.append(finding("HIGH", "TrustCondition", "Wildcard PrincipalArn condition",
                                        principal_arn, "The condition can match multiple principals."))

    if "ec2.amazonaws.com" not in allowed_services:
        findings.append(finding("LOW", "TrustPolicy", "No EC2 service trust identified", role_arn,
                                "The role is in an instance profile, but no EC2 service trust was identified across the policy."))
    return findings


def action_matches(action: str, patterns: Set[str]) -> bool:
    return any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in patterns)


def analyze_permissions(name: str, kind: str,
                        policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for statement in listify(policy.get("Statement")):
        if not isinstance(statement, dict) or str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = [str(x) for x in listify(statement.get("Action"))]
        resources = listify(statement.get("Resource"))
        for action in actions:
            evidence = {"policy": name, "type": kind, "action": action, "resource": resources,
                        "condition": statement.get("Condition")}
            if action_matches(action, PRIVILEGE_ACTIONS):
                results.append(finding("HIGH" if "*" in resources else "MEDIUM",
                                       "PrivilegeEscalationPermission",
                                       "Privilege-escalation-relevant permission", evidence,
                                       "Effective exploitability depends on resources, conditions, boundaries, SCPs and explicit denies."))
            if action_matches(action, HIGH_IMPACT_PATTERNS):
                results.append(finding("HIGH" if "*" in resources else "MEDIUM",
                                       "HighImpactPermission", "High-impact permission", evidence,
                                       "This permission can increase the impact of a validated assumption path."))
    return results


def collect_policies(iam: Any, role_name: str,
                     cache: Dict[str, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], bool]:
    managed: List[Dict[str, Any]] = []
    inline: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    complete = True

    for attached in paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role_name):
        arn = attached["PolicyArn"]
        try:
            if arn not in cache:
                meta = iam.get_policy(PolicyArn=arn)["Policy"]
                version = iam.get_policy_version(PolicyArn=arn,
                                                 VersionId=meta["DefaultVersionId"])["PolicyVersion"]
                cache[arn] = {"arn": arn, "name": meta.get("PolicyName"),
                              "version": meta.get("DefaultVersionId"),
                              "document": decode_policy(version.get("Document"))}
            item = cache[arn]
            managed.append(item)
            findings.extend(analyze_permissions(item.get("name") or arn, "managed", item["document"]))
        except (ClientError, BotoCoreError) as exc:
            complete = False
            managed.append({"arn": arn, "name": attached.get("PolicyName"), "error": safe_error(exc)})

    for name in paginate(iam, "list_role_policies", "PolicyNames", RoleName=role_name):
        try:
            document = decode_policy(iam.get_role_policy(RoleName=role_name,
                                                         PolicyName=name).get("PolicyDocument"))
            inline.append({"name": name, "document": document})
            findings.extend(analyze_permissions(name, "inline", document))
        except (ClientError, BotoCoreError) as exc:
            complete = False
            inline.append({"name": name, "error": safe_error(exc)})
    return managed, inline, findings, complete


def get_regions(session: boto3.Session, requested: Optional[List[str]]) -> List[str]:
    if requested:
        return sorted(set(requested))
    region = session.region_name or os.getenv("AWS_REGION") or "us-east-1"
    ec2 = session.client("ec2", region_name=region, config=RETRY_CONFIG)
    return sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False).get("Regions", []))


def collect_associations(session: boto3.Session, regions: List[str]) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    index: Dict[str, List[Dict[str, Any]]] = {}
    errors: List[Dict[str, Any]] = []
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region, config=RETRY_CONFIG)
            for assoc in paginate(ec2, "describe_iam_instance_profile_associations",
                                  "IamInstanceProfileAssociations"):
                arn = assoc.get("IamInstanceProfile", {}).get("Arn")
                if arn:
                    index.setdefault(arn, []).append({
                        "region": region, "association_id": assoc.get("AssociationId"),
                        "instance_id": assoc.get("InstanceId"), "state": assoc.get("State")})
        except (ClientError, BotoCoreError) as exc:
            errors.append({"region": region, "error": safe_error(exc)})
    return index, errors


def trust_potentially_matches(policy: Dict[str, Any], source_arn: str,
                              source_account: str) -> bool:
    for statement in listify(policy.get("Statement")):
        if not isinstance(statement, dict) or str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = {str(x).lower() for x in listify(statement.get("Action"))}
        if not actions.intersection({"sts:assumerole", "sts:*", "*"}):
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            for trusted in [str(x) for x in listify(principal.get("AWS"))]:
                if trusted in {"*", source_arn, f"arn:aws:iam::{source_account}:root"}:
                    return True
    return False


def probe(session: boto3.Session, role_arn: str, duration: int,
          external_id: Optional[str]) -> Dict[str, Any]:
    sts = session.client("sts", config=RETRY_CONFIG)
    session_name = f"ip-audit-{int(time.time())}"[:64]
    kwargs: Dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": session_name,
                              "DurationSeconds": duration}
    if external_id:
        kwargs["ExternalId"] = external_id
    try:
        response = sts.assume_role(**kwargs)
        credentials = response["Credentials"]
        assumed = boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                                aws_secret_access_key=credentials["SecretAccessKey"],
                                aws_session_token=credentials["SessionToken"])
        identity = assumed.client("sts", config=RETRY_CONFIG).get_caller_identity()
        access_key = credentials.get("AccessKeyId", "")
        expiration = credentials.get("Expiration")
        fingerprint_material = "|".join([
            access_key, credentials.get("SecretAccessKey", ""),
            credentials.get("SessionToken", ""), str(expiration), role_arn, session_name])
        result = {
            "attempted": True, "succeeded": True, "status": "ACTIVELY_VALIDATED",
            "role_arn": role_arn, "session_name": session_name,
            "issued_credentials": {
                "access_key_id_masked": (access_key[:4] + "*" * max(0, len(access_key) - 8) + access_key[-4:]),
                "access_key_id_last_four": access_key[-4:],
                "secret_access_key": "REDACTED", "session_token": "REDACTED",
                "expiration": expiration.isoformat() if hasattr(expiration, "isoformat") else str(expiration),
                "credential_set_sha256": hashlib.sha256(fingerprint_material.encode()).hexdigest(),
            },
            "assumed_identity": {"account": identity.get("Account"), "arn": identity.get("Arn"),
                                 "user_id_prefix": str(identity.get("UserId", "")).split(":")[0]},
            "sts_response_metadata": {
                "request_id": response.get("ResponseMetadata", {}).get("RequestId"),
                "http_status_code": response.get("ResponseMetadata", {}).get("HTTPStatusCode")},
        }
        del credentials, response, assumed, fingerprint_material
        return result
    except (ClientError, BotoCoreError) as exc:
        return {"attempted": True, "succeeded": False, "status": "ACTIVE_TEST_DENIED",
                "error": safe_error(exc), "session_name": session_name}


def parse_external_ids(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    output: Dict[str, str] = {}
    for role_arn, value in data.items():
        if isinstance(value, dict) and value.get("external_id"):
            output[role_arn] = str(value["external_id"])
    return output


def audit_profile(name: str, args: argparse.Namespace,
                  seen_accounts: Set[str], tested_paths: Set[Tuple[str, str]],
                  external_ids: Dict[str, str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {"profile": name, "started_at": now(), "status": "STARTED",
                              "instance_profiles": [], "errors": [], "completeness": {}}
    try:
        session = boto3.Session(profile_name=name)
        identity = session.client("sts", config=RETRY_CONFIG).get_caller_identity()
    except (ProfileNotFound, NoCredentialsError, ClientError, BotoCoreError) as exc:
        result.update(status="FAILED", completed_at=now())
        result["errors"].append(safe_error(exc))
        return result

    account = str(identity.get("Account", ""))
    source_arn = str(identity.get("Arn", ""))
    result["source_identity"] = {"account": account, "arn": source_arn,
                                 "user_id": identity.get("UserId")}

    if args.allowed_account and account not in args.allowed_account:
        result.update(status="SKIPPED_OUTSIDE_SCOPE", completed_at=now())
        result["errors"].append({"code": "AccountOutsideScope",
                                 "message": f"Account {account} is not allowlisted"})
        return result
    if account in seen_accounts and not args.allow_duplicate_accounts:
        result.update(status="SKIPPED_DUPLICATE_ACCOUNT", completed_at=now())
        return result
    seen_accounts.add(account)

    association_index: Dict[str, List[Dict[str, Any]]] = {}
    association_errors: List[Dict[str, Any]] = []
    if args.scan_ec2_associations:
        try:
            regions = get_regions(session, args.regions)
            association_index, association_errors = collect_associations(session, regions)
        except (ClientError, BotoCoreError) as exc:
            association_errors.append({"error": safe_error(exc)})

    try:
        iam = session.client("iam", config=RETRY_CONFIG)
        profiles = list(paginate(iam, "list_instance_profiles", "InstanceProfiles"))
    except (ClientError, BotoCoreError) as exc:
        result.update(status="FAILED", completed_at=now())
        result["errors"].append(safe_error(exc))
        return result

    cache: Dict[str, Dict[str, Any]] = {}
    partial = bool(association_errors)
    for profile in profiles:
        profile_arn = str(profile.get("Arn", ""))
        profile_record: Dict[str, Any] = {
            "instance_profile_name": profile.get("InstanceProfileName"),
            "instance_profile_id": profile.get("InstanceProfileId"),
            "instance_profile_arn": profile_arn, "path": profile.get("Path"),
            "created_date": profile.get("CreateDate").isoformat() if profile.get("CreateDate") else None,
            "ec2_associations": association_index.get(profile_arn, []), "roles": []}

        for role_summary in profile.get("Roles", []):
            role_name = role_summary["RoleName"]
            try:
                role = iam.get_role(RoleName=role_name)["Role"]
                role_arn = role["Arn"]
                trust = decode_policy(role.get("AssumeRolePolicyDocument"))
                managed, inline, permission_findings, policies_complete = collect_policies(iam, role_name, cache)
                role_findings = analyze_trust(trust, account, role_arn) + permission_findings
                trust_candidate = trust_potentially_matches(trust, source_arn, account)
                role_record: Dict[str, Any] = {
                    "role_name": role_name, "role_id": role.get("RoleId"), "role_arn": role_arn,
                    "max_session_duration": role.get("MaxSessionDuration"),
                    "permissions_boundary": role.get("PermissionsBoundary"),
                    "trust_policy": trust, "managed_policies": managed, "inline_policies": inline,
                    "findings": role_findings, "source_profile_is_potential_trust_match": trust_candidate,
                    "completeness": {"trust_policy_retrieved": True,
                                     "permission_policies_complete": policies_complete}}
                if not policies_complete:
                    partial = True

                path = (source_arn, role_arn)
                if args.probe_assume and role_arn in args.probe_role_arn:
                    if account not in args.allowed_account:
                        role_record["assume_role_probe"] = {"attempted": False,
                            "status": "BLOCKED_ACCOUNT_NOT_ALLOWLISTED"}
                    elif path in tested_paths:
                        role_record["assume_role_probe"] = {"attempted": False,
                            "status": "SKIPPED_DUPLICATE_PATH"}
                    else:
                        tested_paths.add(path)
                        role_record["assume_role_probe"] = probe(
                            session, role_arn, args.duration_seconds, external_ids.get(role_arn))
                else:
                    role_record["assume_role_probe"] = {"attempted": False,
                        "status": "PASSIVE_ONLY" if not args.probe_assume else "ROLE_NOT_ALLOWLISTED"}
                profile_record["roles"].append(role_record)
            except (ClientError, BotoCoreError) as exc:
                partial = True
                profile_record["roles"].append({"role_name": role_name, "error": safe_error(exc)})
        result["instance_profiles"].append(profile_record)

    result["association_errors"] = association_errors
    result["status"] = "PARTIAL" if partial else "COMPLETED"
    result["completed_at"] = now()
    return result


def exclusive_json(path: Path, data: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Refusing to overwrite evidence file: {path}")
    with path.open("x", encoding="utf-8") as handle:
        json.dump(redact(data), handle, indent=2, default=str)
    os.chmod(path, 0o600)


def exclusive_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Refusing to overwrite evidence file: {path}")
    columns = [
        "aws_profile", "source_account", "source_arn", "instance_profile_name",
        "instance_profile_arn", "attached_instance_ids", "role_name", "role_arn",
        "potential_trust_match", "finding_severity", "finding_category", "finding_title",
        "finding_evidence", "finding_rationale", "probe_status", "probe_succeeded",
        "assumed_identity_arn", "access_key_id_masked", "credential_expiration",
        "credential_set_sha256", "sts_request_id", "error"]
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(path, 0o600)


def flatten(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for pr in report["profiles"]:
        source = pr.get("source_identity", {})
        for ip in pr.get("instance_profiles", []):
            instances = ",".join(sorted({str(x.get("instance_id")) for x in ip.get("ec2_associations", []) if x.get("instance_id")}))
            for role in ip.get("roles", []):
                if role.get("error"):
                    rows.append({"aws_profile": pr.get("profile"), "source_account": source.get("account"),
                                 "source_arn": source.get("arn"), "instance_profile_name": ip.get("instance_profile_name"),
                                 "instance_profile_arn": ip.get("instance_profile_arn"), "role_name": role.get("role_name"),
                                 "error": json.dumps(role.get("error"))})
                    continue
                probe_result = role.get("assume_role_probe", {})
                creds = probe_result.get("issued_credentials", {})
                assumed = probe_result.get("assumed_identity", {})
                metadata = probe_result.get("sts_response_metadata", {})
                findings = role.get("findings") or [finding("INFO", "Review", "No heuristic finding", "",
                                                           "No finding was generated by the implemented heuristics.")]
                for f in findings:
                    rows.append({
                        "aws_profile": pr.get("profile"), "source_account": source.get("account"),
                        "source_arn": source.get("arn"), "instance_profile_name": ip.get("instance_profile_name"),
                        "instance_profile_arn": ip.get("instance_profile_arn"), "attached_instance_ids": instances,
                        "role_name": role.get("role_name"), "role_arn": role.get("role_arn"),
                        "potential_trust_match": role.get("source_profile_is_potential_trust_match"),
                        "finding_severity": f.get("severity"), "finding_category": f.get("category"),
                        "finding_title": f.get("title"), "finding_evidence": json.dumps(f.get("evidence"), default=str),
                        "finding_rationale": f.get("rationale"), "probe_status": probe_result.get("status"),
                        "probe_succeeded": probe_result.get("succeeded"), "assumed_identity_arn": assumed.get("arn"),
                        "access_key_id_masked": creds.get("access_key_id_masked"),
                        "credential_expiration": creds.get("expiration"),
                        "credential_set_sha256": creds.get("credential_set_sha256"),
                        "sts_request_id": metadata.get("request_id"), "error": ""})
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safely audit AWS EC2 instance profiles and role trust paths.")
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--profiles", nargs="+", help="Explicit authorized AWS CLI profiles")
    scope.add_argument("--all-configured-profiles", action="store_true",
                       help="Audit all configured profiles; use only with explicit authorization")
    parser.add_argument("--exclude-profiles", nargs="*", default=[])
    parser.add_argument("--allowed-account", action="append", default=[], help="Authorized AWS account ID; repeatable")
    parser.add_argument("--allow-duplicate-accounts", action="store_true")
    parser.add_argument("--scan-ec2-associations", action="store_true")
    parser.add_argument("--regions", nargs="+", help="Explicit regions; default is all enabled regions when association scanning")
    parser.add_argument("--out-dir", default="instance-profile-audit")
    parser.add_argument("--probe-assume", action="store_true", help="Enable controlled STS validation")
    parser.add_argument("--probe-role-arn", action="append", default=[], help="Explicit target role ARN; repeatable")
    parser.add_argument("--confirm-active-testing", help=f"Required exact phrase: {CONFIRMATION}")
    parser.add_argument("--external-id-map", help="Protected JSON mapping role ARN to {'external_id': 'value'}")
    parser.add_argument("--duration-seconds", type=int, default=900)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.duration_seconds < 900:
        print("--duration-seconds must be at least 900", file=sys.stderr)
        return 2
    if args.probe_assume:
        if args.confirm_active_testing != CONFIRMATION:
            print("Active testing refused: confirmation phrase missing or incorrect", file=sys.stderr)
            return 2
        if not args.allowed_account or not args.probe_role_arn:
            print("Active testing requires --allowed-account and --probe-role-arn", file=sys.stderr)
            return 2
        for arn in args.probe_role_arn:
            account = account_from_arn(arn)
            if account not in args.allowed_account:
                print(f"Active testing refused: role account is not allowlisted: {arn}", file=sys.stderr)
                return 2

    profiles = sorted(set(boto3.Session().available_profiles if args.all_configured_profiles else args.profiles))
    profiles = [p for p in profiles if p not in set(args.exclude_profiles)]
    if not profiles:
        print("No AWS CLI profiles selected", file=sys.stderr)
        return 2

    os.umask(0o077)
    base = Path(args.out_dir).expanduser()
    if base.exists() and base.is_symlink():
        print("Output directory must not be a symbolic link", file=sys.stderr)
        return 2
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = base.resolve() / run_id
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(out, 0o700)

    external_ids = parse_external_ids(args.external_id_map)
    report: Dict[str, Any] = {
        "tool": "AWS instance-profile role audit", "version": VERSION,
        "generated_at": now(), "run_id": run_id, "hostname": socket.gethostname(),
        "boto3_version": boto3.__version__, "botocore_version": botocore.__version__,
        "active_validation_enabled": args.probe_assume,
        "profiles_requested": profiles, "allowed_accounts": args.allowed_account,
        "probe_role_arns": args.probe_role_arn, "profiles": []}

    seen_accounts: Set[str] = set()
    tested_paths: Set[Tuple[str, str]] = set()
    for index, profile in enumerate(profiles, 1):
        print(f"[{index}/{len(profiles)}] Auditing {profile}", flush=True)
        result = audit_profile(profile, args, seen_accounts, tested_paths, external_ids)
        report["profiles"].append(result)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", profile)
        exclusive_json(out / f"{safe_name}.json", result)

    summary = {"profiles_total": len(report["profiles"]), "statuses": {},
               "instance_profiles": 0, "roles": 0, "active_validations_succeeded": 0}
    for pr in report["profiles"]:
        status = pr.get("status", "UNKNOWN")
        summary["statuses"][status] = summary["statuses"].get(status, 0) + 1
        summary["instance_profiles"] += len(pr.get("instance_profiles", []))
        for ip in pr.get("instance_profiles", []):
            summary["roles"] += len([r for r in ip.get("roles", []) if r.get("role_arn")])
            summary["active_validations_succeeded"] += sum(
                1 for r in ip.get("roles", []) if r.get("assume_role_probe", {}).get("succeeded"))
    report["summary"] = summary

    exclusive_json(out / "instance_profile_audit.json", report)
    exclusive_json(out / "summary.json", summary)
    exclusive_csv(out / "instance_profile_findings.csv", flatten(report))
    print(json.dumps(summary, indent=2))
    print(f"Evidence directory: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
