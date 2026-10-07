#!/usr/bin/env python3

"""
AWS instance-profile and role-assumption audit.

Purpose:
  1. Enumerate all AWS CLI profiles.
  2. Enumerate every IAM instance profile visible through each profile.
  3. Retrieve contained-role trust policies.
  4. Retrieve attached and inline permissions policies.
  5. Identify potentially unintended role-assumption paths.
  6. Optionally validate sts:AssumeRole without performing resource actions.
  7. Write detailed JSON and CSV reports.

Default behavior is read-only and does not attempt role assumption.

Required IAM read permissions:
  iam:ListInstanceProfiles
  iam:GetInstanceProfile
  iam:GetRole
  iam:ListAttachedRolePolicies
  iam:ListRolePolicies
  iam:GetRolePolicy
  iam:GetPolicy
  iam:GetPolicyVersion

Optional:
  ec2:DescribeRegions
  ec2:DescribeIamInstanceProfileAssociations
  sts:GetCallerIdentity

For --probe-assume:
  sts:AssumeRole on applicable target roles
"""

import argparse
import configparser
import csv
import fnmatch
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)


SCRIPT_VERSION = "1.0"

RETRY_CONFIG = Config(
    retries={
        "max_attempts": 10,
        "mode": "adaptive",
    },
    connect_timeout=10,
    read_timeout=30,
)

ADMIN_ACTION_PATTERNS = {
    "*",
    "iam:*",
    "sts:*",
    "ec2:*",
    "s3:*",
    "lambda:*",
    "organizations:*",
}

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:updateassumerolepolicy",
    "iam:passrole",
    "iam:addroletoinstanceprofile",
    "iam:createrole",
    "iam:createpolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putgrouppolicy",
    "sts:assumerole",
    "sts:assumerolewithwebidentity",
    "sts:assumerolewithsaml",
    "ec2:associateiaminstanceprofile",
    "ec2:replaceiaminstanceprofileassociation",
    "lambda:createfunction",
    "lambda:updatefunctionconfiguration",
    "glue:createdevendpoint",
    "cloudformation:createstack",
    "cloudformation:updatestack",
}

HIGH_IMPACT_ACTION_PATTERNS = {
    "cloudtrail:stoplogging",
    "cloudtrail:delete*",
    "guardduty:delete*",
    "guardduty:dis*",
    "kms:*",
    "secretsmanager:getsecretvalue",
    "ssm:getparameter*",
    "s3:getobject",
    "s3:putbucketpolicy",
    "s3:putbucketacl",
    "ec2:runinstances",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def decode_policy_document(document: Any) -> Dict[str, Any]:
    if isinstance(document, dict):
        return document

    if isinstance(document, str):
        decoded = unquote(document)
        try:
            return json.loads(decoded)
        except json.JSONDecodeError:
            return {"_raw": decoded}

    return {"_raw": document}


def compact_error(exc: Exception) -> Dict[str, str]:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return {
            "code": str(error.get("Code", "ClientError")),
            "message": str(error.get("Message", str(exc))),
        }

    return {
        "code": exc.__class__.__name__,
        "message": str(exc),
    }


def get_configured_profiles() -> List[str]:
    profiles: Set[str] = set(boto3.Session().available_profiles)

    files = [
        Path(os.path.expanduser("~/.aws/config")),
        Path(os.path.expanduser("~/.aws/credentials")),
    ]

    for file_path in files:
        if not file_path.exists():
            continue

        parser = configparser.RawConfigParser()
        parser.read(file_path)

        for section in parser.sections():
            if section.startswith("profile "):
                profiles.add(section[len("profile "):].strip())
            else:
                profiles.add(section.strip())

    return sorted(p for p in profiles if p)


def paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterablepaginator = client.get_paginator(operation)

    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def get_caller_identity(session: boto3.Session) -> Dict[str, Any]:
    return session.client("sts", config=RETRY_CONFIG).get_caller_identity()


def account_from_arn(arn: str) -> Optional[str]:
    parts = arn.split(":")
    if len(parts) >= 6:
        return parts[4] or None
    return None


def action_matches(action: str, patterns: Set[str]) -> bool:
    action_lower = action.lower()

    for pattern in patterns:
        if fnmatch.fnmatchcase(action_lower, pattern.lower()):
            return True

    return False


def resource_is_broad(resource: Any) -> bool:
    resources = normalize_list(resource)
    return any(str(item) == "*" for item in resources)


def conditions_flat(condition: Any) -> List[Tuple[str, str, Any]]:
    flattened: List[Tuple[str, str, Any]] = []

    if not isinstance(condition, dict):
        return flattened

    for operator, entries in condition.items():
        if not isinstance(entries, dict):
            continue

        for key, value in entries.items():
            flattened.append((str(operator), str(key), value))

    return flattened


def condition_has_key(condition: Any, suffix_or_key: str) -> bool:
    target = suffix_or_key.lower()

    for _, key, _ in conditions_flat(condition):
        lowered = key.lower()
        if lowered == target or lowered.endswith(target):
            return True

    return False


def condition_values(condition: Any, wanted_key: str) -> Listresults: List[str] = []
    wanted = wanted_key.lower()

    for _, key, value in conditions_flat(condition):
        key_lower = key.lower()

        if key_lower == wanted or key_lower.endswith(wanted):
            results.extend(str(v) for v in normalize_list(value))

    return results


def wildcard_value(value: str) -> bool:
    return "*" in value or "?" in value


def severity_score(severity: str) -> int:
    return {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(severity, 0)


def add_finding(
    findings: List[Dict[str, Any]],
    severity: str,
    category: str,
    title: str,
    evidence: Any,
    rationale: str,
) -> None:
    findings.append({
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "rationale": rationale,
    })


def analyze_aws_principal(
    principal_values: List[str],
    condition: Dict[str, Any],
    current_account: str,
    findings: List[Dict[str, Any]],
) -> None:
    for principal in principal_values:
        principal_account = account_from_arn(principal)

        if principal == "*":
            add_finding(
                findings,
                "CRITICAL",
                "TrustPolicy",
                "Wildcard AWS principal",
                principal,
                "The trust statement permits an unrestricted AWS principal unless "
                "conditions safely constrain the caller.",
            )

        elif principal.endswith(":root"):
            if principal_account == current_account:
                add_finding(
                    findings,
                    "MEDIUM",
                    "TrustPolicy",
                    "Current account root is trusted",
                    principal,
                    "Trusting the account principal can allow identities in the account "
                    "to assume the role when their identity policies also permit it.",
                )
            else:
                external_id_present = condition_has_key(condition, "sts:ExternalId")
                severity = "MEDIUM" if external_id_present else "HIGH"

                add_finding(
                    findings,
                    severity,
                    "CrossAccountTrust",
                    "External AWS account root is trusted",
                    {
                        "principal": principal,
                        "external_id_condition": external_id_present,
                    },
                    "The role permits cross-account delegation. Validate the external "
                    "account ownership and any ExternalId requirement.",
                )

        elif ":user/" in principal:
            add_finding(
                findings,
                "HIGH",
                "DirectPrincipalTrust",
                "Explicit IAM user can assume the role",
                principal,
                "A long-lived IAM user is explicitly trusted by an EC2-associated role.",
            )

        elif ":role/" in principal:
            severity = "MEDIUM"

            if principal_account and principal_account != current_account:
                severity = "HIGH"

            add_finding(
                findings,
                severity,
                "RoleChaining",
                "IAM role principal can assume the instance-profile role",
                principal,
                "The instance-profile role is also available through STS role assumption.",
            )

        elif principal.startswith("arn:aws:iam::"):
            add_finding(
                findings,
                "MEDIUM",
                "DirectPrincipalTrust",
                "Additional AWS principal is trusted",
                principal,
                "The trust relationship is broader than EC2 service-only trust.",
            )

    principal_arn_values = condition_values(condition, "aws:PrincipalArn")

    for value in principal_arn_values:
        if wildcard_value(value):
            add_finding(
                findings,
                "HIGH",
                "TrustCondition",
                "Wildcard aws:PrincipalArn condition",
                value,
                "A wildcard PrincipalArn pattern can admit more principals than intended.",
            )


def analyze_service_principal(
    services: List[str],
    condition: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> None:
    normalized = {s.lower() for s in services}

    for service in services:
        if service.lower() == "ec2.amazonaws.com":
            source_account = condition_has_key(condition, "aws:SourceAccount")
            source_arn = condition_has_key(condition, "aws:SourceArn")

            add_finding(
                findings,
                "INFO",
                "ExpectedEC2Trust",
                "EC2 service is trusted",
                {
                    "service": service,
                    "source_account_condition": source_account,
                    "source_arn_condition": source_arn,
                },
                "EC2 service trust is expected for an EC2 instance-profile role.",
            )
        else:
            add_finding(
                findings,
                "MEDIUM",
                "AdditionalServiceTrust",
                "Non-EC2 AWS service can assume the role",
                service,
                "The instance-profile role is available to an additional AWS service.",
            )

    if "ec2.amazonaws.com" not in normalized:
        add_finding(
            findings,
            "LOW",
            "UnexpectedTrustModel",
            "Instance-profile role does not trust EC2",
            services,
            "The role is in an instance profile but the reviewed statement does not "
            "include the EC2 service principal.",
        )


def analyze_federated_principal(
    providers: List[str],
    condition: Dict[str, Any],
    actions: List[str],
    findings: List[Dict[str, Any]],
) -> None:
    lowered_actions = {action.lower() for action in actions}

    for provider in providers:
        provider_lower = provider.lower()

        if (
            "token.actions.githubusercontent.com" in provider_lower
            or "assumerolewithwebidentity" in " ".join(lowered_actions)
        ):
            aud_values = condition_values(condition, ":aud")
            sub_values = condition_values(condition, ":sub")

            if not aud_values:
                add_finding(
                    findings,
                    "HIGH",
                    "OIDCTrust",
                    "OIDC trust has no audience restriction",
                    provider,
                    "The trust statement does not visibly restrict the OIDC audience.",
                )

            if not sub_values:
                add_finding(
                    findings,
                    "CRITICAL",
                    "OIDCTrust",
                    "OIDC trust has no subject restriction",
                    provider,
                    "The trust statement does not visibly restrict the OIDC subject.",
                )
            else:
                for subject in sub_values:
                    if wildcard_value(subject):
                        add_finding(
                            findings,
                            "HIGH",
                            "OIDCTrust",
                            "OIDC subject contains a wildcard",
                            subject,
                            "The subject pattern may authorize additional repositories, "
                            "branches, environments or workloads.",
                        )
                    else:
                        add_finding(
                            findings,
                            "INFO",
                            "OIDCTrust",
                            "OIDC trust has an explicit subject",
                            subject,
                            "The OIDC subject is explicitly constrained.",
                        )

        elif "saml-provider/" in provider_lower:
            add_finding(
                findings,
                "MEDIUM",
                "SAMLTrust",
                "SAML identity provider can assume the role",
                provider,
                "The EC2-associated role is also exposed through SAML federation.",
            )

        else:
            add_finding(
                findings,
                "MEDIUM",
                "FederatedTrust",
                "Federated identity provider can assume the role",
                provider,
                "The EC2-associated role is available through a federated trust path.",
            )


def analyze_trust_policy(
    trust_policy: Dict[str, Any],
    current_account: str,
    role_arn: str,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    statements = normalize_list(trust_policy.get("Statement", []))

    if not statements:
        add_finding(
            findings,
            "LOW",
            "TrustPolicy",
            "Trust policy contains no statements",
            trust_policy,
            "No usable trust statement was found.",
        )
        return findings

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue

        effect = str(statement.get("Effect", ""))
        actions = [str(a) for a in normalize_list(statement.get("Action"))]
        principal = statement.get("Principal", {})
        condition = statement.get("Condition", {})

        relevant_actions = {
            "sts:assumerole",
            "sts:assumerolewithwebidentity",
            "sts:assumerolewithsaml",
            "sts:*",
            "*",
        }

        if effect.lower() != "allow":
            continue

        if not any(a.lower() in relevant_actions for a in actions):
            continue

        statement_evidence = {
            "statement_index": index,
            "actions": actions,
            "principal": principal,
            "condition": condition,
        }

        if principal == "*":
            add_finding(
                findings,
                "CRITICAL",
                "TrustPolicy",
                "Allow statement has wildcard Principal",
                statement_evidence,
                "The role trust statement permits any principal unless conditions "
                "strictly constrain access.",
            )
            continue

        if not isinstance(principal, dict):
            add_finding(
                findings,
                "HIGH",
                "TrustPolicy",
                "Unrecognized Principal structure",
                statement_evidence,
                "Manual review of the role trust statement is required.",
            )
            continue

        aws_principals = [
            str(v) for v in normalize_list(principal.get("AWS"))
        ]
        service_principals = [
            str(v) for v in normalize_list(principal.get("Service"))
        ]
        federated_principals = [
            str(v) for v in normalize_list(principal.get("Federated"))
        ]

        if aws_principals:
            analyze_aws_principal(
                aws_principals,
                condition,
                current_account,
                findings,
            )

        if service_principals:
            analyze_service_principal(
                service_principals,
                condition,
                findings,
            )

        if federated_principals:
            analyze_federated_principal(
                federated_principals,
                condition,
                actions,
                findings,
            )

        if not aws_principals and not service_principals and not federated_principals:
            add_finding(
                findings,
                "MEDIUM",
                "TrustPolicy",
                "Trust statement has an unrecognized principal type",
                statement_evidence,
                "Manual review is required.",
            )

        if role_arn in aws_principals:
            add_finding(
                findings,
                "MEDIUM",
                "SelfAssumption",
                "Role explicitly trusts itself",
                role_arn,
                "The role can attempt to create a new session of itself if its identity "
                "permissions also permit sts:AssumeRole.",
            )

        org_values = condition_values(condition, "aws:PrincipalOrgID")
        for org_id in org_values:
            add_finding(
                findings,
                "LOW",
                "OrganizationTrust",
                "Trust is constrained to an AWS Organization",
                org_id,
                "Organization-level trust may include multiple accounts and principals. "
                "Validate whether that scope is intended.",
            )

        if aws_principals and not condition_has_key(condition, "aws:MultiFactorAuthPresent"):
            human_principals = [
                p for p in aws_principals
                if ":user/" in p or p.endswith(":root")
            ]

            if human_principals:
                add_finding(
                    findings,
                    "MEDIUM",
                    "MFACondition",
                    "Human-oriented AWS trust has no MFA condition",
                    human_principals,
                    "No aws:MultiFactorAuthPresent condition was found in the statement.",
                )

    return findings


def extract_allow_statements(policy_document: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for statement in normalize_list(policy_document.get("Statement", [])):
        if not isinstance(statement, dict):
            continue

        if str(statement.get("Effect", "")).lower() == "allow":
            yield statement


def analyze_permission_policy(
    policy_name: str,
    policy_type: str,
    policy_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for statement in extract_allow_statements(policy_document):
        actions = [str(a) for a in normalize_list(statement.get("Action"))]
        resources = normalize_list(statement.get("Resource"))
        broad_resource = resource_is_broad(resources)

        for action in actions:
            if action_matches(action, ADMIN_ACTION_PATTERNS):
                add_finding(
                    findings,
                    "CRITICAL",
                    "PermissionsPolicy",
                    "Administrative permission pattern",
                    {
                        "policy": policy_name,
                        "policy_type": policy_type,
                        "action": action,
                        "resource": resources,
                    },
                    "The role has a broad administrative action pattern.",
                )

            if action_matches(action, PRIVILEGE_ESCALATION_ACTIONS):
                severity = "HIGH" if broad_resource else "MEDIUM"

                add_finding(
                    findings,
                    severity,
                    "PrivilegeEscalationPermission",
                    "Privilege-escalation-relevant permission",
                    {
                        "policy": policy_name,
                        "policy_type": policy_type,
                        "action": action,
                        "resource": resources,
                    },
                    "The action can contribute to role assumption, role passing or IAM "
                    "configuration modification depending on conditions and resources.",
                )

            if action_matches(action, HIGH_IMPACT_ACTION_PATTERNS):
                severity = "HIGH" if broad_resource else "MEDIUM"

                add_finding(
                    findings,
                    severity,
                    "HighImpactPermission",
                    "High-impact permission",
                    {
                        "policy": policy_name,
                        "policy_type": policy_type,
                        "action": action,
                        "resource": resources,
                    },
                    "The permission may materially increase the impact of a successful "
                    "role-assumption path.",
                )

    return findings


def get_managed_policy(
    iam: Any,
    policy_arn: str,
    cache: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    if policy_arn in cache:
        return cache[policy_arn]

    metadata = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = metadata["DefaultVersionId"]

    version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id,
    )["PolicyVersion"]

    result = {
        "arn": policy_arn,
        "name": metadata.get("PolicyName"),
        "default_version_id": version_id,
        "document": decode_policy_document(version.get("Document")),
    }

    cache[policy_arn] = result
    return result


def collect_role_policies(
    iam: Any,
    role_name: str,
    managed_cache: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    managed_policies: List[Dict[str, Any]] = []
    inline_policies: List[Dict[str, Any]] = []
    permission_findings: List[Dict[str, Any]] = []

    for attached in paginate(
        iam,
        "list_attached_role_policies",
        "AttachedPolicies",
        RoleName=role_name,
    ):
        policy_arn = attached["PolicyArn"]

        try:
            policy = get_managed_policy(iam, policy_arn, managed_cache)
            managed_policies.append(policy)

            permission_findings.extend(
                analyze_permission_policy(
                    policy.get("name") or policy_arn,
                    "managed",
                    policy["document"],
                )
            )
        except Exception as exc:
            managed_policies.append({
                "arn": policy_arn,
                "name": attached.get("PolicyName"),
                "error": compact_error(exc),
            })

    inline_names = list(
        paginate(
            iam,
            "list_role_policies",
            "PolicyNames",
            RoleName=role_name,
        )
    )

    for policy_name in inline_names:
        try:
            response = iam.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )

            document = decode_policy_document(
                response.get("PolicyDocument")
            )

            inline_policy = {
                "name": policy_name,
                "document": document,
            }

            inline_policies.append(inline_policy)

            permission_findings.extend(
                analyze_permission_policy(
                    policy_name,
                    "inline",
                    document,
                )
            )
        except Exception as exc:
            inline_policies.append({
                "name": policy_name,
                "error": compact_error(exc),
            })

    return managed_policies, inline_policies, permission_findings


def get_profile_region(session: boto3.Session) -> str:
    return session.region_name or os.getenv("AWS_REGION") or "us-east-1"


def list_enabled_regions(session: boto3.Session) -> Listtry:
        ec2 = session.client(
            "ec2",
            region_name=get_profile_region(session),
            config=RETRY_CONFIG,
        )

        response = ec2.describe_regions(
            AllRegions=False
        )

        return sorted(
            region["RegionName"]
            for region in response.get("Regions", [])
            if region.get("RegionName")
        )
    except Exception:
        return [get_profile_region(session)]


def find_profile_associations(
    session: boto3.Session,
    profile_arn: str,
    scan_regions: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    associations: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    regions = (
        list_enabled_regions(session)
        if scan_regions
        else [get_profile_region(session)]
    )

    for region in regions:
        try:
            ec2 = session.client(
                "ec2",
                region_name=region,
                config=RETRY_CONFIG,
            )

            paginator = ec2.get_paginator(
                "describe_iam_instance_profile_associations"
            )

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "iam-instance-profile.arn",
                        "Values": [profile_arn],
                    }
                ]
            ):
                for association in page.get(
                    "IamInstanceProfileAssociations",
                    []
                ):
                    associations.append({
                        "region": region,
                        "association_id": association.get("AssociationId"),
                        "instance_id": association.get("InstanceId"),
                        "state": association.get("State"),
                        "profile_arn": (
                            association.get("IamInstanceProfile", {})
                            .get("Arn")
                        ),
                    })

        except Exception as exc:
            errors.append({
                "region": region,
                "error": compact_error(exc),
            })

    return associations, errors


def principal_may_match_source(
    trusted_principal: str,
    source_arn: str,
    source_account: str,
) -> bool:
    if trusted_principal == "*":
        return True

    if trusted_principal == source_arn:
        return True

    if trusted_principal == f"arn:aws:iam::{source_account}:root":
        return True

    return False


def trust_has_source_candidate(
    trust_policy: Dict[str, Any],
    source_arn: str,
    source_account: str,
) -> bool:
    for statement in normalize_list(trust_policy.get("Statement", [])):
        if not isinstance(statement, dict):
            continue

        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        actions = {
            str(action).lower()
            for action in normalize_list(statement.get("Action"))
        }

        if not actions.intersection({"sts:assumerole", "sts:*", "*"}):
            continue

        principal = statement.get("Principal")

        if principal == "*":
            return True

        if not isinstance(principal, dict):
            continue

        for trusted in normalize_list(principal.get("AWS")):
            if principal_may_match_source(
                str(trusted),
                source_arn,
                source_account,
            ):
                return True

    return False


def probe_assume_role(
    source_session: boto3.Session,
    role_arn: str,
    external_id: Optional[str],
    duration_seconds: int,
) -> Dict[str, Any]:
    sts = source_session.client("sts", config=RETRY_CONFIG)

    session_name = (
        "instance-profile-audit-"
        + str(int(time.time()))
    )[:64]

    parameters: Dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": duration_seconds,
    }

    if external_id:
        parameters["ExternalId"] = external_id

    try:
        response = sts.assume_role(**parameters)
        credentials = response["Credentials"]

        assumed_session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

        assumed_identity = assumed_session.client(
            "sts",
            config=RETRY_CONFIG,
        ).get_caller_identity()

        del credentials

        return {
            "attempted": True,
            "succeeded": True,
            "session_name": session_name,
            "assumed_identity": {
                "account": assumed_identity.get("Account"),
                "arn": assumed_identity.get("Arn"),
                "user_id_prefix": (
                    str(assumed_identity.get("UserId", "")).split(":")[0]
                ),
            },
        }

    except Exception as exc:
        return {
            "attempted": True,
            "succeeded": False,
            "error": compact_error(exc),
        }


def audit_profile(
    profile_name: str,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "profile": profile_name,
        "started_at": utc_now(),
        "status": "started",
        "instance_profiles": [],
        "errors": [],
    }

    try:
        session = boto3.Session(profile_name=profile_name)
        identity = get_caller_identity(session)

        result["source_identity"] = {
            "account": identity.get("Account"),
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId"),
        }

        source_account = str(identity.get("Account", ""))
        source_arn = str(identity.get("Arn", ""))

        iam = session.client("iam", config=RETRY_CONFIG)
        managed_cache: Dict[str, Dict[str, Any]] = {}

        instance_profiles = list(
            paginate(
                iam,
                "list_instance_profiles",
                "InstanceProfiles",
            )
        )

        for profile in instance_profiles:
            profile_record: Dict[str, Any] = {
                "instance_profile_name": profile.get(
                    "InstanceProfileName"
                ),
                "instance_profile_id": profile.get(
                    "InstanceProfileId"
                ),
                "instance_profile_arn": profile.get("Arn"),
                "path": profile.get("Path"),
                "created_date": (
                    profile.get("CreateDate").isoformat()
                    if profile.get("CreateDate")
                    else None
                ),
                "roles": [],
            }

            if args.scan_ec2_associations:
                associations, association_errors = (
                    find_profile_associations(
                        session,
                        str(profile.get("Arn", "")),
                        args.all_regions,
                    )
                )

                profile_record["ec2_associations"] = associations
                profile_record["ec2_association_errors"] = (
                    association_errors
                )

            for role_summary in profile.get("Roles", []):
                role_name = role_summary["RoleName"]

                try:
                    role = iam.get_role(
                        RoleName=role_name
                    )["Role"]

                    role_arn = role["Arn"]
                    trust_policy = decode_policy_document(
                        role.get("AssumeRolePolicyDocument")
                    )

                    trust_findings = analyze_trust_policy(
                        trust_policy,
                        source_account,
                        role_arn,
                    )

                    (
                        managed_policies,
                        inline_policies,
                        permission_findings,
                    ) = collect_role_policies(
                        iam,
                        role_name,
                        managed_cache,
                    )

                    findings = trust_findings + permission_findings
                    max_severity = max(
                        (
                            severity_score(f["severity"])
                            for f in findings
                        ),
                        default=0,
                    )

                    severity_name = {
                        0: "INFO",
                        1: "LOW",
                        2: "MEDIUM",
                        3: "HIGH",
                        4: "CRITICAL",
                    }[max_severity]

                    source_is_candidate = trust_has_source_candidate(
                        trust_policy,
                        source_arn,
                        source_account,
                    )

                    role_record: Dict[str, Any] = {
                        "role_name": role_name,
                        "role_id": role.get("RoleId"),
                        "role_arn": role_arn,
                        "path": role.get("Path"),
                        "created_date": (
                            role.get("CreateDate").isoformat()
                            if role.get("CreateDate")
                            else None
                        ),
                        "max_session_duration": role.get(
                            "MaxSessionDuration"
                        ),
                        "permissions_boundary": role.get(
                            "PermissionsBoundary"
                        ),
                        "trust_policy": trust_policy,
                        "managed_policies": managed_policies,
                        "inline_policies": inline_policies,
                        "findings": findings,
                        "maximum_severity": severity_name,
                        "source_profile_is_trust_candidate": (
                            source_is_candidate
                        ),
                    }

                    if args.probe_assume and source_is_candidate:
                        role_record["assume_role_probe"] = (
                            probe_assume_role(
                                session,
                                role_arn,
                                args.external_id,
                                args.duration_seconds,
                            )
                        )
                    else:
                        role_record["assume_role_probe"] = {
                            "attempted": False,
                            "reason": (
                                "Live probing disabled"
                                if not args.probe_assume
                                else "Source profile not identified as a "
                                     "trust-policy candidate"
                            ),
                        }

                    profile_record["roles"].append(role_record)

                except Exception as exc:
                    profile_record["roles"].append({
                        "role_name": role_name,
                        "error": compact_error(exc),
                    })

            result["instance_profiles"].append(profile_record)

        result["status"] = "completed"

    except (
        ProfileNotFound,
        NoCredentialsError,
        ClientError,
        BotoCoreError,
        Exception,
    ) as exc:
        result["status"] = "failed"
        result["errors"].append(compact_error(exc))

    result["completed_at"] = utc_now()
    return result


def write_json(path: Path, content: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            content,
            handle,
            indent=2,
            default=str,
            sort_keys=False,
        )


def flatten_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for profile_result in report.get("profiles", []):
        source = profile_result.get("source_identity", {})

        for instance_profile in profile_result.get(
            "instance_profiles",
            []
        ):
            associations = instance_profile.get(
                "ec2_associations",
                []
            )

            attached_instances = ",".join(
                sorted(
                    {
                        str(a.get("instance_id"))
                        for a in associations
                        if a.get("instance_id")
                    }
                )
            )

            for role in instance_profile.get("roles", []):
                if "error" in role:
                    rows.append({
                        "aws_profile": profile_result.get("profile"),
                        "source_account": source.get("account"),
                        "source_arn": source.get("arn"),
                        "instance_profile_name": (
                            instance_profile.get(
                                "instance_profile_name"
                            )
                        ),
                        "instance_profile_arn": (
                            instance_profile.get(
                                "instance_profile_arn"
                            )
                        ),
                        "role_name": role.get("role_name"),
                        "error": json.dumps(role.get("error")),
                    })
                    continue

                findings = role.get("findings", [])
                probe = role.get("assume_role_probe", {})

                if not findings:
                    findings = [{
                        "severity": "INFO",
                        "category": "Review",
                        "title": "No heuristic finding",
                        "evidence": "",
                        "rationale": (
                            "No finding was generated by the implemented "
                            "heuristics."
                        ),
                    }]

                for finding in findings:
                    rows.append({
                        "aws_profile": profile_result.get("profile"),
                        "source_account": source.get("account"),
                        "source_arn": source.get("arn"),
                        "instance_profile_name": (
                            instance_profile.get(
                                "instance_profile_name"
                            )
                        ),
                        "instance_profile_arn": (
                            instance_profile.get(
                                "instance_profile_arn"
                            )
                        ),
                        "attached_instance_ids": attached_instances,
                        "role_name": role.get("role_name"),
                        "role_arn": role.get("role_arn"),
                        "source_profile_is_trust_candidate": (
                            role.get(
                                "source_profile_is_trust_candidate"
                            )
                        ),
                        "probe_attempted": probe.get("attempted"),
                        "probe_succeeded": probe.get("succeeded"),
                        "maximum_severity": (
                            role.get("maximum_severity")
                        ),
                        "finding_severity": finding.get("severity"),
                        "finding_category": finding.get("category"),
                        "finding_title": finding.get("title"),
                        "finding_evidence": json.dumps(
                            finding.get("evidence"),
                            default=str,
                        ),
                        "finding_rationale": finding.get("rationale"),
                        "error": "",
                    })

    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    columns = [
        "aws_profile",
        "source_account",
        "source_arn",
        "instance_profile_name",
        "instance_profile_arn",
        "attached_instance_ids",
        "role_name",
        "role_arn",
        "source_profile_is_trust_candidate",
        "probe_attempted",
        "probe_succeeded",
        "maximum_severity",
        "finding_severity",
        "finding_category",
        "finding_title",
        "finding_evidence",
        "finding_rationale",
        "error",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=columns,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)


def build_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    summary = {
        "profiles_total": 0,
        "profiles_completed": 0,
        "profiles_failed": 0,
        "instance_profiles_total": 0,
        "roles_total": 0,
        "trust_candidates_total": 0,
        "successful_assume_probes": 0,
        "severity_counts": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        },
    }

    for profile in report.get("profiles", []):
        summary["profiles_total"] += 1

        if profile.get("status") == "completed":
            summary["profiles_completed"] += 1
        else:
            summary["profiles_failed"] += 1

        for instance_profile in profile.get(
            "instance_profiles",
            []
        ):
            summary["instance_profiles_total"] += 1

            for role in instance_profile.get("roles", []):
                if role.get("role_arn"):
                    summary["roles_total"] += 1

                if role.get("source_profile_is_trust_candidate"):
                    summary["trust_candidates_total"] += 1

                if (
                    role.get("assume_role_probe", {})
                    .get("succeeded")
                ):
                    summary["successful_assume_probes"] += 1

                for finding in role.get("findings", []):
                    severity = finding.get("severity", "INFO")
                    if severity in summary["severity_counts"]:
                        summary["severity_counts"][severity] += 1

    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate AWS IAM instance profiles and identify "
            "potentially assumable or over-trusted contained roles."
        )
    )

    parser.add_argument(
        "--profiles",
        nargs="+",
        help=(
            "Only audit these AWS CLI profiles. By default, all "
            "configured profiles are audited."
        ),
    )

    parser.add_argument(
        "--exclude-profiles",
        nargs="*",
        default=[],
        help="AWS CLI profiles to exclude.",
    )

    parser.add_argument(
        "--out-dir",
        default="instance-profile-audit",
        help="Output directory.",
    )

    parser.add_argument(
        "--scan-ec2-associations",
        action="store_true",
        help=(
            "Check whether instance profiles are associated with "
            "EC2 instances."
        ),
    )

    parser.add_argument(
        "--all-regions",
        action="store_true",
        help=(
            "When association scanning is enabled, scan all enabled "
            "regions."
        ),
    )

    parser.add_argument(
        "--probe-assume",
        action="store_true",
        help=(
            "Attempt sts:AssumeRole only when the current source "
            "profile appears to match the target trust policy."
        ),
    )

    parser.add_argument(
        "--external-id",
        help=(
            "ExternalId to supply during optional AssumeRole "
            "validation."
        ),
    )

    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=900,
        help="Duration for optional AssumeRole validation.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.duration_seconds < 900:
        print(
            "Error: --duration-seconds must be at least 900.",
            file=sys.stderr,
        )
        return 2

    if args.profiles:
        profiles = sorted(set(args.profiles))
    else:
        profiles = get_configured_profiles()

    excluded = set(args.exclude_profiles)
    profiles = [
        profile
        for profile in profiles
        if profile not in excluded
    ]

    if not profiles:
        print(
            "No AWS CLI profiles were found.",
            file=sys.stderr,
        )
        return 1

    output_directory = Path(args.out_dir)
    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report: Dict[str, Any] = {
        "tool": "AWS instance-profile role audit",
        "version": SCRIPT_VERSION,
        "generated_at": utc_now(),
        "live_assume_role_validation_enabled": args.probe_assume,
        "profiles_requested": profiles,
        "profiles": [],
    }

    for index, profile in enumerate(profiles, start=1):
        print(
            f"[{index}/{len(profiles)}] Auditing profile: {profile}",
            flush=True,
        )

        profile_result = audit_profile(
            profile,
            args,
        )

        report["profiles"].append(profile_result)

        safe_profile = re.sub(
            r"[^A-Za-z0-9_.-]+",
            "_",
            profile,
        )

        write_json(
            output_directory / f"{safe_profile}.json",
            profile_result,
        )

    report["summary"] = build_summary(report)

    write_json(
        output_directory / "instance_profile_audit.json",
        report,
    )

    rows = flatten_rows(report)

    write_csv(
        output_directory / "instance_profile_findings.csv",
        rows,
    )

    write_json(
        output_directory / "summary.json",
        report["summary"],
    )

    print()
    print(json.dumps(report["summary"], indent=2))
    print()
    print(
        "Detailed JSON:",
        output_directory / "instance_profile_audit.json",
    )
    print(
        "Finding CSV:",
        output_directory / "instance_profile_findings.csv",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
