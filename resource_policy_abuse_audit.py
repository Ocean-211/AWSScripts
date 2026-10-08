#!/usr/bin/env python3
"""Read-only AWS resource-policy enumeration and static abuse analysis.

Enumerates applicable resource policies across configured AWS CLI profiles and
selected/all AWS regions. Findings are potential exposure paths, not proof of
effective access. SCPs, identity policies, permissions boundaries, session
policies, explicit denies, service-level public-access controls, and network
conditions may alter the final authorization decision.

Coverage:
  S3, KMS keys and grants, Lambda, SQS, SNS, Secrets Manager, ECR,
  EventBridge event buses, AWS Backup vaults, OpenSearch domains,
  VPC endpoint policies, and API Gateway REST API policies.
"""

import argparse
import csv
import hashlib
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import (
        ClientError,
        NoCredentialsError,
        PartialCredentialsError,
        ProfileNotFound,
    )
except ImportError:
    sys.exit("[FATAL] boto3 is required: pip install boto3")

LOG = logging.getLogger("resource-policy-audit")
BOTO_CONFIG = Config(
    retries={"max_attempts": 4, "mode": "standard"},
    connect_timeout=10,
    read_timeout=30,
)
GLOBAL_REGION = "us-east-1"

DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "UnauthorizedException",
}
NOT_FOUND_CODES = {
    "NoSuchBucketPolicy",
    "ResourceNotFoundException",
    "NotFoundException",
    "NoSuchEntity",
    "PolicyNotFoundException",
}
THROTTLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def sanitize(value):
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("_")
    return cleaned or "unnamed"


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8",
    )
    temporary.replace(path)


def parse_policy(value):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    for candidate in (value, unquote(value)):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except (TypeError, ValueError):
            continue
    return None


def account_from_arn(value):
    match = re.match(
        r"^arn:[^:]+:[^:]*:[^:]*:(\d{12}):",
        str(value),
    )
    return match.group(1) if match else None


def wildcard_match(pattern, value):
    expression = (
        "^"
        + re.escape(str(pattern))
        .replace(r"\*", ".*")
        .replace(r"\?", ".")
        + "$"
    )
    return re.match(expression, str(value), re.IGNORECASE) is not None


def classify_exception(exception):
    if isinstance(exception, ClientError):
        error = exception.response.get("Error", {})
        code = error.get("Code", "Unknown")
        message = error.get("Message", str(exception))
        detail = f"{code}: {message}"
        if code in DENIED_CODES or "not authorized" in message.lower():
            return "ACCESS_DENIED", detail
        if code in NOT_FOUND_CODES:
            return "NOT_FOUND", detail
        if code in THROTTLE_CODES:
            return "THROTTLED", detail
        return "ERROR", detail
    if isinstance(
        exception,
        (NoCredentialsError, PartialCredentialsError, ProfileNotFound),
    ):
        return "CREDENTIAL_FAILURE", str(exception)
    return "ERROR", f"{type(exception).__name__}: {exception}"


class ProfileRun:
    def __init__(self, profile, output_root):
        self.profile = profile
        self.root = output_root / sanitize(profile)
        self.raw_root = self.root / "raw-policies"
        self.account = "UNKNOWN"
        self.caller = ""
        self.status = []
        self.findings = []
        self.policy_counts = {}

    def record(self, service, operation, target, status, detail=""):
        self.status.append(
            {
                "Timestamp": utc_now(),
                "Profile": self.profile,
                "AccountId": self.account,
                "Service": service,
                "Operation": operation,
                "Target": str(target),
                "Status": status,
                "Detail": " ".join(str(detail).split())[:1000],
            }
        )

    def call(
        self,
        service,
        operation,
        target,
        function,
        *args,
        missing_ok=False,
        **kwargs,
    ):
        try:
            response = function(*args, **kwargs)
            self.record(service, operation, target, "SUCCESS")
            return response
        except Exception as exception:
            status, detail = classify_exception(exception)
            if missing_ok and status == "NOT_FOUND":
                status = "EMPTY"
            self.record(service, operation, target, status, detail)
            return None

    def save_policy(
        self,
        service,
        resource_type,
        resource_id,
        region,
        policy,
        metadata=None,
    ):
        document = parse_policy(policy)
        if not document:
            self.record(
                service,
                "ParsePolicy",
                resource_id,
                "EMPTY",
                "No parseable policy document",
            )
            return

        digest = hashlib.sha256(
            f"{service}|{region}|{resource_id}".encode("utf-8")
        ).hexdigest()[:10]
        filename = (
            f"{sanitize(resource_type)}--"
            f"{sanitize(resource_id)[-100:]}--{digest}.json"
        )
        path = self.raw_root / sanitize(service) / filename
        item = {
            "Profile": self.profile,
            "AccountId": self.account,
            "Region": region,
            "Service": service,
            "ResourceType": resource_type,
            "ResourceId": resource_id,
            "Metadata": metadata or {},
            "Policy": document,
        }
        write_json(path, item)
        self.policy_counts[service] = self.policy_counts.get(service, 0) + 1
        self.analyze_policy(item, str(path.relative_to(self.root)))

    def add_finding(
        self,
        item,
        category,
        severity,
        statement,
        evidence,
        impact,
        confidence="MEDIUM",
    ):
        self.findings.append(
            {
                "Profile": self.profile,
                "AccountId": self.account,
                "Region": item["Region"],
                "Service": item["Service"],
                "ResourceType": item["ResourceType"],
                "ResourceId": item["ResourceId"],
                "Category": category,
                "Severity": severity,
                "Confidence": confidence,
                "StatementSid": (
                    statement.get("Sid", "")
                    if isinstance(statement, dict)
                    else ""
                ),
                "Evidence": evidence,
                "Impact": impact,
                "Source": item.get("Source", ""),
            }
        )

    def analyze_policy(self, item, source):
        item["Source"] = source
        policy = item["Policy"]

        for statement in as_list(policy.get("Statement")):
            if not isinstance(statement, dict):
                continue
            if str(statement.get("Effect", "")).lower() != "allow":
                continue

            principal = statement.get("Principal")
            actions = as_list(statement.get("Action"))
            not_actions = as_list(statement.get("NotAction"))
            conditions = statement.get("Condition") or {}
            resources = as_list(statement.get("Resource"))

            principal_values = []
            if principal == "*":
                principal_values = ["*"]
            elif isinstance(principal, dict):
                for value in principal.values():
                    principal_values.extend(
                        str(entry) for entry in as_list(value)
                    )

            public = "*" in principal_values
            external_accounts = sorted(
                {
                    account
                    for account in (
                        account_from_arn(value)
                        for value in principal_values
                    )
                    if account and account != self.account
                }
            )
            broad_action = bool(not_actions) or any(
                action == "*" or str(action).endswith(":*")
                for action in actions
            )
            broad_resource = any(resource == "*" for resource in resources)
            conditions_text = json.dumps(
                conditions,
                default=str,
            ).lower()
            constrained = bool(conditions)
            organization_limited = (
                "aws:principalorgid" in conditions_text
                or "aws:principalorgpaths" in conditions_text
            )
            source_limited = (
                "aws:sourcearn" in conditions_text
                or "aws:sourceaccount" in conditions_text
            )

            if public:
                self.add_finding(
                    item,
                    "PUBLIC_RESOURCE_POLICY",
                    "CRITICAL" if broad_action else "HIGH",
                    statement,
                    {
                        "Principal": principal,
                        "Action": actions,
                        "NotAction": not_actions,
                        "Resource": resources,
                        "Condition": conditions,
                    },
                    "The resource policy allows an anonymous or unrestricted "
                    "principal. Conditions and service-level public-access "
                    "controls must be validated.",
                    "HIGH",
                )

            if external_accounts:
                self.add_finding(
                    item,
                    "CROSS_ACCOUNT_RESOURCE_ACCESS",
                    "HIGH" if not constrained else "MEDIUM",
                    statement,
                    {
                        "ExternalAccounts": external_accounts,
                        "Principal": principal,
                        "Action": actions,
                        "Condition": conditions,
                    },
                    "An external AWS account is granted access directly by "
                    "the resource policy.",
                    "HIGH",
                )

            if broad_action and (public or external_accounts):
                self.add_finding(
                    item,
                    "BROAD_ACTION_EXTERNAL_PRINCIPAL",
                    "CRITICAL",
                    statement,
                    {
                        "Principal": principal,
                        "Action": actions,
                        "NotAction": not_actions,
                        "Resource": resources,
                    },
                    "A public or cross-account principal receives wildcard "
                    "or NotAction-based permissions.",
                    "HIGH",
                )

            if broad_resource and (public or external_accounts):
                self.add_finding(
                    item,
                    "BROAD_RESOURCE_SCOPE",
                    "HIGH",
                    statement,
                    {
                        "Principal": principal,
                        "Action": actions,
                        "Resource": resources,
                    },
                    "External access applies to a wildcard resource scope.",
                )

            service_principals = [
                value
                for value in principal_values
                if value.endswith(".amazonaws.com")
            ]
            if service_principals and not source_limited:
                self.add_finding(
                    item,
                    "CONFUSED_DEPUTY_GUARD_MISSING",
                    "HIGH",
                    statement,
                    {
                        "ServicePrincipals": service_principals,
                        "Action": actions,
                        "Condition": conditions,
                    },
                    "A service principal is trusted without aws:SourceArn or "
                    "aws:SourceAccount protection. Validate whether a "
                    "confused-deputy path exists.",
                    "MEDIUM",
                )

            if (
                (public or external_accounts)
                and not organization_limited
                and not constrained
            ):
                self.add_finding(
                    item,
                    "UNCONSTRAINED_EXTERNAL_ACCESS",
                    "HIGH",
                    statement,
                    {
                        "Principal": principal,
                        "Action": actions,
                    },
                    "External access has no policy Condition block.",
                    "HIGH",
                )

            if item["Service"] == "kms" and any(
                wildcard_match(action, "kms:CreateGrant")
                for action in actions
            ):
                self.add_finding(
                    item,
                    "KMS_GRANT_CREATION_EXPOSURE",
                    "CRITICAL" if (public or external_accounts) else "HIGH",
                    statement,
                    {
                        "Principal": principal,
                        "Action": actions,
                        "Condition": conditions,
                    },
                    "The principal may create KMS grants, which can delegate "
                    "persistent cryptographic permissions.",
                )

            if (
                item["Service"] == "lambda"
                and (public or external_accounts)
                and any(
                    wildcard_match(action, "lambda:InvokeFunction")
                    for action in actions
                )
            ):
                self.add_finding(
                    item,
                    "EXTERNAL_LAMBDA_INVOCATION",
                    "HIGH",
                    statement,
                    {
                        "Principal": principal,
                        "Condition": conditions,
                    },
                    "The Lambda function may be invoked by a public or "
                    "external principal.",
                    "HIGH",
                )


def iter_pages(client, operation, **kwargs):
    try:
        paginator = client.get_paginator(operation)
        yield from paginator.paginate(**kwargs)
    except Exception:
        yield getattr(client, operation)(**kwargs)


def available_regions(session):
    regions = set(session.get_available_regions("ec2"))
    regions.add(session.region_name or GLOBAL_REGION)
    return sorted(regions)


def enumerate_s3(run, session):
    client = session.client("s3", config=BOTO_CONFIG)
    response = run.call(
        "s3",
        "ListBuckets",
        "account",
        client.list_buckets,
    ) or {}

    for bucket in response.get("Buckets", []):
        name = bucket.get("Name")
        location = run.call(
            "s3",
            "GetBucketLocation",
            name,
            client.get_bucket_location,
            Bucket=name,
        ) or {}
        region = location.get("LocationConstraint") or GLOBAL_REGION
        policy = run.call(
            "s3",
            "GetBucketPolicy",
            name,
            client.get_bucket_policy,
            Bucket=name,
            missing_ok=True,
        )
        if policy and policy.get("Policy"):
            run.save_policy(
                "s3",
                "bucket",
                name,
                region,
                policy["Policy"],
            )


def enumerate_region(run, session, region):
    # KMS key policies and grants
    kms = session.client("kms", region_name=region, config=BOTO_CONFIG)
    for page in iter_pages(kms, "list_keys"):
        for key in page.get("Keys", []):
            key_id = key.get("KeyId")
            policy = run.call(
                "kms",
                "GetKeyPolicy",
                key_id,
                kms.get_key_policy,
                KeyId=key_id,
                PolicyName="default",
            )
            if policy and policy.get("Policy"):
                run.save_policy(
                    "kms",
                    "key",
                    key_id,
                    region,
                    policy["Policy"],
                )

            grants = run.call(
                "kms",
                "ListGrants",
                key_id,
                kms.list_grants,
                KeyId=key_id,
            )
            if grants:
                for grant in grants.get("Grants", []):
                    grant_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": grant.get("GrantId", ""),
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": grant.get("GranteePrincipal")
                                },
                                "Action": [
                                    f"kms:{operation}"
                                    for operation in grant.get(
                                        "Operations",
                                        [],
                                    )
                                ],
                                "Resource": "*",
                                "Condition": grant.get("Constraints", {}),
                            }
                        ],
                    }
                    run.save_policy(
                        "kms",
                        "grant",
                        f"{key_id}:{grant.get('GrantId')}",
                        region,
                        grant_policy,
                        {
                            "RetiringPrincipal": grant.get(
                                "RetiringPrincipal"
                            )
                        },
                    )

    # Lambda
    lambda_client = session.client(
        "lambda",
        region_name=region,
        config=BOTO_CONFIG,
    )
    for page in iter_pages(lambda_client, "list_functions"):
        for function in page.get("Functions", []):
            arn = function.get("FunctionArn")
            policy = run.call(
                "lambda",
                "GetPolicy",
                arn,
                lambda_client.get_policy,
                FunctionName=arn,
                missing_ok=True,
            )
            if policy and policy.get("Policy"):
                run.save_policy(
                    "lambda",
                    "function",
                    arn,
                    region,
                    policy["Policy"],
                )

    # SQS
    sqs = session.client("sqs", region_name=region, config=BOTO_CONFIG)
    queues = run.call(
        "sqs",
        "ListQueues",
        region,
        sqs.list_queues,
    ) or {}
    for queue_url in queues.get("QueueUrls", []):
        attributes = run.call(
            "sqs",
            "GetQueueAttributes",
            queue_url,
            sqs.get_queue_attributes,
            QueueUrl=queue_url,
            AttributeNames=["Policy", "QueueArn"],
        )
        values = (attributes or {}).get("Attributes", {})
        if values.get("Policy"):
            run.save_policy(
                "sqs",
                "queue",
                values.get("QueueArn", queue_url),
                region,
                values["Policy"],
            )

    # SNS
    sns = session.client("sns", region_name=region, config=BOTO_CONFIG)
    for page in iter_pages(sns, "list_topics"):
        for topic in page.get("Topics", []):
            arn = topic.get("TopicArn")
            attributes = run.call(
                "sns",
                "GetTopicAttributes",
                arn,
                sns.get_topic_attributes,
                TopicArn=arn,
            )
            values = (attributes or {}).get("Attributes", {})
            if values.get("Policy"):
                run.save_policy(
                    "sns",
                    "topic",
                    arn,
                    region,
                    values["Policy"],
                )

    # Secrets Manager
    secrets = session.client(
        "secretsmanager",
        region_name=region,
        config=BOTO_CONFIG,
    )
    for page in iter_pages(secrets, "list_secrets"):
        for secret in page.get("SecretList", []):
            arn = secret.get("ARN")
            policy = run.call(
                "secretsmanager",
                "GetResourcePolicy",
                arn,
                secrets.get_resource_policy,
                SecretId=arn,
                missing_ok=True,
            )
            if policy and policy.get("ResourcePolicy"):
                run.save_policy(
                    "secretsmanager",
                    "secret",
                    arn,
                    region,
                    policy["ResourcePolicy"],
                )

    # ECR
    ecr = session.client("ecr", region_name=region, config=BOTO_CONFIG)
    for page in iter_pages(ecr, "describe_repositories"):
        for repository in page.get("repositories", []):
            name = repository.get("repositoryName")
            policy = run.call(
                "ecr",
                "GetRepositoryPolicy",
                name,
                ecr.get_repository_policy,
                repositoryName=name,
                missing_ok=True,
            )
            if policy and policy.get("policyText"):
                run.save_policy(
                    "ecr",
                    "repository",
                    repository.get("repositoryArn", name),
                    region,
                    policy["policyText"],
                )

    # EventBridge event buses
    events = session.client(
        "events",
        region_name=region,
        config=BOTO_CONFIG,
    )
    for page in iter_pages(events, "list_event_buses"):
        for bus in page.get("EventBuses", []):
            if bus.get("Policy"):
                run.save_policy(
                    "events",
                    "event-bus",
                    bus.get("Arn", bus.get("Name")),
                    region,
                    bus["Policy"],
                )

    # AWS Backup vaults
    backup = session.client(
        "backup",
        region_name=region,
        config=BOTO_CONFIG,
    )
    for page in iter_pages(backup, "list_backup_vaults"):
        for vault in page.get("BackupVaultList", []):
            name = vault.get("BackupVaultName")
            policy = run.call(
                "backup",
                "GetBackupVaultAccessPolicy",
                name,
                backup.get_backup_vault_access_policy,
                BackupVaultName=name,
                missing_ok=True,
            )
            if policy and policy.get("Policy"):
                run.save_policy(
                    "backup",
                    "vault",
                    vault.get("BackupVaultArn", name),
                    region,
                    policy["Policy"],
                )

    # OpenSearch domains
    opensearch = session.client(
        "opensearch",
        region_name=region,
        config=BOTO_CONFIG,
    )
    domains = run.call(
        "opensearch",
        "ListDomainNames",
        region,
        opensearch.list_domain_names,
    ) or {}
    for domain in domains.get("DomainNames", []):
        name = domain.get("DomainName")
        configuration = run.call(
            "opensearch",
            "DescribeDomainConfig",
            name,
            opensearch.describe_domain_config,
            DomainName=name,
        )
        policy = (
            (((configuration or {}).get("DomainConfig") or {}).get(
                "AccessPolicies"
            ) or {}).get("Options")
        )
        if policy:
            run.save_policy(
                "opensearch",
                "domain",
                name,
                region,
                policy,
            )

    # VPC endpoint policies
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    for page in iter_pages(ec2, "describe_vpc_endpoints"):
        for endpoint in page.get("VpcEndpoints", []):
            if endpoint.get("PolicyDocument"):
                run.save_policy(
                    "ec2",
                    "vpc-endpoint",
                    endpoint.get("VpcEndpointId"),
                    region,
                    endpoint["PolicyDocument"],
                    {"ServiceName": endpoint.get("ServiceName")},
                )

    # API Gateway REST API policies
    api_gateway = session.client(
        "apigateway",
        region_name=region,
        config=BOTO_CONFIG,
    )
    for page in iter_pages(
        api_gateway,
        "get_rest_apis",
        limit=500,
    ):
        for api in page.get("items", []):
            if api.get("policy"):
                run.save_policy(
                    "apigateway",
                    "rest-api",
                    api.get("id"),
                    region,
                    api["policy"],
                    {"Name": api.get("name")},
                )


def write_outputs(run):
    run.root.mkdir(parents=True, exist_ok=True)

    write_json(
        run.root / "resource-policy-findings.json",
        {
            "Profile": run.profile,
            "AccountId": run.account,
            "Caller": run.caller,
            "GeneratedAt": utc_now(),
            "PolicyCounts": run.policy_counts,
            "Limitations": [
                "Static policy analysis does not prove effective access.",
                "Explicit denies and organization controls may override an allow.",
                "A missing result after ACCESS_DENIED means not enumerated, not absent.",
            ],
            "Findings": run.findings,
        },
    )

    finding_fields = [
        "Profile",
        "AccountId",
        "Region",
        "Service",
        "ResourceType",
        "ResourceId",
        "Category",
        "Severity",
        "Confidence",
        "StatementSid",
        "Evidence",
        "Impact",
        "Source",
    ]
    with (run.root / "resource-policy-findings.csv").open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=finding_fields,
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        for finding in run.findings:
            row = dict(finding)
            row["Evidence"] = json.dumps(
                row["Evidence"],
                default=str,
                sort_keys=True,
            )
            writer.writerow(row)

    status_fields = [
        "Timestamp",
        "Profile",
        "AccountId",
        "Service",
        "Operation",
        "Target",
        "Status",
        "Detail",
    ]
    with (run.root / "enumeration-status.csv").open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=status_fields,
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        writer.writerows(run.status)

    status_values = sorted({entry["Status"] for entry in run.status})
    write_json(
        run.root / "profile-summary.json",
        {
            "Profile": run.profile,
            "AccountId": run.account,
            "Caller": run.caller,
            "PoliciesRetrieved": sum(run.policy_counts.values()),
            "Findings": len(run.findings),
            "PolicyCounts": run.policy_counts,
            "StatusCounts": {
                status: sum(
                    1
                    for entry in run.status
                    if entry["Status"] == status
                )
                for status in status_values
            },
        },
    )


def process_profile(profile, output_root, selected_regions=None):
    run = ProfileRun(profile, output_root)

    try:
        session = boto3.Session(profile_name=profile)
    except Exception as exception:
        status, detail = classify_exception(exception)
        run.record("session", "CreateSession", profile, status, detail)
        write_outputs(run)
        return run

    sts = session.client(
        "sts",
        region_name=session.region_name or GLOBAL_REGION,
        config=BOTO_CONFIG,
    )
    identity = run.call(
        "sts",
        "GetCallerIdentity",
        profile,
        sts.get_caller_identity,
    )
    if not identity:
        write_outputs(run)
        return run

    run.account = identity.get("Account", "UNKNOWN")
    run.caller = identity.get("Arn", "")

    enumerate_s3(run, session)

    for region in selected_regions or available_regions(session):
        try:
            enumerate_region(run, session, region)
        except Exception as exception:
            status, detail = classify_exception(exception)
            run.record(
                "region",
                "EnumerateRegion",
                region,
                status,
                detail,
            )

    write_outputs(run)
    return run


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Read-only AWS resource-policy enumeration and abuse-path analysis"
        )
    )
    parser.add_argument(
        "-o",
        "--output",
        default="aws-resource-policy-analysis",
    )
    parser.add_argument(
        "-p",
        "--profiles",
        nargs="+",
        help="AWS CLI profiles; default is all configured profiles",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        help="Restrict regional enumeration",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def main():
    arguments = parse_args()
    output_root = Path(arguments.output)
    output_root.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG if arguments.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    profiles = arguments.profiles or boto3.Session().available_profiles
    if not profiles:
        LOG.error("No AWS CLI profiles found")
        return 1

    summaries = []
    for profile in profiles:
        LOG.info("Processing profile %s", profile)
        run = process_profile(
            profile,
            output_root,
            arguments.regions,
        )
        summaries.append(
            {
                "Profile": profile,
                "AccountId": run.account,
                "Policies": sum(run.policy_counts.values()),
                "Findings": len(run.findings),
            }
        )

    write_json(
        output_root / "run-summary.json",
        {
            "GeneratedAt": utc_now(),
            "Profiles": summaries,
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
