# Core enhanced analysis module from aws_iam_abuse_path_analyzer.py
# This page shows the abuse-path analysis logic added to the IAM enumerator.

import csv
import json
import re
from pathlib import Path

CALLER_CAPABILITY_ACTIONS = [
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "ec2:RunInstances",
]


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def wildcard_match(pattern, value):
    regex = (
        "^"
        + re.escape(str(pattern))
        .replace(r"\*", ".*")
        .replace(r"\?", ".")
        + "$"
    )
    return re.match(regex, str(value), re.IGNORECASE) is not None


def action_allowed_by_statement(statement, action):
    if str(statement.get("Effect", "")).lower() != "allow":
        return False

    actions = as_list(statement.get("Action"))
    not_actions = as_list(statement.get("NotAction"))

    if actions and any(wildcard_match(item, action) for item in actions):
        return True

    if not_actions and not any(
        wildcard_match(item, action) for item in not_actions
    ):
        return True

    return False


def policy_document_from_json(data):
    if not isinstance(data, dict):
        return None

    candidates = [
        data,
        data.get("PolicyDocument"),
        (data.get("PolicyVersion") or {}).get("Document"),
        (data.get("Role") or {}).get("AssumeRolePolicyDocument"),
    ]

    for candidate in candidates:
        if isinstance(candidate, dict) and (
            "Statement" in candidate or "Version" in candidate
        ):
            return candidate

    return None


def conditions_weak_or_absent(statement, oidc=False):
    condition = statement.get("Condition")

    if not isinstance(condition, dict) or not condition:
        return True, ["No Condition block"]

    flattened = []
    for operator, values in condition.items():
        if isinstance(values, dict):
            for key, value in values.items():
                flattened.append(
                    (str(operator), str(key), as_list(value))
                )

    reasons = []

    if oidc:
        keys = [key.lower() for _, key, _ in flattened]

        if not any(key.endswith(":sub") for key in keys):
            reasons.append("OIDC subject claim is not constrained")

        if not any(key.endswith(":aud") for key in keys):
            reasons.append("OIDC audience claim is not constrained")

    for operator, key, values in flattened:
        if any("*" in str(value) for value in values):
            reasons.append(
                f"Wildcard condition value in {operator}:{key}"
            )

    return bool(reasons), reasons


def account_from_arn(value):
    match = re.match(
        r"^arn:[^:]+:iam::(\d{12}):",
        str(value),
    )
    return match.group(1) if match else None


def load_json(path):
    try:
        with Path(path).open(encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (OSError, ValueError):
        return None


def collect_role_policy_statements(role_dir):
    statements = []
    sources = []

    policy_files = list(
        role_dir.glob(
            "attached-managed-policies/*-permissions.json"
        )
    )
    policy_files += list(
        role_dir.glob("inline-policies/*-permissions.json")
    )

    for path in policy_files:
        data = load_json(path)
        document = policy_document_from_json(data)

        if not document:
            continue

        for statement in as_list(document.get("Statement")):
            if isinstance(statement, dict):
                statements.append(statement)
                sources.append(str(path))

    return statements, sources


def role_is_privileged(statements):
    sensitive_actions = [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
        "iam:CreatePolicyVersion",
        "sts:AssumeRole",
        "lambda:AddPermission",
        "cloudformation:CreateStack",
        "organizations:*",
    ]

    reasons = []

    for statement in statements:
        for action in sensitive_actions:
            if action_allowed_by_statement(statement, action):
                reasons.append(action)

    return bool(reasons), sorted(set(reasons))


def append_finding(
    findings,
    profile,
    account,
    category,
    severity,
    role,
    source,
    evidence,
    impact,
    confidence="MEDIUM",
):
    findings.append(
        {
            "Profile": profile,
            "AccountId": account,
            "Category": category,
            "Severity": severity,
            "Confidence": confidence,
            "Role": role,
            "Source": source,
            "Evidence": evidence,
            "Impact": impact,
        }
    )


def analyze_role_trust(context, role_dir, findings):
    details_path = role_dir / "role-details.json"
    data = load_json(details_path)
    role = (data or {}).get("Role", {})
    trust_policy = role.get("AssumeRolePolicyDocument") or {}
    role_name = role.get("RoleName", role_dir.name)
    target_account = context.account

    permission_statements, permission_sources = (
        collect_role_policy_statements(role_dir)
    )
    privileged, privilege_reasons = role_is_privileged(
        permission_statements
    )

    for statement in as_list(trust_policy.get("Statement")):
        if not isinstance(statement, dict):
            continue

        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        actions = as_list(statement.get("Action"))
        principal = statement.get("Principal", {})

        aws_principals = (
            as_list(principal.get("AWS"))
            if isinstance(principal, dict)
            else []
        )

        # 1. Cross-account trust
        for principal_arn in aws_principals:
            source_account = account_from_arn(principal_arn)

            if (
                source_account
                and target_account != "UNKNOWN"
                and source_account != target_account
            ):
                weak, reasons = conditions_weak_or_absent(statement)

                append_finding(
                    findings,
                    context.profile,
                    target_account,
                    "CROSS_ACCOUNT_TRUST",
                    "HIGH" if weak else "MEDIUM",
                    role_name,
                    str(details_path),
                    {
                        "Principal": principal_arn,
                        "Actions": actions,
                        "Weaknesses": reasons,
                    },
                    "An external AWS account principal is trusted to assume "
                    "this role. Weak conditions may permit unintended use.",
                    "HIGH" if weak else "MEDIUM",
                )

        # 5. Direct unconstrained assumption
        wildcard_principal = principal == "*" or (
            isinstance(principal, dict)
            and principal.get("AWS") == "*"
        )
        root_principal = any(
            str(value).endswith(":root")
            for value in aws_principals
        )

        assume_role_allowed = any(
            wildcard_match(action, "sts:AssumeRole")
            for action in actions
        )

        if assume_role_allowed and (
            wildcard_principal or root_principal
        ):
            weak, reasons = conditions_weak_or_absent(statement)

            if wildcard_principal or weak:
                append_finding(
                    findings,
                    context.profile,
                    target_account,
                    "DIRECT_UNCONSTRAINED_ROLE_ASSUMPTION",
                    "CRITICAL" if privileged else "HIGH",
                    role_name,
                    str(details_path),
                    {
                        "Principal": principal,
                        "Weaknesses": reasons,
                        "PrivilegedPermissions": privilege_reasons,
                        "PermissionSources": permission_sources,
                    },
                    "A broad principal may directly assume the role. "
                    "Impact increases when the role has privileged access.",
                    "HIGH",
                )

        # 2. OIDC / web identity abuse
        federated_principals = (
            as_list(principal.get("Federated"))
            if isinstance(principal, dict)
            else []
        )

        web_identity_allowed = any(
            wildcard_match(
                action,
                "sts:AssumeRoleWithWebIdentity",
            )
            for action in actions
        )

        if federated_principals and web_identity_allowed:
            weak, reasons = conditions_weak_or_absent(
                statement,
                oidc=True,
            )

            if weak:
                append_finding(
                    findings,
                    context.profile,
                    target_account,
                    "OIDC_TRUST_ABUSE",
                    "CRITICAL" if privileged else "HIGH",
                    role_name,
                    str(details_path),
                    {
                        "FederatedPrincipal": federated_principals,
                        "Weaknesses": reasons,
                        "PrivilegedPermissions": privilege_reasons,
                        "Condition": statement.get("Condition"),
                    },
                    "Weak OIDC subject or audience restrictions may allow "
                    "an unintended workload or repository to obtain the role.",
                    "HIGH",
                )

        # 4. Privileged Lambda or EC2 role
        service_principals = (
            as_list(principal.get("Service"))
            if isinstance(principal, dict)
            else []
        )
        compute_services = [
            value
            for value in service_principals
            if str(value).lower()
            in (
                "ec2.amazonaws.com",
                "lambda.amazonaws.com",
            )
        ]

        if compute_services and privileged:
            append_finding(
                findings,
                context.profile,
                target_account,
                "PRIVILEGED_COMPUTE_SERVICE_ROLE",
                "HIGH",
                role_name,
                str(details_path),
                {
                    "Services": compute_services,
                    "PrivilegedPermissions": privilege_reasons,
                    "InstanceProfiles": str(
                        role_dir / "instance-profiles.json"
                    ),
                },
                "New or compromised Lambda or EC2 compute using this role "
                "may automatically receive privileged AWS permissions.",
                "MEDIUM",
            )


def analyze_passrole_chains(context, role_dir, findings):
    statements, sources = collect_role_policy_statements(role_dir)

    if not statements:
        return

    role_name = role_dir.name

    pass_role = any(
        action_allowed_by_statement(statement, "iam:PassRole")
        for statement in statements
    )
    lambda_control = any(
        action_allowed_by_statement(
            statement,
            "lambda:CreateFunction",
        )
        or action_allowed_by_statement(
            statement,
            "lambda:UpdateFunctionConfiguration",
        )
        for statement in statements
    )
    ec2_control = any(
        action_allowed_by_statement(statement, "ec2:RunInstances")
        for statement in statements
    )

    policy_mutation_actions = (
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:PutRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
    )
    policy_mutation = any(
        action_allowed_by_statement(statement, action)
        for statement in statements
        for action in policy_mutation_actions
    )

    if pass_role and (lambda_control or ec2_control):
        append_finding(
            findings,
            context.profile,
            context.account,
            "PASSROLE_COMPUTE_PRIVILEGE_CHAIN",
            "CRITICAL",
            role_name,
            "; ".join(sorted(set(sources))),
            {
                "iam:PassRole": True,
                "lambda_control": lambda_control,
                "ec2_control": ec2_control,
            },
            "The identity may be able to pass a more privileged role to "
            "newly created or reconfigured Lambda or EC2 compute.",
            "MEDIUM",
        )

    if policy_mutation:
        append_finding(
            findings,
            context.profile,
            context.account,
            "IAM_POLICY_ATTACHMENT_OR_MUTATION",
            "CRITICAL",
            role_name,
            "; ".join(sorted(set(sources))),
            {"PolicyMutationCapability": True},
            "The identity policy includes IAM policy attachment or mutation "
            "actions that may enable privilege escalation.",
            "MEDIUM",
        )


def simulate_caller_capabilities(
    context,
    iam_client,
    caller_arn,
    profile_dir,
):
    # There is no AWS API action named sts:Attach. The relevant actions are
    # IAM policy attachment/mutation, iam:PassRole, sts:AssumeRole, and
    # compute creation.
    policy_source_arn = caller_arn

    assumed_role = re.match(
        r"^arn:([^:]+):sts::(\d{12}):assumed-role/(.+)/[^/]+$",
        caller_arn,
    )

    if assumed_role:
        partition, account, role_path = assumed_role.groups()
        policy_source_arn = (
            f"arn:{partition}:iam::{account}:role/{role_path}"
        )

    if not policy_source_arn.startswith("arn:"):
        context.record(
            "iam:SimulatePrincipalPolicy",
            caller_arn,
            "NOT_APPLICABLE",
            "Caller ARN unavailable",
        )
        return None

    return context.call(
        "iam:SimulatePrincipalPolicy",
        policy_source_arn,
        iam_client,
        "simulate_principal_policy",
        output=(
            profile_dir / "caller-capability-simulation.json"
        ),
        paginate_keys=["EvaluationResults"],
        PolicySourceArn=policy_source_arn,
        ActionNames=CALLER_CAPABILITY_ACTIONS,
    )


def analyze_profile_directory(context, profile_dir, utc_now, write_json):
    findings = []
    role_root = profile_dir / "roles"

    if role_root.exists():
        for role_dir in sorted(
            path for path in role_root.iterdir() if path.is_dir()
        ):
            try:
                analyze_role_trust(context, role_dir, findings)
                analyze_passrole_chains(context, role_dir, findings)
            except Exception as exception:
                context.errors += 1
                context.record(
                    "analyze_role",
                    role_dir.name,
                    "ERROR",
                    repr(exception),
                )

    simulation = load_json(
        profile_dir / "caller-capability-simulation.json"
    ) or {}

    for result in simulation.get("EvaluationResults", []):
        decision = str(result.get("EvalDecision", "")).lower()

        if decision == "allowed":
            append_finding(
                findings,
                context.profile,
                context.account,
                "CALLER_ALLOWED_SENSITIVE_ACTION",
                "CRITICAL",
                context.caller_arn,
                str(
                    profile_dir
                    / "caller-capability-simulation.json"
                ),
                {
                    "Action": result.get("EvalActionName", ""),
                    "Decision": result.get("EvalDecision"),
                    "MatchedStatements": result.get(
                        "MatchedStatements",
                        [],
                    ),
                },
                "The assessment principal is simulated as allowed to perform "
                "a sensitive IAM, STS, Lambda, or EC2 action.",
                "HIGH",
            )

    output_json = profile_dir / "security-abuse-findings.json"
    write_json(
        output_json,
        {
            "Profile": context.profile,
            "AccountId": context.account,
            "Caller": context.caller_arn,
            "GeneratedAt": utc_now(),
            "ImportantLimitations": [
                "Static findings are potential paths, not proof of exploitability.",
                "Simulation may not fully reflect SCPs, resource policies, session policies, permissions boundaries, or runtime conditions.",
                "There is no AWS API action named sts:Attach; IAM attachment/mutation and iam:PassRole are evaluated instead.",
            ],
            "Findings": findings,
        },
    )

    output_csv = profile_dir / "security-abuse-findings.csv"
    fields = [
        "Profile",
        "AccountId",
        "Category",
        "Severity",
        "Confidence",
        "Role",
        "Source",
        "Evidence",
        "Impact",
    ]

    with output_csv.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=fields,
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()

        for finding in findings:
            row = dict(finding)
            row["Evidence"] = json.dumps(
                row["Evidence"],
                default=str,
                sort_keys=True,
            )
            writer.writerow(row)

    context.record(
        "local:AnalyzeEnumeratedPolicies",
        context.profile,
        "SUCCESS",
        f"{len(findings)} potential finding(s)",
    )

    return findings
