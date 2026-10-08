#!/usr/bin/env python3
"""
Analyze output produced by enumerate_aws_iam.py.

Static, read-only analysis for:
  1. Cross-account role trust and abuse paths
  2. OIDC trust weaknesses
  3. Whether the enumerating caller appears able to call sts:AssumeRole
  4. iam:PassRole + Lambda/EC2 privilege paths
  5. Direct/unconstrained role assumption and IAM privilege escalation

The script does NOT call AWS APIs and does NOT attempt role assumption.
It only reads JSON evidence and creates JSON reports.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VERSION = "1.0.0"

PRIVILEGED_ACTIONS = {
    "*", "iam:*", "organizations:*", "account:*",
    "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachrolepolicy", "iam:attachuserpolicy", "iam:attachgrouppolicy",
    "iam:putrolepolicy", "iam:putuserpolicy", "iam:putgrouppolicy",
    "iam:updateassumerolepolicy", "iam:createrole", "iam:createuser",
    "iam:addusertogroup", "iam:createaccesskey", "iam:updateloginprofile",
    "iam:passrole", "sts:assumerole",
}
LAMBDA_CREATE_ACTIONS = {"lambda:createfunction"}
LAMBDA_CONTROL_ACTIONS = {
    "lambda:updatefunctioncode", "lambda:updatefunctionconfiguration",
    "lambda:invokefunction", "lambda:addpermission",
    "lambda:createeventsourcemapping",
}
EC2_CREATE_ACTIONS = {"ec2:runinstances"}
EC2_PROFILE_ACTIONS = {
    "ec2:associateiaminstanceprofile", "ec2:replaceiaminstanceprofileassociation",
    "iam:createinstanceprofile", "iam:addroletoinstanceprofile",
    "iam:removerolefrominstanceprofile",
}
ASSUME_ACTIONS = {"sts:assumerole"}
OIDC_ACTIONS = {"sts:assumerolewithwebidentity"}


def values(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def lower_values(v: Any) -> List[str]:
    return [str(x).lower() for x in values(v)]


def safe_load(path: Path) -> Optional[Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    tmp.replace(path)


def account_from_arn(arn: str) -> Optional[str]:
    m = re.match(r"^arn:[^:]+:[^:]*:[^:]*:(\d{12}):", arn or "")
    return m.group(1) if m else None


def role_name_from_arn(arn: str) -> Optional[str]:
    m = re.match(r"^arn:[^:]+:iam::\d{12}:role/(.+)$", arn or "")
    return m.group(1) if m else None


def action_matches(grant: str, wanted: str) -> bool:
    return fnmatch.fnmatchcase(wanted.lower(), grant.lower())


def resource_matches(pattern: str, resource: str) -> bool:
    return fnmatch.fnmatchcase(resource, pattern)


def has_action(actions: Iterable[str], wanted: str) -> bool:
    return any(action_matches(a, wanted) for a in actions)


def severity_rank(s: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}.get(s, 0)


def conditions_flat(condition: Any) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not isinstance(condition, dict):
        return out
    for operator, pairs in condition.items():
        if not isinstance(pairs, dict):
            continue
        for key, val in pairs.items():
            out[f"{operator}:{key}".lower()] = [str(x) for x in values(val)]
    return out


def condition_values(condition: Any, suffix: str) -> List[str]:
    suffix = suffix.lower()
    found: List[str] = []
    for key, vals in conditions_flat(condition).items():
        cond_key = key.split(":", 1)[-1]
        if cond_key.endswith(suffix):
            found.extend(vals)
    return found


def normalize_policy_document(doc: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(doc, dict):
        return None
    if isinstance(doc.get("PolicyVersion"), dict):
        doc = doc["PolicyVersion"].get("Document")
    elif isinstance(doc.get("Policy"), dict) and "Document" in doc["Policy"]:
        doc = doc["Policy"].get("Document")
    if isinstance(doc, dict) and "Document" in doc and isinstance(doc["Document"], dict):
        doc = doc["Document"]
    return doc if isinstance(doc, dict) and "Statement" in doc else None


@dataclass
class StatementRef:
    file: str
    index: int
    effect: str
    actions: List[str]
    not_actions: List[str]
    resources: List[str]
    not_resources: List[str]
    principals: Dict[str, List[str]]
    condition: Any
    sid: str = ""

    def evidence(self) -> Dict[str, Any]:
        return {
            "file": self.file, "statement_index": self.index, "sid": self.sid,
            "effect": self.effect, "actions": self.actions,
            "not_actions": self.not_actions, "resources": self.resources,
            "not_resources": self.not_resources, "principals": self.principals,
            "condition": self.condition,
        }


def statements_from_doc(doc: Dict[str, Any], source: str) -> List[StatementRef]:
    result: List[StatementRef] = []
    for i, st in enumerate(values(doc.get("Statement"))):
        if not isinstance(st, dict):
            continue
        principal: Dict[str, List[str]] = {}
        p = st.get("Principal")
        if isinstance(p, dict):
            principal = {str(k): [str(x) for x in values(v)] for k, v in p.items()}
        elif p is not None:
            principal = {"Any": [str(x) for x in values(p)]}
        result.append(StatementRef(
            file=source, index=i, effect=str(st.get("Effect", "")),
            actions=lower_values(st.get("Action")),
            not_actions=lower_values(st.get("NotAction")),
            resources=[str(x) for x in values(st.get("Resource", "*"))],
            not_resources=[str(x) for x in values(st.get("NotResource"))],
            principals=principal, condition=st.get("Condition", {}),
            sid=str(st.get("Sid", "")),
        ))
    return result


@dataclass
class Role:
    name: str
    arn: str
    account: str
    trust: List[StatementRef] = field(default_factory=list)
    permissions: List[StatementRef] = field(default_factory=list)
    boundary_arn: Optional[str] = None
    source_dir: str = ""

    def trusts_service(self, service: str) -> bool:
        service = service.lower()
        return any(
            s.effect.lower() == "allow" and any(action_matches(a, "sts:AssumeRole") for a in s.actions)
            and any(x.lower() == service for x in s.principals.get("Service", []))
            for s in self.trust
        )


class Analyzer:
    def __init__(self, root: Path, out: Path):
        self.root = root.resolve()
        self.out = out.resolve()
        self.all_findings: List[Dict[str, Any]] = []
        self.finding_counter = 0

    def finding(self, profile: str, account: str, category: str, severity: str,
                title: str, assessment: str, evidence: List[Dict[str, Any]],
                target_role: str = "", source_principal: str = "",
                confidence: str = "Potential", missing: Optional[List[str]] = None,
                blocking: Optional[List[str]] = None, remediation: str = "") -> Dict[str, Any]:
        self.finding_counter += 1
        prefix = {
            "CrossAccountAccess": "XACCOUNT", "OIDC": "OIDC",
            "AssumeRole": "ASSUME", "PassRoleCompute": "PASSROLE",
            "DirectPrivilege": "PRIV", "EvidenceGap": "GAP",
        }.get(category, "GEN")
        return {
            "finding_id": f"IAM-{prefix}-{self.finding_counter:04d}",
            "profile": profile, "account_id": account, "category": category,
            "severity": severity, "confidence": confidence, "title": title,
            "source_principal": source_principal, "target_role": target_role,
            "assessment": assessment, "evidence": evidence,
            "missing_requirements": missing or [], "blocking_conditions": blocking or [],
            "remediation": remediation,
        }

    def discover_profiles(self) -> List[Path]:
        profiles = []
        for p in sorted(self.root.iterdir() if self.root.exists() else []):
            if p.is_dir() and (p / "caller-identity.json").exists():
                profiles.append(p)
        return profiles

    def parse_role(self, role_dir: Path) -> Optional[Role]:
        detail_path = role_dir / "role-details.json"
        raw = safe_load(detail_path)
        if not isinstance(raw, dict):
            return None
        data = raw.get("Role", raw)
        if not isinstance(data, dict):
            return None
        arn = str(data.get("Arn", ""))
        name = str(data.get("RoleName", role_dir.name))
        account = account_from_arn(arn) or "UNKNOWN"
        trust_doc = data.get("AssumeRolePolicyDocument")
        trust = statements_from_doc(trust_doc, str(detail_path)) if isinstance(trust_doc, dict) else []
        role = Role(name=name, arn=arn, account=account, trust=trust,
                    boundary_arn=(data.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                    source_dir=str(role_dir))
        candidates = []
        for sub in ("attached-managed-policies", "inline-policies"):
            d = role_dir / sub
            if d.exists():
                candidates.extend(d.rglob("*.json"))
        for path in candidates:
            doc = normalize_policy_document(safe_load(path))
            if doc:
                role.permissions.extend(statements_from_doc(doc, str(path)))
        return role

    def collect_roles(self, profile_dir: Path) -> Dict[str, Role]:
        roles: Dict[str, Role] = {}
        role_root = profile_dir / "roles"
        if role_root.exists():
            for d in sorted(role_root.iterdir()):
                if d.is_dir():
                    role = self.parse_role(d)
                    if role:
                        roles[role.arn or role.name] = role
        return roles

    def caller_policy_statements(self, profile_dir: Path, caller_arn: str) -> Tuple[List[StatementRef], List[str]]:
        """Best-effort extraction from GetAccountAuthorizationDetails."""
        path = profile_dir / "account-authorization-details.json"
        raw = safe_load(path)
        if not isinstance(raw, dict):
            return [], [f"Missing or unreadable {path}"]
        out: List[StatementRef] = []
        gaps: List[str] = []
        policy_map: Dict[str, Dict[str, Any]] = {}
        for p in values(raw.get("Policies")):
            if not isinstance(p, dict):
                continue
            arn = str(p.get("Arn", ""))
            default = str(p.get("DefaultVersionId", ""))
            for ver in values(p.get("PolicyVersionList")):
                if isinstance(ver, dict) and str(ver.get("VersionId")) == default and isinstance(ver.get("Document"), dict):
                    policy_map[arn] = ver["Document"]

        if ":user/" in caller_arn:
            name = caller_arn.split(":user/", 1)[1]
            users = [u for u in values(raw.get("UserDetailList")) if isinstance(u, dict) and u.get("UserName") == name]
            if not users:
                gaps.append("Caller user not found in account authorization details")
            for u in users:
                for pol in values(u.get("UserPolicyList")):
                    if isinstance(pol, dict) and isinstance(pol.get("PolicyDocument"), dict):
                        out.extend(statements_from_doc(pol["PolicyDocument"], str(path)))
                for arn in values(u.get("AttachedManagedPolicies")):
                    parn = arn.get("PolicyArn") if isinstance(arn, dict) else None
                    if parn in policy_map:
                        out.extend(statements_from_doc(policy_map[parn], str(path)))
                groups = set(values(u.get("GroupList")))
                for g in values(raw.get("GroupDetailList")):
                    if not isinstance(g, dict) or g.get("GroupName") not in groups:
                        continue
                    for pol in values(g.get("GroupPolicyList")):
                        if isinstance(pol, dict) and isinstance(pol.get("PolicyDocument"), dict):
                            out.extend(statements_from_doc(pol["PolicyDocument"], str(path)))
                    for arn in values(g.get("AttachedManagedPolicies")):
                        parn = arn.get("PolicyArn") if isinstance(arn, dict) else None
                        if parn in policy_map:
                            out.extend(statements_from_doc(policy_map[parn], str(path)))
        elif ":assumed-role/" in caller_arn:
            role_session = caller_arn.split(":assumed-role/", 1)[1]
            role_name = role_session.split("/", 1)[0]
            roles = [r for r in values(raw.get("RoleDetailList")) if isinstance(r, dict) and r.get("RoleName") == role_name]
            if not roles:
                gaps.append("Caller role not found in account authorization details")
            for r in roles:
                for pol in values(r.get("RolePolicyList")):
                    if isinstance(pol, dict) and isinstance(pol.get("PolicyDocument"), dict):
                        out.extend(statements_from_doc(pol["PolicyDocument"], str(path)))
                for arn in values(r.get("AttachedManagedPolicies")):
                    parn = arn.get("PolicyArn") if isinstance(arn, dict) else None
                    if parn in policy_map:
                        out.extend(statements_from_doc(policy_map[parn], str(path)))
                if r.get("PermissionsBoundary"):
                    gaps.append("Caller has a permissions boundary; static allow results require boundary evaluation")
            gaps.append("Session policies and role-session restrictions are not present in IAM authorization details")
        else:
            gaps.append("Caller ARN is not an IAM user or assumed role recognized by this analyzer")
        return out, gaps

    def allow_refs(self, statements: List[StatementRef], action: str, resource: str = "*") -> List[StatementRef]:
        refs = []
        for s in statements:
            if s.effect.lower() != "allow" or s.not_actions:
                continue
            if has_action(s.actions, action) and any(resource_matches(r, resource) for r in s.resources):
                refs.append(s)
        return refs

    def deny_refs(self, statements: List[StatementRef], action: str, resource: str = "*") -> List[StatementRef]:
        refs = []
        for s in statements:
            if s.effect.lower() != "deny":
                continue
            action_hit = has_action(s.actions, action) if s.actions else action not in s.not_actions
            resource_hit = any(resource_matches(r, resource) for r in s.resources) if s.resources else True
            if action_hit and resource_hit:
                refs.append(s)
        return refs

    def trust_allows_caller(self, role: Role, caller_arn: str, caller_account: str) -> Tuple[List[StatementRef], List[str]]:
        matched, caveats = [], []
        for s in role.trust:
            if s.effect.lower() != "allow" or not has_action(s.actions, "sts:AssumeRole"):
                continue
            aws_principals = s.principals.get("AWS", []) + s.principals.get("Any", [])
            hit = False
            for p in aws_principals:
                if p == "*" or p == caller_arn:
                    hit = True
                elif p == f"arn:aws:iam::{caller_account}:root":
                    hit = True
                elif p.endswith(":root") and account_from_arn(p) == caller_account:
                    hit = True
            if hit:
                matched.append(s)
                if s.condition:
                    caveats.append(f"Trust statement {s.index} contains conditions requiring runtime validation")
        return matched, caveats

    def role_privileged(self, role: Role) -> Tuple[bool, List[StatementRef]]:
        refs = []
        for s in role.permissions:
            if s.effect.lower() != "allow":
                continue
            if any(any(action_matches(a, wanted) for wanted in PRIVILEGED_ACTIONS) for a in s.actions):
                refs.append(s)
            elif has_action(s.actions, "iam:PassRole") and "*" in s.resources:
                refs.append(s)
        return bool(refs), refs

    def analyze_profile(self, profile_dir: Path) -> Dict[str, Any]:
        profile = profile_dir.name
        identity = safe_load(profile_dir / "caller-identity.json") or {}
        account = str(identity.get("Account", "UNKNOWN"))
        caller = str(identity.get("Arn", ""))
        caller_account = account_from_arn(caller) or account
        roles = self.collect_roles(profile_dir)
        caller_policies, gaps = self.caller_policy_statements(profile_dir, caller)
        findings: List[Dict[str, Any]] = []

        for gap in gaps:
            findings.append(self.finding(profile, account, "EvidenceGap", "Informational",
                "Static-analysis evidence gap", gap, [], source_principal=caller,
                confidence="InsufficientEvidence"))

        # Trust and OIDC analysis.
        for role in roles.values():
            privileged, privilege_refs = self.role_privileged(role)
            for st in role.trust:
                if st.effect.lower() != "allow":
                    continue
                aws_principals = st.principals.get("AWS", []) + st.principals.get("Any", [])
                if has_action(st.actions, "sts:AssumeRole"):
                    for principal in aws_principals:
                        p_account = account_from_arn(principal)
                        external = principal == "*" or (p_account and p_account != role.account)
                        if external:
                            cond = conditions_flat(st.condition)
                            constrained = any(k.endswith("sts:externalid") or k.endswith("aws:principalorgid") or k.endswith("aws:principalarn") for k in cond)
                            sev = "Critical" if privileged and principal == "*" else "High" if privileged or not constrained else "Medium"
                            findings.append(self.finding(profile, account, "CrossAccountAccess", sev,
                                "Cross-account or public role trust detected",
                                f"Role trust permits {principal}; {'a restrictive cross-account condition was observed' if constrained else 'no ExternalId, PrincipalOrgID, or PrincipalArn restriction was observed in this statement'}.",
                                [st.evidence()] + [x.evidence() for x in privilege_refs],
                                target_role=role.arn, source_principal=principal,
                                confidence="PolicyConfirmed" if not st.condition else "ConditionDependent",
                                remediation="Restrict the trusted principal and add appropriate organization, principal, source, or external-ID conditions."))
                    if any(p == "*" for p in aws_principals):
                        findings.append(self.finding(profile, account, "DirectPrivilege", "Critical" if privileged else "High",
                            "Unconstrained role trust",
                            "The role trust permits any AWS principal to request sts:AssumeRole.",
                            [st.evidence()] + [x.evidence() for x in privilege_refs], target_role=role.arn,
                            confidence="PolicyConfirmed" if not st.condition else "ConditionDependent",
                            remediation="Replace wildcard trust with explicit principals and restrictive conditions."))

                federated = st.principals.get("Federated", [])
                if federated and has_action(st.actions, "sts:AssumeRoleWithWebIdentity"):
                    aud = condition_values(st.condition, ":aud")
                    sub = condition_values(st.condition, ":sub")
                    issues = []
                    if not aud:
                        issues.append("missing audience restriction")
                    if not sub:
                        issues.append("missing subject restriction")
                    elif any("*" in x or "?" in x for x in sub):
                        issues.append("wildcard subject restriction")
                    if not issues:
                        continue
                    sev = "Critical" if privileged and (not sub or any("*" in x for x in sub)) else "High" if privileged else "Medium"
                    findings.append(self.finding(profile, account, "OIDC", sev,
                        "Potentially broad OIDC role trust",
                        "The OIDC trust has " + ", ".join(issues) + ".",
                        [st.evidence()] + [x.evidence() for x in privilege_refs], target_role=role.arn,
                        source_principal=", ".join(federated), confidence="PolicyConfirmed",
                        remediation="Constrain OIDC audience and subject claims to the intended workload, repository, branch, tag, or environment."))

            # Caller -> AssumeRole static path.
            trust_refs, caveats = self.trust_allows_caller(role, caller, caller_account)
            allow = self.allow_refs(caller_policies, "sts:AssumeRole", role.arn)
            deny = self.deny_refs(caller_policies, "sts:AssumeRole", role.arn)
            if trust_refs:
                if allow and not deny:
                    findings.append(self.finding(profile, account, "AssumeRole", "Critical" if privileged else "High",
                        "Caller appears statically authorized to assume role",
                        "Both an identity-policy allow and a matching role-trust allow were found. This is a static conclusion and does not evaluate SCPs, session policies, or runtime conditions.",
                        [x.evidence() for x in allow + trust_refs + privilege_refs], target_role=role.arn,
                        source_principal=caller, confidence="ConditionDependent" if caveats else "StaticallyAllowed",
                        blocking=caveats, remediation="Restrict sts:AssumeRole resources and narrow the target role trust."))
                elif deny:
                    findings.append(self.finding(profile, account, "AssumeRole", "Informational",
                        "Caller assumption path blocked by explicit identity-policy deny",
                        "A matching trust was found, but an explicit identity-policy deny was also found.",
                        [x.evidence() for x in trust_refs + deny], target_role=role.arn,
                        source_principal=caller, confidence="StaticallyDenied"))
                else:
                    findings.append(self.finding(profile, account, "AssumeRole", "Low",
                        "Target role trusts caller but caller-side allow was not found",
                        "The target trust matches the caller, but the available caller policies do not show a matching sts:AssumeRole allow.",
                        [x.evidence() for x in trust_refs], target_role=role.arn,
                        source_principal=caller, confidence="InsufficientEvidence",
                        missing=["Matching caller identity-policy permission, or complete effective-permissions evidence"]))

        # PassRole + compute creation/control analysis for caller.
        passrole = [s for s in caller_policies if s.effect.lower() == "allow" and has_action(s.actions, "iam:PassRole")]
        lambda_create = self.allow_refs(caller_policies, "lambda:CreateFunction")
        ec2_create = self.allow_refs(caller_policies, "ec2:RunInstances")
        lambda_control = [s for s in caller_policies if s.effect.lower() == "allow" and any(has_action(s.actions, a) for a in LAMBDA_CONTROL_ACTIONS)]
        ec2_control = [s for s in caller_policies if s.effect.lower() == "allow" and any(has_action(s.actions, a) for a in EC2_PROFILE_ACTIONS)]
        for role in roles.values():
            privileged, privilege_refs = self.role_privileged(role)
            matching_pass = [s for s in passrole if any(resource_matches(r, role.arn) for r in s.resources)]
            if not matching_pass:
                continue
            passed_to = []
            for s in matching_pass:
                passed_to.extend(condition_values(s.condition, "iam:passedtoservice"))
            lambda_ok = role.trusts_service("lambda.amazonaws.com") and lambda_create and (not passed_to or "lambda.amazonaws.com" in [x.lower() for x in passed_to])
            ec2_ok = role.trusts_service("ec2.amazonaws.com") and ec2_create and (not passed_to or "ec2.amazonaws.com" in [x.lower() for x in passed_to])
            if lambda_ok:
                findings.append(self.finding(profile, account, "PassRoleCompute", "Critical" if privileged else "High",
                    "Caller can potentially create Lambda with a passable role",
                    "The caller has matching iam:PassRole and lambda:CreateFunction permissions, and the role trusts Lambda.",
                    [x.evidence() for x in matching_pass + lambda_create + lambda_control + privilege_refs],
                    target_role=role.arn, source_principal=caller, confidence="StaticallyAllowed",
                    remediation="Restrict iam:PassRole to approved roles and scope Lambda creation and code-control permissions."))
            if ec2_ok:
                findings.append(self.finding(profile, account, "PassRoleCompute", "Critical" if privileged else "High",
                    "Caller can potentially launch EC2 with a passable role",
                    "The caller has matching iam:PassRole and ec2:RunInstances permissions, and the role trusts EC2.",
                    [x.evidence() for x in matching_pass + ec2_create + ec2_control + privilege_refs],
                    target_role=role.arn, source_principal=caller, confidence="StaticallyAllowed",
                    remediation="Restrict iam:PassRole, instance-profile operations, and EC2 launch permissions to approved resources."))

        # Broad IAM privilege statements for all roles.
        for role in roles.values():
            for st in role.permissions:
                if st.effect.lower() != "allow":
                    continue
                matched = [p for p in PRIVILEGED_ACTIONS if has_action(st.actions, p)]
                if not matched:
                    continue
                broad_resource = "*" in st.resources or not st.resources
                sev = "Critical" if "*" in st.actions or ("iam:*" in st.actions and broad_resource) else "High"
                findings.append(self.finding(profile, account, "DirectPrivilege", sev,
                    "Role contains direct IAM or privilege-escalation capability",
                    "Matched high-impact actions: " + ", ".join(sorted(matched)) + ".",
                    [st.evidence()], target_role=role.arn, confidence="PolicyConfirmed",
                    remediation="Replace broad IAM permissions with task-specific actions and resource constraints."))

        findings.sort(key=lambda x: (-severity_rank(x["severity"]), x["category"], x["finding_id"]))
        self.all_findings.extend(findings)
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        report = {
            "tool": "analyze_aws_iam.py", "version": VERSION,
            "profile": profile, "account_id": account, "caller_arn": caller,
            "roles_analyzed": len(roles), "caller_policy_statements": len(caller_policies),
            "finding_counts_by_severity": counts, "findings": findings,
            "limitations": [
                "Static analysis does not evaluate SCPs, RCPs, session policies, VPC endpoint policies, or runtime context.",
                "NotAction and NotResource are retained as evidence but only conservatively evaluated.",
                "Resource policies outside IAM are not analyzed.",
                "No AWS API calls or sts:AssumeRole probes are performed.",
            ],
        }
        write_json(self.out / profile / "analysis-summary.json", report)
        for category, filename in {
            "CrossAccountAccess": "cross-account-findings.json",
            "OIDC": "oidc-findings.json", "AssumeRole": "assume-role-paths.json",
            "PassRoleCompute": "passrole-compute-paths.json",
            "DirectPrivilege": "direct-privilege-paths.json",
            "EvidenceGap": "evidence-gaps.json",
        }.items():
            write_json(self.out / profile / filename, [f for f in findings if f["category"] == category])
        return report

    def run(self) -> int:
        profiles = self.discover_profiles()
        if not profiles:
            print(f"[ERROR] No profile directories containing caller-identity.json under: {self.root}", file=sys.stderr)
            return 2
        reports = []
        for p in profiles:
            print(f"[*] Analyzing profile: {p.name}")
            reports.append(self.analyze_profile(p))
        self.all_findings.sort(key=lambda x: (-severity_rank(x["severity"]), x["profile"], x["finding_id"]))
        write_json(self.out / "consolidated-findings.json", self.all_findings)
        write_json(self.out / "profile-analysis-summary.json", [{
            "profile": r["profile"], "account_id": r["account_id"],
            "caller_arn": r["caller_arn"], "roles_analyzed": r["roles_analyzed"],
            "caller_policy_statements": r["caller_policy_statements"],
            "finding_counts_by_severity": r["finding_counts_by_severity"],
        } for r in reports])
        print(f"[+] Profiles analyzed: {len(reports)}")
        print(f"[+] Findings written: {len(self.all_findings)}")
        print(f"[+] Output directory: {self.out}")
        return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Static analyzer for enumerate_aws_iam.py output")
    p.add_argument("input", type=Path, help="Root directory created by enumerate_aws_iam.py")
    p.add_argument("-o", "--output", type=Path, default=Path("aws-iam-analysis"), help="Analysis output directory")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.input.resolve() == args.output.resolve():
        print("[ERROR] Input and output directories must be different.", file=sys.stderr)
        return 2
    return Analyzer(args.input, args.output).run()


if __name__ == "__main__":
    raise SystemExit(main())
