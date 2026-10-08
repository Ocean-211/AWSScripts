#!/usr/bin/env python3
"""
enumerate_aws_iam.py

Fault-tolerant enumeration of IAM roles, trust policies, permissions
boundaries, attached managed policies, inline policies and customer-managed
policies across every profile configured in the local AWS CLI.

Design goals
  - A denied / failed API call never aborts the role, profile, or run
  - JSON is written only when the call succeeds (no empty/corrupt files)
  - Each call is classified: SUCCESS / EMPTY / ACCESS_DENIED /
    CREDENTIAL_FAILURE / THROTTLED / NOT_FOUND / ERROR
  - Machine-readable status log for audit evidence

Usage
  python3 enumerate_aws_iam.py
  python3 enumerate_aws_iam.py -o iam-results
  python3 enumerate_aws_iam.py -o iam-results -p prod dr audit
  python3 enumerate_aws_iam.py --skip-auth-details

Requirements
  Python 3.8+, boto3 / botocore
"""

import argparse
import csv
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        NoCredentialsError,
        PartialCredentialsError,
        ProfileNotFound,
    )
except ImportError:
    sys.exit("[FATAL] boto3 is required: pip install boto3")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "standard"},
    read_timeout=30,
    connect_timeout=10,
)

DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "UnauthorizedAccess",
}
CREDENTIAL_CODES = {
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "UnrecognizedClientException",
    "InvalidAccessKeyId",
}
THROTTLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
}
NOT_FOUND_CODES = {"NoSuchEntity", "NoSuchEntityException"}

RUN_TIMESTAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

log = logging.getLogger("iam-enum")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize(name: str) -> str:
    """Filesystem-safe name."""
    return re.sub(r"[\\/:*?\"<>|\s]", "_", str(name)) or "_unnamed_"


def write_json(path: Path, data) -> None:
    """Atomic JSON write: temp file first, then rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    tmp.replace(path)


def strip_metadata(response: dict) -> dict:
    response = dict(response)
    response.pop("ResponseMetadata", None)
    return response


def classify_exception(exc: Exception):
    """Return (status, detail) for an exception."""
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        detail = f"{code}: {message}"
        if code in DENIED_CODES or "not authorized" in message.lower():
            return "ACCESS_DENIED", detail
        if code in CREDENTIAL_CODES:
            return "CREDENTIAL_FAILURE", detail
        if code in THROTTLE_CODES:
            return "THROTTLED", detail
        if code in NOT_FOUND_CODES:
            return "NOT_FOUND", detail
        return "ERROR", detail

    if isinstance(exc, (NoCredentialsError, PartialCredentialsError, ProfileNotFound)):
        return "CREDENTIAL_FAILURE", f"{type(exc).__name__}: {exc}"

    name = type(exc).__name__
    if any(k in name for k in ("Token", "SSO", "Credential")):
        return "CREDENTIAL_FAILURE", f"{name}: {exc}"

    return "ERROR", f"{name}: {exc}"


# --------------------------------------------------------------------------
# Status tracking
# --------------------------------------------------------------------------

class StatusLog:
    """Run-wide CSV log: one row per API operation."""

    HEADER = ["Timestamp", "Profile", "AccountId", "Operation",
              "Target", "Status", "Detail"]

    def __init__(self, path: Path):
        self.path = path
        new_file = not path.exists()
        self._fh = path.open("a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._fh, quoting=csv.QUOTE_ALL)
        if new_file:
            self._writer.writerow(self.HEADER)

    def record(self, profile, account, operation, target, status, detail=""):
        detail = " ".join(str(detail).split())[:500]
        self._writer.writerow([RUN_TIMESTAMP, profile, account, operation,
                               target, status, detail])
        self._fh.flush()

    def count(self, status: str) -> int:
        self._fh.flush()
        with self.path.open(newline="", encoding="utf-8") as fh:
            return sum(1 for row in csv.DictReader(fh)
                       if row.get("Status") == status
                       and row.get("Timestamp") == RUN_TIMESTAMP)

    def close(self):
        self._fh.close()


class ProfileContext:
    """Per-profile counters plus a fault-tolerant boto3 call wrapper."""

    def __init__(self, profile: str, status_log: StatusLog):
        self.profile = profile
        self.account = "UNKNOWN"
        self.caller_arn = ""
        self.status_log = status_log
        self.success = 0
        self.denied = 0
        self.errors = 0

    def record(self, operation, target, status, detail=""):
        self.status_log.record(self.profile, self.account,
                               operation, target, status, detail)

    def call(self, operation, target, client, method,
             output=None, paginate_keys=None, **kwargs):
        """
        Execute a boto3 call without ever raising.

        paginate_keys : list of response keys to merge across pages
                        (uses the client paginator when provided)
        output        : Path - JSON is written only on success

        Returns the response dict on success, otherwise None.
        """
        try:
            if paginate_keys:
                paginator = client.get_paginator(method)
                merged = {k: [] for k in paginate_keys}
                for page in paginator.paginate(**kwargs):
                    for key in paginate_keys:
                        merged[key].extend(page.get(key, []))
                response = merged
            else:
                response = strip_metadata(getattr(client, method)(**kwargs))

        except Exception as exc:  # noqa: BLE001 - deliberate catch-all
            status, detail = classify_exception(exc)
            if status == "ACCESS_DENIED":
                self.denied += 1
            elif status != "NOT_FOUND":
                self.errors += 1
            log.warning("SKIP %s :: %s :: %s", status, operation, target)
            self.record(operation, target, status, detail)
            return None

        if output is not None:
            try:
                write_json(output, response)
            except (OSError, TypeError, ValueError) as exc:
                self.errors += 1
                log.warning("WRITE FAILURE :: %s :: %s", operation, exc)
                self.record(operation, target, "WRITE_ERROR", str(exc))
                return None

        self.success += 1
        self.record(operation, target, "SUCCESS")
        return response


# --------------------------------------------------------------------------
# Enumeration: roles
# --------------------------------------------------------------------------

def fetch_managed_policy(ctx, iam, policy_arn, meta_path, doc_path):
    """Policy metadata + default-version document. Returns metadata or None."""
    meta = ctx.call("iam:GetPolicy", policy_arn, iam, "get_policy",
                    output=meta_path, PolicyArn=policy_arn)
    if not meta:
        return None

    version_id = meta.get("Policy", {}).get("DefaultVersionId")
    if version_id:
        ctx.call("iam:GetPolicyVersion", f"{policy_arn} ({version_id})",
                 iam, "get_policy_version", output=doc_path,
                 PolicyArn=policy_arn, VersionId=version_id)
    return meta


def process_role(ctx, iam, role_name, role_root: Path):
    role_dir = role_root / sanitize(role_name)
    role_dir.mkdir(parents=True, exist_ok=True)

    # Trust policy, permissions boundary, tags, session duration
    ctx.call("iam:GetRole", role_name, iam, "get_role",
             output=role_dir / "role-details.json", RoleName=role_name)

    # ---- Attached managed policies -------------------------------------
    attached = ctx.call(
        "iam:ListAttachedRolePolicies", role_name, iam,
        "list_attached_role_policies",
        output=role_dir / "attached-managed-policies.json",
        paginate_keys=["AttachedPolicies"], RoleName=role_name)

    if attached is not None:
        policies = attached.get("AttachedPolicies", [])
        if not policies:
            ctx.record("iam:ListAttachedRolePolicies", role_name,
                       "EMPTY", "No managed policies attached")
        mp_dir = role_dir / "attached-managed-policies"
        for pol in policies:
            arn = pol.get("PolicyArn")
            if not arn:
                continue
            safe = sanitize(arn.rsplit("/", 1)[-1])
            fetch_managed_policy(ctx, iam, arn,
                                 mp_dir / f"{safe}-metadata.json",
                                 mp_dir / f"{safe}-permissions.json")

    # ---- Inline policies ---------------------------------------------------
    inline = ctx.call(
        "iam:ListRolePolicies", role_name, iam, "list_role_policies",
        output=role_dir / "inline-policies.json",
        paginate_keys=["PolicyNames"], RoleName=role_name)

    if inline is not None:
        names = inline.get("PolicyNames", [])
        if not names:
            ctx.record("iam:ListRolePolicies", role_name,
                       "EMPTY", "No inline policies present")
        ip_dir = role_dir / "inline-policies"
        for name in names:
            ctx.call("iam:GetRolePolicy", f"{role_name}/{name}", iam,
                     "get_role_policy",
                     output=ip_dir / f"{sanitize(name)}-permissions.json",
                     RoleName=role_name, PolicyName=name)

    # ---- Instance profiles -------------------------------------------------
    ctx.call("iam:ListInstanceProfilesForRole", role_name, iam,
             "list_instance_profiles_for_role",
             output=role_dir / "instance-profiles.json",
             paginate_keys=["InstanceProfiles"], RoleName=role_name)


# --------------------------------------------------------------------------
# Enumeration: customer-managed policies (attached and unattached)
# --------------------------------------------------------------------------

def process_customer_managed_policies(ctx, iam, profile_dir: Path):
    listing = ctx.call(
        "iam:ListPolicies(scope=Local)", ctx.profile, iam, "list_policies",
        output=profile_dir / "customer-managed-policies-list.json",
        paginate_keys=["Policies"], Scope="Local")

    if listing is None:
        return

    policies = listing.get("Policies", [])
    if not policies:
        ctx.record("iam:ListPolicies(scope=Local)", ctx.profile,
                   "EMPTY", "No customer-managed policies")
        return

    base = profile_dir / "customer-managed-policies"
    for pol in policies:
        arn = pol.get("Arn")
        if not arn:
            continue
        pdir = base / sanitize(pol.get("PolicyName") or arn.rsplit("/", 1)[-1])

        meta = fetch_managed_policy(ctx, iam, arn,
                                    pdir / "metadata.json",
                                    pdir / "default-version-permissions.json")
        if meta is None:
            continue

        ctx.call("iam:ListPolicyVersions", arn, iam, "list_policy_versions",
                 output=pdir / "all-versions.json",
                 paginate_keys=["Versions"], PolicyArn=arn)

        ctx.call("iam:ListEntitiesForPolicy", arn, iam,
                 "list_entities_for_policy",
                 output=pdir / "attached-entities.json",
                 paginate_keys=["PolicyGroups", "PolicyUsers", "PolicyRoles"],
                 PolicyArn=arn)


# --------------------------------------------------------------------------
# Summaries
# --------------------------------------------------------------------------

def load_json(path: Path):
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def build_summaries(profile_dir: Path, roles: list, role_root: Path):
    # roles-summary.csv
    if roles:
        with (profile_dir / "roles-summary.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, quoting=csv.QUOTE_ALL)
            w.writerow(["RoleName", "RoleArn", "CreateDate",
                        "MaxSessionDuration", "PermissionsBoundary"])
            for r in roles:
                w.writerow([
                    r.get("RoleName", ""),
                    r.get("Arn", ""),
                    str(r.get("CreateDate", "")),
                    r.get("MaxSessionDuration", ""),
                    (r.get("PermissionsBoundary") or {}).get(
                        "PermissionsBoundaryArn", "NONE"),
                ])

    # role-policy-mapping.csv with explicit NOT_ENUMERATED markers
    with (profile_dir / "role-policy-mapping.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        w.writerow(["RoleName", "PolicyType", "PolicyName",
                    "PolicyArn", "EnumerationStatus"])

        for r in roles:
            name = r.get("RoleName", "")
            rdir = role_root / sanitize(name)

            attached = load_json(rdir / "attached-managed-policies.json")
            if attached is None:
                w.writerow([name, "Managed", "", "", "NOT_ENUMERATED"])
            elif not attached.get("AttachedPolicies"):
                w.writerow([name, "Managed", "(none)", "", "OK_EMPTY"])
            else:
                for p in attached["AttachedPolicies"]:
                    w.writerow([name, "Managed", p.get("PolicyName", ""),
                                p.get("PolicyArn", ""), "OK"])

            inline = load_json(rdir / "inline-policies.json")
            if inline is None:
                w.writerow([name, "Inline", "", "", "NOT_ENUMERATED"])
            elif not inline.get("PolicyNames"):
                w.writerow([name, "Inline", "(none)", "", "OK_EMPTY"])
            else:
                for pn in inline["PolicyNames"]:
                    w.writerow([name, "Inline", pn, "", "OK"])


# --------------------------------------------------------------------------
# Profile processing
# --------------------------------------------------------------------------

def process_profile(profile, output_root: Path, status_log: StatusLog,
                    skip_auth_details: bool) -> dict:
    ctx = ProfileContext(profile, status_log)
    profile_dir = output_root / sanitize(profile)
    role_root = profile_dir / "roles"
    role_root.mkdir(parents=True, exist_ok=True)

    log.info("=" * 60)
    log.info("Processing profile: %s", profile)

    # ---- Session / client creation -----------------------------------------
    try:
        session = boto3.session.Session(profile_name=profile)
        region = session.region_name or "us-east-1"
        sts = session.client("sts", region_name=region, config=BOTO_CONFIG)
        iam = session.client("iam", region_name=region, config=BOTO_CONFIG)
    except Exception as exc:  # noqa: BLE001
        status, detail = classify_exception(exc)
        ctx.errors += 1
        ctx.record("session:create", profile, status, detail)
        log.warning("Cannot initialise session for %s: %s", profile, detail)
        return finalize(ctx, profile_dir, "SESSION_FAILED")

    # ---- Credential validation -------------------------------------------
    identity = ctx.call("sts:GetCallerIdentity", profile, sts,
                        "get_caller_identity",
                        output=profile_dir / "caller-identity.json")
    if identity is None:
        log.warning("Authentication failed, skipping profile: %s", profile)
        return finalize(ctx, profile_dir, "AUTHENTICATION_FAILED")

    ctx.account = identity.get("Account", "UNKNOWN")
    ctx.caller_arn = identity.get("Arn", "")
    log.info("Account: %s | Caller: %s", ctx.account, ctx.caller_arn)

    # ---- Roles -----------------------------------------------------------------
    roles = []
    roles_resp = ctx.call("iam:ListRoles", profile, iam, "list_roles",
                          output=profile_dir / "roles.json",
                          paginate_keys=["Roles"])
    if roles_resp is not None:
        roles = roles_resp.get("Roles", [])
        if not roles:
            ctx.record("iam:ListRoles", profile, "EMPTY", "No roles returned")
        log.info("Roles discovered: %d", len(roles))

        for idx, role in enumerate(roles, 1):
            name = role.get("RoleName")
            if not name:
                continue
            log.info("  [%d/%d] Role: %s", idx, len(roles), name)
            try:
                process_role(ctx, iam, name, role_root)
            except Exception as exc:  # noqa: BLE001 - last-resort guard
                ctx.errors += 1
                ctx.record("process_role", name, "ERROR", repr(exc))
                log.error("Unexpected failure on role %s: %r", name, exc)
    else:
        log.warning("Role enumeration unavailable for %s", profile)

    # ---- Customer-managed policies ---------------------------------------------
    try:
        process_customer_managed_policies(ctx, iam, profile_dir)
    except Exception as exc:  # noqa: BLE001
        ctx.errors += 1
        ctx.record("process_customer_managed_policies", profile, "ERROR", repr(exc))

    # ---- Attached policies inventory (all scopes) ------------------------------
    ctx.call("iam:ListPolicies(attached-only)", profile, iam, "list_policies",
             output=profile_dir / "attached-policies-all-scopes.json",
             paginate_keys=["Policies"], Scope="All", OnlyAttached=True)

    # ---- Full authorization snapshot (best effort) ------------------------------
    if not skip_auth_details:
        ctx.call("iam:GetAccountAuthorizationDetails", profile, iam,
                 "get_account_authorization_details",
                 output=profile_dir / "account-authorization-details.json",
                 paginate_keys=["UserDetailList", "GroupDetailList",
                                "RoleDetailList", "Policies"])

    # ---- Summaries --------------------------------------------------------------
    try:
        build_summaries(profile_dir, roles, role_root)
    except Exception as exc:  # noqa: BLE001
        ctx.errors += 1
        ctx.record("build_summaries", profile, "ERROR", repr(exc))

    verdict = "COMPLETE" if (ctx.denied == 0 and ctx.errors == 0) else "PARTIAL"
    return finalize(ctx, profile_dir, verdict)


def finalize(ctx: ProfileContext, profile_dir: Path, verdict: str) -> dict:
    profile_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "Profile": ctx.profile,
        "AccountId": ctx.account,
        "Caller": ctx.caller_arn,
        "Verdict": verdict,
        "SuccessfulCalls": ctx.success,
        "AccessDenied": ctx.denied,
        "OtherErrors": ctx.errors,
        "CompletedAt": utc_now(),
    }
    with (profile_dir / "PROFILE_STATUS.txt").open("w", encoding="utf-8") as fh:
        for k, v in result.items():
            fh.write(f"{k}: {v}\n")

    level = logging.INFO if verdict == "COMPLETE" else logging.WARNING
    log.log(level, "%s: %s (success=%d, denied=%d, errors=%d)",
            verdict, ctx.profile, ctx.success, ctx.denied, ctx.errors)
    return result


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Fault-tolerant IAM role and policy enumeration "
                    "across AWS CLI profiles.")
    p.add_argument("-o", "--output", default="aws-iam-enumeration",
                   help="Output directory (default: aws-iam-enumeration)")
    p.add_argument("-p", "--profiles", nargs="+",
                   help="Specific profiles to process (default: all configured)")
    p.add_argument("--skip-auth-details", action="store_true",
                   help="Skip iam:GetAccountAuthorizationDetails snapshot")
    p.add_argument("--max-attempts", type=int, default=5,
                   help="Max attempts per API call incl. retries (default: 5)")
    p.add_argument("--connect-timeout", type=int, default=10,
                   help="Connect timeout in seconds (default: 10)")
    p.add_argument("--read-timeout", type=int, default=30,
                   help="Read timeout in seconds (default: 30)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose (debug) console logging")
    return p.parse_args()


def setup_logging(output_root: Path, verbose: bool):
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            "%Y-%m-%dT%H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    filelog = logging.FileHandler(output_root / "run.log", encoding="utf-8")
    filelog.setLevel(logging.DEBUG)
    filelog.setFormatter(fmt)
    log.addHandler(console)
    log.addHandler(filelog)


def main() -> int:
    global BOTO_CONFIG
    args = parse_args()
    BOTO_CONFIG = Config(
        retries={"max_attempts": max(1, args.max_attempts), "mode": "standard"},
        read_timeout=args.read_timeout,
        connect_timeout=args.connect_timeout,
    )
    output_root = Path(args.output)
    output_root.mkdir(parents=True, exist_ok=True)
    setup_logging(output_root, args.verbose)

    if args.profiles:
        profiles = args.profiles
    else:
        try:
            profiles = boto3.session.Session().available_profiles
        except Exception as exc:  # noqa: BLE001
            log.critical("Cannot read AWS CLI configuration: %s", exc)
            return 1

    if not profiles:
        log.critical("No AWS CLI profiles found.")
        return 1

    log.info("Output directory: %s", output_root.resolve())
    log.info("Profiles to process (%d): %s", len(profiles), ", ".join(profiles))

    status_log = StatusLog(output_root / "enumeration-status.csv")
    results = []

    try:
        for profile in profiles:
            try:
                results.append(process_profile(
                    profile, output_root, status_log, args.skip_auth_details))
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001 - never stop the run
                log.error("Unhandled failure on profile %s: %r", profile, exc)
                status_log.record(profile, "UNKNOWN", "process_profile",
                                  profile, "ERROR", repr(exc))
                results.append({"Profile": profile, "AccountId": "UNKNOWN",
                                "Caller": "", "Verdict": "FAILED",
                                "SuccessfulCalls": 0, "AccessDenied": 0,
                                "OtherErrors": 1, "CompletedAt": utc_now()})
    except KeyboardInterrupt:
        log.warning("Interrupted by user - writing partial summary.")
    finally:
        denied_total = status_log.count("ACCESS_DENIED")
        status_log.close()

        summary_path = output_root / "profile-summary.csv"
        fields = ["Profile", "AccountId", "Caller", "Verdict",
                  "SuccessfulCalls", "AccessDenied", "OtherErrors", "CompletedAt"]
        with summary_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, quoting=csv.QUOTE_ALL)
            w.writeheader()
            w.writerows(results)

        log.info("=" * 60)
        log.info("Enumeration finished.")
        log.info("Status log:      %s", output_root / "enumeration-status.csv")
        log.info("Profile summary: %s", summary_path)

        print("\nProfile verdicts:")
        print(f"{'Profile':<25}{'Account':<15}{'Verdict':<24}"
              f"{'OK':>6}{'Denied':>8}{'Errors':>8}")
        for r in results:
            print(f"{r['Profile']:<25}{r['AccountId']:<15}{r['Verdict']:<24}"
                  f"{r['SuccessfulCalls']:>6}{r['AccessDenied']:>8}{r['OtherErrors']:>8}")

        if denied_total:
            print(f"\n[!] {denied_total} operation(s) were blocked by insufficient "
                  "permissions.\n    Treat the corresponding data as NOT "
                  "ENUMERATED, not as 'no configuration present'.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
