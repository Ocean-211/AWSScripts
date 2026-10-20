#!/usr/bin/env python3
"""
enumerate_public_s3_buckets.py

Enumerates S3 buckets across all configured AWS CLI profiles (or a chosen subset)
and reports which buckets are publicly accessible. Results are written to a text file.

Per bucket it evaluates:
  1. Bucket policy status        (GetBucketPolicyStatus -> IsPublic)
  2. Bucket policy statements    (Allow + Principal "*" -> flags, notes conditions)
  3. Bucket ACL                  (grants to AllUsers / AuthenticatedUsers)
  4. Bucket-level Public Access Block (PAB)
  5. Account-level Public Access Block (S3 Control)
  6. Optional anonymous probe    (--probe: unsigned ListObjectsV2 / GetBucketAcl)

Verdicts:
  PUBLIC            - public policy/ACL exists and is NOT neutralised by Public Access Block
  PUBLIC-BLOCKED    - public policy/ACL exists but PAB currently neutralises it (latent risk)
  NOT PUBLIC        - no public policy/ACL found
  UNKNOWN           - required API calls were denied/failed, could not determine

Requirements: boto3  (pip install boto3)
Required IAM permissions (read-only):
  s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketPolicy, s3:GetBucketPolicyStatus,
  s3:GetBucketAcl, s3:GetBucketPublicAccessBlock, s3:GetAccountPublicAccessBlock,
  sts:GetCallerIdentity

Usage:
  python enumerate_public_s3_buckets.py
  python enumerate_public_s3_buckets.py --profiles dev01 prod01 -o public_s3.txt
  python enumerate_public_s3_buckets.py --probe --workers 20
  python enumerate_public_s3_buckets.py --dedupe-accounts
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

CLIENT_CFG = Config(retries={"max_attempts": 5, "mode": "adaptive"},
                    connect_timeout=10, read_timeout=30)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def err_code(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "ClientError")
    return type(e).__name__


def get_account_pab(session, account_id):
    """Account-level Public Access Block. Returns (dict, error)."""
    try:
        s3c = session.client("s3control", config=CLIENT_CFG)
        resp = s3c.get_public_access_block(AccountId=account_id)
        return resp["PublicAccessBlockConfiguration"], None
    except ClientError as e:
        if err_code(e) == "NoSuchPublicAccessBlockConfiguration":
            return {}, None  # not configured
        return {}, err_code(e)
    except BotoCoreError as e:
        return {}, type(e).__name__


def analyze_policy_statements(policy_json):
    """Return list of human-readable findings for Allow + wildcard-principal statements."""
    findings = []
    try:
        policy = json.loads(policy_json)
    except Exception:
        return ["Policy could not be parsed"]
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        wildcard = principal == "*" or (
            isinstance(principal, dict)
            and ("*" in (principal.get("AWS") if isinstance(principal.get("AWS"), list)
                         else [principal.get("AWS")]))
        )
        if not wildcard:
            continue
        actions = st.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        cond = st.get("Condition")
        sid = st.get("Sid", "-")
        note = f"Sid={sid}; Actions={','.join(actions)}"
        note += f"; Condition={json.dumps(cond)}" if cond else "; Condition=NONE"
        findings.append(note)
    return findings


def anonymous_probe(bucket, region):
    """Unsigned requests - confirms real-world anonymous access (opt-in)."""
    result = {}
    try:
        anon = boto3.client("s3", region_name=region or "us-east-1",
                            config=Config(signature_version=UNSIGNED,
                                          connect_timeout=10, read_timeout=20,
                                          retries={"max_attempts": 2}))
    except Exception as e:  # pragma: no cover
        return {"error": type(e).__name__}
    try:
        anon.list_objects_v2(Bucket=bucket, MaxKeys=1)
        result["anonymous_list"] = "ALLOWED"
    except ClientError as e:
        result["anonymous_list"] = f"denied ({err_code(e)})"
    except Exception as e:
        result["anonymous_list"] = f"error ({type(e).__name__})"
    try:
        anon.get_bucket_acl(Bucket=bucket)
        result["anonymous_read_acl"] = "ALLOWED"
    except ClientError as e:
        result["anonymous_read_acl"] = f"denied ({err_code(e)})"
    except Exception as e:
        result["anonymous_read_acl"] = f"error ({type(e).__name__})"
    return result


def analyze_bucket(session, name, account_pab, probe):
    info = {
        "bucket": name, "region": None, "verdict": "UNKNOWN",
        "policy_is_public": None, "policy_findings": [],
        "acl_public_grants": [], "bucket_pab": None,
        "effective_pab": {}, "reasons": [], "errors": [], "probe": None,
    }

    # Region
    try:
        s3 = session.client("s3", config=CLIENT_CFG)
        loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
        region = loc or "us-east-1"
        if region == "EU":
            region = "eu-west-1"
        info["region"] = region
    except Exception as e:
        info["errors"].append(f"GetBucketLocation:{err_code(e)}")
        region = None
    s3 = session.client("s3", region_name=region, config=CLIENT_CFG) if region else s3

    # Bucket-level PAB
    bpab = {}
    try:
        bpab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        info["bucket_pab"] = bpab
    except ClientError as e:
        if err_code(e) == "NoSuchPublicAccessBlockConfiguration":
            info["bucket_pab"] = "NOT CONFIGURED"
        else:
            info["errors"].append(f"GetBucketPublicAccessBlock:{err_code(e)}")
    except Exception as e:
        info["errors"].append(f"GetBucketPublicAccessBlock:{type(e).__name__}")

    def flag(k):
        return bool(bpab.get(k)) or bool(account_pab.get(k))
    info["effective_pab"] = {k: flag(k) for k in
                             ("BlockPublicAcls", "IgnorePublicAcls",
                              "BlockPublicPolicy", "RestrictPublicBuckets")}

    # Policy status + statements
    policy_checked = False
    try:
        ps = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
        info["policy_is_public"] = bool(ps.get("IsPublic"))
        policy_checked = True
    except ClientError as e:
        if err_code(e) == "NoSuchBucketPolicy":
            info["policy_is_public"] = False
            policy_checked = True
        else:
            info["errors"].append(f"GetBucketPolicyStatus:{err_code(e)}")
    except Exception as e:
        info["errors"].append(f"GetBucketPolicyStatus:{type(e).__name__}")

    try:
        pol = s3.get_bucket_policy(Bucket=name)["Policy"]
        info["policy_findings"] = analyze_policy_statements(pol)
        if info["policy_is_public"] is None and info["policy_findings"]:
            # fall back to statement analysis if status API was denied
            info["policy_is_public"] = any("Condition=NONE" in f for f in info["policy_findings"])
            policy_checked = True
    except ClientError as e:
        if err_code(e) != "NoSuchBucketPolicy":
            info["errors"].append(f"GetBucketPolicy:{err_code(e)}")
    except Exception as e:
        info["errors"].append(f"GetBucketPolicy:{type(e).__name__}")

    # ACL
    acl_checked = False
    try:
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        for g in grants:
            uri = g.get("Grantee", {}).get("URI")
            if uri in (ALL_USERS_URI, AUTH_USERS_URI):
                grp = "AllUsers" if uri == ALL_USERS_URI else "AuthenticatedUsers"
                info["acl_public_grants"].append(f"{grp}:{g.get('Permission')}")
        acl_checked = True
    except Exception as e:
        info["errors"].append(f"GetBucketAcl:{err_code(e)}")

    # Verdict
    policy_pub = bool(info["policy_is_public"])
    acl_pub = bool(info["acl_public_grants"])
    eff = info["effective_pab"]
    policy_live = policy_pub and not eff["RestrictPublicBuckets"]
    acl_live = acl_pub and not eff["IgnorePublicAcls"]

    if policy_pub:
        info["reasons"].append("Bucket policy grants public access"
                               + (" (neutralised by RestrictPublicBuckets)" if not policy_live else ""))
    if acl_pub:
        info["reasons"].append("ACL grants: " + ", ".join(info["acl_public_grants"])
                               + (" (neutralised by IgnorePublicAcls)" if not acl_live else ""))

    if policy_live or acl_live:
        info["verdict"] = "PUBLIC"
    elif policy_pub or acl_pub:
        info["verdict"] = "PUBLIC-BLOCKED"
    elif policy_checked and acl_checked:
        info["verdict"] = "NOT PUBLIC"
    else:
        info["verdict"] = "UNKNOWN"

    if probe:
        info["probe"] = anonymous_probe(name, region)
        if info["probe"].get("anonymous_list") == "ALLOWED" and info["verdict"] != "PUBLIC":
            info["verdict"] = "PUBLIC"
            info["reasons"].append("Anonymous ListObjectsV2 succeeded (confirmed by probe)")
    return info


def scan_profile(profile, probe, workers):
    res = {"profile": profile, "account_id": None, "arn": None, "account_pab": None,
           "buckets": [], "error": None}
    try:
        session = boto3.Session(profile_name=profile)
        ident = session.client("sts", config=CLIENT_CFG).get_caller_identity()
        res["account_id"], res["arn"] = ident["Account"], ident["Arn"]
    except Exception as e:
        res["error"] = f"STS GetCallerIdentity failed: {err_code(e)} - {e}"
        return res

    account_pab, pab_err = get_account_pab(session, res["account_id"])
    res["account_pab"] = account_pab if account_pab else (
        f"ERROR: {pab_err}" if pab_err else "NOT CONFIGURED")

    try:
        buckets = session.client("s3", config=CLIENT_CFG).list_buckets().get("Buckets", [])
    except Exception as e:
        res["error"] = f"ListBuckets failed: {err_code(e)} - {e}"
        return res

    names = [b["Name"] for b in buckets]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(analyze_bucket, session, n, account_pab, probe) for n in names]
        for f in futures:
            try:
                res["buckets"].append(f.result())
            except Exception as e:  # never let one bucket kill the profile
                res["buckets"].append({"bucket": "?", "verdict": "UNKNOWN",
                                       "errors": [f"Unhandled:{type(e).__name__}"],
                                       "reasons": [], "policy_findings": [],
                                       "acl_public_grants": [], "effective_pab": {},
                                       "region": None, "bucket_pab": None, "probe": None})
    res["buckets"].sort(key=lambda b: b["bucket"])
    return res


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def write_report(results, path, public_only):
    lines = []
    w = lines.append
    w("=" * 100)
    w("PUBLICLY ACCESSIBLE S3 BUCKET ENUMERATION")
    w(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"Profiles  : {len(results)}")
    w("=" * 100)
    w("")

    # Summary table
    w("SUMMARY")
    w("-" * 100)
    w(f"{'PROFILE':<28}{'ACCOUNT':<15}{'BUCKETS':>8}{'PUBLIC':>8}{'BLOCKED':>9}{'UNKNOWN':>9}  STATUS")
    totals = [0, 0, 0, 0]
    for r in results:
        bl = r["buckets"]
        pub = sum(b["verdict"] == "PUBLIC" for b in bl)
        blk = sum(b["verdict"] == "PUBLIC-BLOCKED" for b in bl)
        unk = sum(b["verdict"] == "UNKNOWN" for b in bl)
        status = "ERROR" if r["error"] else "OK"
        w(f"{r['profile']:<28}{(r['account_id'] or '-'):<15}{len(bl):>8}{pub:>8}{blk:>9}{unk:>9}  {status}")
        for i, v in enumerate((len(bl), pub, blk, unk)):
            totals[i] += v
    w("-" * 100)
    w(f"{'TOTAL':<43}{totals[0]:>8}{totals[1]:>8}{totals[2]:>9}{totals[3]:>9}")
    w("")

    # Consolidated list of public buckets
    w("ALL PUBLIC BUCKETS (verdict = PUBLIC)")
    w("-" * 100)
    any_pub = False
    for r in results:
        for b in r["buckets"]:
            if b["verdict"] == "PUBLIC":
                any_pub = True
                w(f"[{r['profile']} / {r['account_id']}] {b['bucket']}  ({b['region']})")
                for reason in b["reasons"]:
                    w(f"      - {reason}")
    if not any_pub:
        w("None found.")
    w("")

    # Per-profile detail
    w("=" * 100)
    w("DETAILS BY PROFILE")
    w("=" * 100)
    for r in results:
        w("")
        w(f"PROFILE : {r['profile']}")
        w(f"ACCOUNT : {r['account_id']}")
        w(f"CALLER  : {r['arn']}")
        w(f"ACCOUNT-LEVEL PUBLIC ACCESS BLOCK: {r['account_pab']}")
        if r["error"]:
            w(f"ERROR   : {r['error']}")
            w("-" * 100)
            continue
        w(f"BUCKETS : {len(r['buckets'])}")
        w("-" * 100)
        for b in r["buckets"]:
            if public_only and b["verdict"] not in ("PUBLIC", "PUBLIC-BLOCKED"):
                continue
            w(f"  Bucket  : {b['bucket']}")
            w(f"  Region  : {b['region']}")
            w(f"  Verdict : {b['verdict']}")
            for reason in b["reasons"]:
                w(f"  Reason  : {reason}")
            for f in b["policy_findings"]:
                w(f"  Policy  : Allow to Principal '*' -> {f}")
            w(f"  Bucket PAB    : {b['bucket_pab']}")
            w(f"  Effective PAB : {b['effective_pab']}")
            if b.get("probe"):
                w(f"  Anon probe    : {b['probe']}")
            if b["errors"]:
                w(f"  Errors  : {', '.join(b['errors'])}")
            w("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Enumerate publicly accessible S3 buckets across AWS profiles.")
    ap.add_argument("--profiles", nargs="+", help="Profiles to scan (default: all configured)")
    ap.add_argument("-o", "--output", default="public_s3_buckets.txt", help="Output text file")
    ap.add_argument("--workers", type=int, default=10, help="Parallel bucket checks per profile")
    ap.add_argument("--probe", action="store_true",
                    help="Also send unsigned (anonymous) requests to confirm access. Only use on authorised targets.")
    ap.add_argument("--public-only", action="store_true",
                    help="In the details section, list only PUBLIC / PUBLIC-BLOCKED buckets")
    ap.add_argument("--dedupe-accounts", action="store_true",
                    help="Skip profiles that resolve to an account already scanned")
    args = ap.parse_args()

    profiles = args.profiles or boto3.Session().available_profiles
    if not profiles:
        sys.exit("No AWS profiles found. Run 'aws configure list-profiles' to verify.")

    results, seen = [], set()
    for p in profiles:
        print(f"[*] Scanning profile: {p}", flush=True)
        r = scan_profile(p, args.probe, args.workers)
        if args.dedupe_accounts and r["account_id"] in seen:
            print(f"    skipped (duplicate account {r['account_id']})")
            continue
        if r["account_id"]:
            seen.add(r["account_id"])
        if r["error"]:
            print(f"    ERROR: {r['error']}")
        else:
            pub = sum(b["verdict"] == "PUBLIC" for b in r["buckets"])
            print(f"    account={r['account_id']} buckets={len(r['buckets'])} public={pub}")
        results.append(r)

    write_report(results, args.output, args.public_only)
    print(f"\n[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
