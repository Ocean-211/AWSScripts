#!/usr/bin/env bash
# Enumerate potentially or confirmed publicly accessible S3 buckets owned by
# every locally configured AWS CLI profile. Read-only checks only.
set -uo pipefail

OUT_DIR="${1:-public_s3_audit}"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/public_s3_buckets.txt"
ERRORS="$OUT_DIR/public_s3_errors.txt"
ALL="$OUT_DIR/all_s3_public_access_checks.txt"
: > "$REPORT"; : > "$ERRORS"; : > "$ALL"

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 2; }

mapfile -t PROFILES < <(aws configure list-profiles 2>/dev/null | awk 'NF' | sort -u)
((${#PROFILES[@]})) || { echo "No configured AWS profiles found" >&2; exit 2; }

is_public_acl() {
  python3 -c 'import json,sys
try:
 d=json.load(sys.stdin)
 print("true" if any(g.get("Grantee",{}).get("URI","").endswith(("/AllUsers","/AuthenticatedUsers")) for g in d.get("Grants",[])) else "false")
except Exception: print("unknown")'
}

printf 'S3 PUBLIC ACCESS AUDIT\nGenerated UTC: %s\n\n' "$(date -u +%FT%TZ)" | tee -a "$REPORT" "$ALL" >/dev/null

for profile in "${PROFILES[@]}"; do
  echo "[+] Profile: $profile"
  account=$(aws sts get-caller-identity --profile "$profile" --query Account --output text 2>>"$ERRORS") || {
    printf 'profile=%s scope=sts status=ERROR\n' "$profile" >> "$ERRORS"; continue;
  }
  mapfile -t buckets < <(aws s3api list-buckets --profile "$profile" --query 'Buckets[].Name' --output text 2>>"$ERRORS" | tr '\t' '\n' | awk 'NF')

  for bucket in "${buckets[@]}"; do
    region=$(aws s3api get-bucket-location --bucket "$bucket" --profile "$profile" --query LocationConstraint --output text 2>>"$ERRORS" || echo UNKNOWN)
    [[ "$region" == "None" || "$region" == "null" ]] && region="us-east-1"
    [[ "$region" == "EU" ]] && region="eu-west-1"

    policy_public=$(aws s3api get-bucket-policy-status --bucket "$bucket" --profile "$profile" --query 'PolicyStatus.IsPublic' --output text 2>>"$ERRORS" || echo UNKNOWN)
    policy_public=${policy_public,,}

    acl_json=$(aws s3api get-bucket-acl --bucket "$bucket" --profile "$profile" --output json 2>>"$ERRORS" || true)
    acl_public="unknown"
    [[ -n "$acl_json" ]] && acl_public=$(printf '%s' "$acl_json" | is_public_acl)

    pab=$(aws s3api get-public-access-block --bucket "$bucket" --profile "$profile" --output json 2>>"$ERRORS" || true)
    if [[ -n "$pab" ]]; then
      all_blocked=$(printf '%s' "$pab" | python3 -c 'import json,sys
try:
 p=json.load(sys.stdin)["PublicAccessBlockConfiguration"]
 print("true" if all(p.get(k) is True for k in ("BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets")) else "false")
except Exception: print("unknown")')
    else
      all_blocked="not-configured-or-unreadable"
    fi

    # Anonymous list test confirms public bucket listing when it succeeds.
    anon_list="false"
    if aws s3api list-objects-v2 --bucket "$bucket" --max-items 1 --no-sign-request >/dev/null 2>>"$ERRORS"; then
      anon_list="true"
    fi

    status="NOT_CONFIRMED_PUBLIC"
    reasons=()
    [[ "$policy_public" == "true" ]] && { status="PUBLIC_OR_PUBLIC_PREFIX"; reasons+=("bucket-policy"); }
    [[ "$acl_public" == "true" ]] && { status="PUBLIC"; reasons+=("public-acl"); }
    [[ "$anon_list" == "true" ]] && { status="PUBLIC"; reasons+=("anonymous-list"); }
    [[ "$all_blocked" != "true" ]] && reasons+=("block-public-access-not-fully-enabled")
    reason=$(IFS=,; echo "${reasons[*]:-none}")

    line="profile=$profile account=$account bucket=$bucket region=$region status=$status reasons=$reason policy_public=$policy_public acl_public=$acl_public anonymous_list=$anon_list all_blocked=$all_blocked"
    echo "$line" >> "$ALL"
    if [[ "$status" != "NOT_CONFIRMED_PUBLIC" ]]; then echo "$line" >> "$REPORT"; fi
  done
done

printf '\nCompleted.\nPublic findings: %s\nAll checks: %s\nErrors: %s\n' "$REPORT" "$ALL" "$ERRORS"
