#!/usr/bin/env bash
#
# rds_kms_audit.sh - Audit RDS encryption at rest across every AWS CLI profile.
#
# For every profile x region it lists RDS DB instances (and DB clusters), then
# for each KMS key in use it checks that:
#   - StorageEncrypted is true
#   - the key is customer-managed (KeyManager=CUSTOMER), not the AWS-managed aws/rds key
#   - automatic key rotation is enabled
#   - the key is in the Enabled state
# Anything that fails a check is FLAG. Anything that can't be verified
# (for example, AccessDenied on a cross-account key) is REVIEW.
#
# The script is read-only. It only makes Describe, Get and List calls.
# It needs the AWS CLI (v1 or v2) and bash 3.2 or later (the macOS default works).
#
# Usage:
#   ./rds_kms_audit.sh                         # all profiles, all enabled regions
#   ./rds_kms_audit.sh -p prod -p staging      # only the named profiles
#   ./rds_kms_audit.sh -r us-east-1,eu-west-1  # only the named regions
#   ./rds_kms_audit.sh -o report.csv --no-clusters
#
# Exit codes: 0 = all PASS, 1 = at least one FLAG, 2 = no FLAG but some REVIEW/ERROR, 3 = usage

set -uo pipefail
export AWS_PAGER=""

PROFILES=()
REGIONS=""
OUT="rds_kms_audit_$(date +%Y%m%d_%H%M%S).csv"
INCLUDE_CLUSTERS=1
SEP=$'\x1f'   # internal field separator that keeps empty fields intact

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }
need_arg() { [ "$1" -ge 2 ] || { echo "Missing value for $2" >&2; usage; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--profile)  need_arg $# "$1"; PROFILES+=("$2"); shift 2 ;;
    -r|--regions)  need_arg $# "$1"; REGIONS="${2//,/ }"; shift 2 ;;
    -o|--output)   need_arg $# "$1"; OUT="$2"; shift 2 ;;
    --no-clusters) INCLUDE_CLUSTERS=0; shift ;;
    -h|--help)     usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found in PATH" >&2; exit 3; }

if [ ${#PROFILES[@]} -eq 0 ]; then
  while IFS= read -r p; do [ -n "$p" ] && PROFILES+=("$p"); done < <(aws configure list-profiles)
fi
[ ${#PROFILES[@]} -gt 0 ] || { echo "No AWS CLI profiles found" >&2; exit 3; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Never let the CLI read stdin (we call it inside 'while read' loops)
awsq() { aws "$@" </dev/null; }

# Pull the error code out of e.g. "An error occurred (AccessDeniedException) when calling..."
err_code() {
  local c
  c=$(grep -oE '\([A-Za-z]+\)' "$1" 2>/dev/null | head -1 | tr -d '()')
  echo "${c:-Error}"
}

csv() { local IFS=,; echo "$*"; }

# ---------------------------------------------------------------------------
# lookup_key PROFILE KEY_ARN
#   prints: manager SEP state SEP rotation SEP alias SEP note   (cached per profile+key)
# ---------------------------------------------------------------------------
lookup_key() {
  local profile=$1 arn=$2 cache kregion out manager state rotation alias note="" errf
  cache="$WORK/key_$(printf '%s|%s' "$profile" "$arn" | cksum | cut -d' ' -f1)"
  if [ -f "$cache" ]; then cat "$cache"; return; fi
  errf="$cache.err"
  kregion=$(printf '%s' "$arn" | cut -d: -f4)   # KMS calls must go to the key's own region

  if out=$(awsq kms describe-key --profile "$profile" --region "$kregion" --key-id "$arn" \
             --query 'KeyMetadata.[KeyManager,KeyState]' --output text 2>"$errf"); then
    manager=$(printf '%s' "$out" | cut -f1)
    state=$(printf '%s' "$out" | cut -f2)
  else
    manager=UNKNOWN; state=UNKNOWN; note="describe-key:$(err_code "$errf")"
  fi

  if out=$(awsq kms get-key-rotation-status --profile "$profile" --region "$kregion" --key-id "$arn" \
             --query 'KeyRotationEnabled' --output text 2>"$errf"); then
    rotation=$out
  else
    rotation=UNKNOWN; note="${note:+$note;}get-key-rotation-status:$(err_code "$errf")"
  fi

  # Show the alias (e.g. aws/rds) when it's visible. This fails silently for cross-account keys.
  alias=$(awsq kms list-aliases --profile "$profile" --region "$kregion" --key-id "$arn" \
            --query 'Aliases[].AliasName' --output text 2>/dev/null | tr '\t' '|')
  [ "$alias" = "None" ] && alias=""

  printf '%s\n' "${manager}${SEP}${state}${SEP}${rotation}${SEP}${alias}${SEP}${note}" | tee "$cache"
}

# ---------------------------------------------------------------------------
# evaluate PROFILE ACCOUNT REGION TYPE ID KEY ENCRYPTED ENGINE  -> one CSV line
# ---------------------------------------------------------------------------
evaluate() {
  local profile=$1 account=$2 region=$3 rtype=$4 id=$5 key=$6 enc=$7 engine=$8
  local manager="" state="" rotation="" alias="" note="" findings="" hard=0 status
  add() { findings="${findings:+$findings;}$1"; }

  [ "$key" = "None" ] && key=""
  if [ "$enc" != "True" ]; then add NOT_ENCRYPTED; hard=1; fi

  if [ -n "$key" ]; then
    IFS="$SEP" read -r manager state rotation alias note <<< "$(lookup_key "$profile" "$key")"
    case "$manager" in
      AWS)      add AWS_MANAGED_KEY; hard=1 ;;
      CUSTOMER) ;;
      *)        add KEY_MANAGER_UNKNOWN ;;
    esac
    case "$rotation" in
      True)  ;;
      False) add ROTATION_DISABLED; hard=1 ;;
      *)     add ROTATION_UNKNOWN ;;
    esac
    if [ "$state" != "Enabled" ] && [ "$state" != "UNKNOWN" ]; then add "KEY_STATE_$state"; hard=1; fi
    [ -n "$note" ] && add "$note"
  elif [ "$enc" = "True" ]; then
    add NO_KMS_KEY_REPORTED
  fi

  if   [ -z "$findings" ]; then status=PASS
  elif [ $hard -eq 1 ];    then status=FLAG
  else                          status=REVIEW
  fi
  csv "$profile" "$account" "$region" "$rtype" "$id" "$engine" "$enc" "$key" \
      "$alias" "$manager" "$state" "$rotation" "$status" "$findings"
}

# ---------------------------------------------------------------------------
# scan PROFILE ACCOUNT REGION instance|cluster
# ---------------------------------------------------------------------------
scan() {
  local profile=$1 account=$2 region=$3 kind=$4 rows rc errf id key enc engine
  errf=$(mktemp "$WORK/err.XXXXXX")
  if [ "$kind" = instance ]; then
    rows=$(awsq rds describe-db-instances --profile "$profile" --region "$region" \
      --query 'DBInstances[].[DBInstanceIdentifier,KmsKeyId,StorageEncrypted,Engine]' \
      --output text 2>"$errf"); rc=$?
  else
    rows=$(awsq rds describe-db-clusters --profile "$profile" --region "$region" \
      --query 'DBClusters[].[DBClusterIdentifier,KmsKeyId,StorageEncrypted,Engine]' \
      --output text 2>"$errf"); rc=$?
  fi
  if [ $rc -ne 0 ]; then
    csv "$profile" "$account" "$region" "$kind" "" "" "" "" "" "" "" "" ERROR \
        "describe-db-${kind}s:$(err_code "$errf")"
    return
  fi
  while IFS=$'\t' read -r id key enc engine; do
    [ -z "$id" ] && continue
    evaluate "$profile" "$account" "$region" "$kind" "$id" "$key" "$enc" "$engine"
  done <<< "$rows"
}

# ---------------------------------------------------------------------------
# audit_profile PROFILE OUTFILE
# ---------------------------------------------------------------------------
audit_profile() {
  local profile=$1 out=$2 account regions region home errf
  errf=$(mktemp "$WORK/err.XXXXXX")

  if ! account=$(awsq sts get-caller-identity --profile "$profile" --query Account --output text 2>"$errf"); then
    csv "$profile" "" "" profile "" "" "" "" "" "" "" "" ERROR "sts:$(err_code "$errf")" >> "$out"
    echo "[$profile] cannot authenticate ($(err_code "$errf")). Skipped." >&2
    return
  fi

  if [ -n "$REGIONS" ]; then
    regions=$REGIONS
  else
    home=$(aws configure get region --profile "$profile" 2>/dev/null)
    if ! regions=$(awsq ec2 describe-regions --profile "$profile" --region "${home:-us-east-1}" \
                     --query 'Regions[].RegionName' --output text 2>"$errf"); then
      csv "$profile" "$account" "" profile "" "" "" "" "" "" "" "" ERROR \
          "describe-regions:$(err_code "$errf") (use -r to list regions)" >> "$out"
      echo "[$profile] cannot list regions. Use -r to name them." >&2
      return
    fi
  fi

  echo "[$profile] account $account: scanning $(echo $regions | wc -w | tr -d ' ') regions..." >&2
  for region in $regions; do
    scan "$profile" "$account" "$region" instance >> "$out"
    [ "$INCLUDE_CLUSTERS" -eq 1 ] && scan "$profile" "$account" "$region" cluster >> "$out"
  done
  echo "[$profile] done." >&2
}

# ---------------------------------------------------------------------------
# main: audit all profiles in parallel, then merge in profile order
# ---------------------------------------------------------------------------
i=0
for p in "${PROFILES[@]}"; do
  audit_profile "$p" "$WORK/profile_$i.csv" &
  i=$((i + 1))
done
wait

echo "profile,account_id,region,resource_type,identifier,engine,storage_encrypted,kms_key_arn,key_alias,key_manager,key_state,rotation_enabled,status,findings" > "$OUT"
i=0
for p in "${PROFILES[@]}"; do
  [ -f "$WORK/profile_$i.csv" ] && cat "$WORK/profile_$i.csv" >> "$OUT"
  i=$((i + 1))
done

count() { awk -F, -v s="$1" 'NR>1 && $13==s' "$OUT" | wc -l | tr -d ' '; }
PASS=$(count PASS); FLAG=$(count FLAG); REVIEW=$(count REVIEW); ERR=$(count ERROR)

echo
echo "=== RDS KMS audit: ${#PROFILES[@]} profiles ==="
echo "PASS: $PASS   FLAG: $FLAG   REVIEW: $REVIEW   ERROR: $ERR"
echo "Report: $OUT"

if [ $((FLAG + REVIEW + ERR)) -gt 0 ]; then
  echo
  {
    printf 'STATUS\tPROFILE\tREGION\tTYPE\tIDENTIFIER\tALIAS\tFINDINGS\n'
    awk -F, -v OFS='\t' 'NR>1 && $13!="PASS" {print $13,$1,$3,$4,($5==""?"-":$5),($9==""?"-":$9),$14}' "$OUT" | sort
  } | if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi
fi

if   [ "$FLAG" -gt 0 ];                   then exit 1
elif [ $((REVIEW + ERR)) -gt 0 ];         then exit 2
else                                           exit 0
fi
