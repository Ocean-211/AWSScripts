#!/usr/bin/env bash
#
# vpc_flowlog_audit.sh - VPC Flow Log coverage audit across every AWS CLI profile and region.
#
# For every profile x region:
#   1. aws ec2 describe-vpcs
#   2. aws ec2 describe-flow-logs   (ResourceId, LogDestination, LogDestinationType,
#                                     TrafficType, FlowLogStatus, plus delivery status)
#   3. Joins flow logs to VPCs on ResourceId = VpcId and classifies each VPC:
#        COVERED          active VPC-level log(s) capture ALL traffic (or ACCEPT + REJECT)
#        ACCEPT_ONLY      only ACCEPT traffic is captured                -> finding
#        REJECT_ONLY      only REJECT traffic is captured                -> finding
#        NO_FLOW_LOG      no VPC-level flow log                          -> finding + missing list
#        INACTIVE         flow log exists but FlowLogStatus != ACTIVE    -> finding + missing list
#        DELIVERY_FAILED  active log but DeliverLogsStatus = FAILED      -> finding + missing list
#      Subnet- and ENI-level flow logs are mapped back to their VPC and reported as partial
#      coverage. They don't count as VPC coverage.
#
# Evidence written to the output directory:
#   flowlog_coverage.csv   one row per VPC: coverage status, traffic types, destination types and ARNs
#   flow_logs.csv          one row per flow log (the describe-flow-logs query, plus delivery fields)
#   missing_vpcs.csv       VPCs with no working VPC-level flow log
#   findings.csv           findings with severity (opens in Excel or Sheets)
#   errors.csv             API calls that failed
#   commands.log           every AWS CLI command run, with a timestamp
#   raw/<profile>/<region>/*.json   the raw API responses
#
# The script is read-only. It needs the AWS CLI (v1 or v2), jq 1.6 or later, and bash 3.2 or later.
#
# Usage:
#   ./vpc_flowlog_audit.sh                          # all profiles, all enabled regions
#   ./vpc_flowlog_audit.sh -p prod -p staging       # only the named profiles
#   ./vpc_flowlog_audit.sh -r us-east-1,ap-south-1  # only the named regions
#   ./vpc_flowlog_audit.sh -o evidence_dir --skip-default-vpcs
#
# Exit codes: 0 = no findings, 1 = findings, 2 = no findings but some API errors, 3 = usage

set -uo pipefail
export AWS_PAGER=""

PROFILES=()
REGIONS=""
OUTDIR="vpc_flowlog_audit_$(date +%Y%m%d_%H%M%S)"
SKIP_DEFAULT=false
CHUNK=50

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }
need_arg() { [ "$1" -ge 2 ] || { echo "Missing value for $2" >&2; usage; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--profile)        need_arg $# "$1"; PROFILES+=("$2"); shift 2 ;;
    -r|--regions)        need_arg $# "$1"; REGIONS="${2//,/ }"; shift 2 ;;
    -o|--output)         need_arg $# "$1"; OUTDIR="$2"; shift 2 ;;
    --skip-default-vpcs) SKIP_DEFAULT=true; shift ;;
    -h|--help)           usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found in PATH" >&2; exit 3; }
command -v jq  >/dev/null 2>&1 || { echo "jq not found (brew install jq / apt install jq)" >&2; exit 3; }

if [ ${#PROFILES[@]} -eq 0 ]; then
  while IFS= read -r p; do [ -n "$p" ] && PROFILES+=("$p"); done < <(aws configure list-profiles)
fi
[ ${#PROFILES[@]} -gt 0 ] || { echo "No AWS CLI profiles found" >&2; exit 3; }

mkdir -p "$OUTDIR/raw" || exit 3
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# jq: join flow logs to VPCs and classify coverage
# ---------------------------------------------------------------------------
ANALYZE_JQ=$(cat <<'JQ'
def tag($k): [(.Tags // [])[] | select(.Key == $k) | .Value][0] // "";
def has($arr; $x): any($arr[]; . == $x);
def kind:
  if   startswith("vpc-")        then "vpc"
  elif startswith("subnet-")     then "subnet"
  elif startswith("eni-")        then "eni"
  elif startswith("tgw-attach-") then "tgw-attachment"
  elif startswith("tgw-")        then "transit-gateway"
  else "other" end;
def dest: (.LogDestination // (if (.LogGroupName // "") != "" then "log-group:" + .LogGroupName else "" end));

(reduce ($sn[0].Subnets // [])[] as $s ({}; .[$s.SubnetId] = $s.VpcId)) as $s2v
| (reduce ($eni[0].NetworkInterfaces // [])[] as $n ({}; .[$n.NetworkInterfaceId] = $n.VpcId)) as $e2v
| [ ($fl[0].FlowLogs // [])[]
    | (.ResourceId | kind) as $k
    | { profile: $profile, account: $account, region: $region,
        flow_log_id: .FlowLogId, resource_id: .ResourceId, resource_kind: $k,
        vpc_id: (if $k == "vpc" then .ResourceId
                 elif $k == "subnet" then ($s2v[.ResourceId] // "")
                 elif $k == "eni" then ($e2v[.ResourceId] // "")
                 else "" end),
        log_destination: dest,
        log_destination_type: (.LogDestinationType // "cloud-watch-logs"),
        traffic_type: (.TrafficType // ""),
        flow_log_status: (.FlowLogStatus // ""),
        deliver_logs_status: (.DeliverLogsStatus // ""),
        deliver_logs_error: (.DeliverLogsErrorMessage // ""),
        max_aggregation_interval: (.MaxAggregationInterval // ""),
        log_format: (.LogFormat // ""),
        deliver_logs_permission_arn: (.DeliverLogsPermissionArn // ""),
        creation_time: (.CreationTime // "") } ] as $flows
| [ ($vpcs[0].Vpcs // [])[]
    | . as $v
    | select(($skip_default | not) or ($v.IsDefault != true))
    | [ $flows[] | select(.resource_kind == "vpc" and .resource_id == $v.VpcId) ] as $mine
    | [ $mine[] | select(.flow_log_status == "ACTIVE") ] as $active
    | [ $active[] | select(.deliver_logs_status != "FAILED") ] as $healthy
    | ([ $healthy[].traffic_type ] | unique) as $tt
    | [ $flows[] | select(.vpc_id == $v.VpcId and (.resource_kind == "subnet" or .resource_kind == "eni")) ] as $partial
    | ( if ($mine | length) == 0 then "NO_FLOW_LOG"
        elif ($active | length) == 0 then "INACTIVE"
        elif ($healthy | length) == 0 then "DELIVERY_FAILED"
        elif has($tt; "ALL") or (has($tt; "ACCEPT") and has($tt; "REJECT")) then "COVERED"
        elif $tt == ["ACCEPT"] then "ACCEPT_ONLY"
        elif $tt == ["REJECT"] then "REJECT_ONLY"
        else "UNKNOWN" end ) as $status
    | { profile: $profile, account: $account, region: $region,
        vpc_id: $v.VpcId, vpc_name: ($v | tag("Name")), cidr: ($v.CidrBlock // ""),
        is_default: ($v.IsDefault // false), vpc_state: ($v.State // ""),
        coverage_status: $status,
        flow_log_count: ($mine | length), active_flow_log_count: ($active | length),
        flow_log_ids: ([ $mine[].flow_log_id ] | join(" ")),
        traffic_types: ([ $mine[].traffic_type ] | unique | join(" ")),
        destination_types: ([ $mine[].log_destination_type ] | unique | join(" ")),
        destinations: ([ $mine[].log_destination ] | unique | join(" ")),
        flow_log_status: ([ $mine[].flow_log_status ] | unique | join(" ")),
        deliver_logs_status: ([ $mine[].deliver_logs_status ] | unique | join(" ")),
        deliver_logs_error: ([ $mine[].deliver_logs_error | select(. != "") ] | unique | join(" | ")),
        max_aggregation_interval: ([ $mine[].max_aggregation_interval | tostring ] | unique | join(" ")),
        partial_coverage: ([ $partial[] | "\(.resource_kind):\(.resource_id)(\(.traffic_type))" ] | join(" ")) } ] as $cov
| { flows: $flows,
    coverage: $cov,
    findings: [ $cov[] | select(.coverage_status != "COVERED")
      | . as $c
      | ( if .coverage_status == "NO_FLOW_LOG" then
            {severity: "High", issue: "VPC has no VPC-level flow log",
             recommendation: "Enable a VPC flow log with TrafficType=ALL to S3, CloudWatch Logs or Firehose"}
          elif .coverage_status == "INACTIVE" then
            {severity: "High", issue: "VPC flow log exists but is not ACTIVE (status: \(.flow_log_status))",
             recommendation: "Recreate the flow log and confirm FlowLogStatus=ACTIVE"}
          elif .coverage_status == "DELIVERY_FAILED" then
            {severity: "High", issue: "VPC flow log delivery is failing (\(.deliver_logs_error))",
             recommendation: "Fix the destination policy, IAM role or bucket/log group so DeliverLogsStatus=SUCCESS"}
          elif .coverage_status == "ACCEPT_ONLY" then
            {severity: "Medium", issue: "Flow log captures ACCEPT traffic only; rejected traffic (scans, blocked attempts) is not logged",
             recommendation: "Recreate the flow log with TrafficType=ALL"}
          elif .coverage_status == "REJECT_ONLY" then
            {severity: "Medium", issue: "Flow log captures REJECT traffic only; accepted traffic (data flows, exfiltration paths) is not logged",
             recommendation: "Recreate the flow log with TrafficType=ALL"}
          else
            {severity: "Low", issue: "Flow log coverage could not be determined",
             recommendation: "Review the flow log configuration manually"}
          end ) as $f
      | { severity: $f.severity, profile, account, region, vpc_id, vpc_name, is_default, coverage_status,
          flow_log_ids, traffic_types, destination_types, destinations,
          issue: $f.issue, recommendation: $f.recommendation,
          evidence: ( (if .is_default then "Default VPC. " else "" end)
                    + (if .partial_coverage != "" then "Partial subnet/ENI-level logs: " + .partial_coverage else "" end) ) } ] }
JQ
)

err_code() {
  local c
  c=$(grep -oE '\([A-Za-z.]+\)' "$1" 2>/dev/null | head -1 | tr -d '()')
  echo "${c:-Error}"
}

run_aws() {  # OUTFILE PROFILE REGION <aws args...>
  local out=$1 profile=$2 region=$3; shift 3
  printf '%s\t%s\t%s\taws %s --profile %s --region %s --output json\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$profile" "$region" "$*" "$profile" "$region" >> "$CMDLOG"
  if aws "$@" --profile "$profile" --region "$region" --output json </dev/null >"$out" 2>"$out.err"; then
    rm -f "$out.err"; return 0
  fi
  return 1
}

record_err() {  # profile account region step errfile
  jq -nc --arg p "$1" --arg a "$2" --arg r "$3" --arg s "$4" --arg c "$(err_code "$5")" \
         --arg m "$(head -c 400 "$5" 2>/dev/null | tr '\n' ' ')" \
    '{profile:$p, account:$a, region:$r, step:$s, error_code:$c, message:$m}' >> "$ERRS"
  rm -f "$5"
}

audit_region() {
  local profile=$1 account=$2 region=$3 d a ids n k chunk
  d="$OUTDIR/raw/$(printf '%s' "$profile" | tr '/ ' '__')/$region"
  a="$WORK/analysis.$IDX.json"
  mkdir -p "$d"

  run_aws "$d/vpcs.json" "$profile" "$region" ec2 describe-vpcs \
    || { record_err "$profile" "$account" "$region" "ec2 describe-vpcs" "$d/vpcs.json.err"; return; }
  run_aws "$d/flow-logs.json" "$profile" "$region" ec2 describe-flow-logs \
    || { record_err "$profile" "$account" "$region" "ec2 describe-flow-logs" "$d/flow-logs.json.err"; return; }

  # Map subnet- and ENI-level flow logs back to their VPC (only when any exist)
  echo '{}' > "$d/subnets.json"; echo '{}' > "$d/network-interfaces.json"
  if jq -e '[.FlowLogs[]? | select(.ResourceId | startswith("subnet-"))] | length > 0' "$d/flow-logs.json" >/dev/null; then
    run_aws "$d/subnets.json" "$profile" "$region" ec2 describe-subnets \
      || { record_err "$profile" "$account" "$region" "ec2 describe-subnets" "$d/subnets.json.err"; echo '{}' > "$d/subnets.json"; }
  fi
  ids=( $(jq -r '.FlowLogs[]? | select(.ResourceId | startswith("eni-")) | .ResourceId' "$d/flow-logs.json") )
  n=${#ids[@]}
  if [ "$n" -gt 0 ]; then
    k=0
    while [ $k -lt $n ]; do
      chunk=$(IFS=,; echo "${ids[*]:$k:$CHUNK}")
      run_aws "$d/eni.part$k.json" "$profile" "$region" ec2 describe-network-interfaces \
        --filters "Name=network-interface-id,Values=$chunk" \
        || record_err "$profile" "$account" "$region" "ec2 describe-network-interfaces" "$d/eni.part$k.json.err"
      k=$((k + CHUNK))
    done
    jq -s '{NetworkInterfaces: (map(.NetworkInterfaces // []) | add // [])}' "$d"/eni.part*.json \
      > "$d/network-interfaces.json" 2>/dev/null || echo '{}' > "$d/network-interfaces.json"
    rm -f "$d"/eni.part*.json
  fi

  if ! jq -n --arg profile "$profile" --arg account "$account" --arg region "$region" \
          --argjson skip_default "$SKIP_DEFAULT" \
          --slurpfile vpcs "$d/vpcs.json" --slurpfile fl "$d/flow-logs.json" \
          --slurpfile sn "$d/subnets.json" --slurpfile eni "$d/network-interfaces.json" \
          "$ANALYZE_JQ" > "$a" 2>"$a.err"; then
    echo "[$profile/$region] analysis failed: $(cat "$a.err")" >&2; return
  fi
  jq -c '.flows[]'    "$a" >> "$FLOWS"
  jq -c '.coverage[]' "$a" >> "$COV"
  jq -c '.findings[]' "$a" >> "$FINDS"
}

audit_profile() {
  local profile=$1 account regions region home errf
  CMDLOG="$WORK/p$IDX.cmd.log"; FLOWS="$WORK/p$IDX.flows.jsonl"; COV="$WORK/p$IDX.cov.jsonl"
  FINDS="$WORK/p$IDX.findings.jsonl"; ERRS="$WORK/p$IDX.errors.jsonl"
  : > "$CMDLOG"; : > "$FLOWS"; : > "$COV"; : > "$FINDS"; : > "$ERRS"
  errf="$WORK/p$IDX.err"

  if ! account=$(aws sts get-caller-identity --profile "$profile" --query Account --output text </dev/null 2>"$errf"); then
    record_err "$profile" "" "" "sts get-caller-identity" "$errf"
    echo "[$profile] cannot authenticate. Skipped (try: aws sso login --profile $profile)." >&2
    return
  fi

  if [ -n "$REGIONS" ]; then
    regions=$REGIONS
  else
    home=$(aws configure get region --profile "$profile" 2>/dev/null)
    if ! regions=$(aws ec2 describe-regions --profile "$profile" --region "${home:-us-east-1}" \
                     --query 'Regions[].RegionName' --output text </dev/null 2>"$errf"); then
      record_err "$profile" "$account" "" "ec2 describe-regions (use -r)" "$errf"
      echo "[$profile] cannot list regions. Use -r to name them." >&2
      return
    fi
  fi

  echo "[$profile] account $account: scanning $(echo $regions | wc -w | tr -d ' ') regions..." >&2
  for region in $regions; do audit_region "$profile" "$account" "$region"; done
  echo "[$profile] done." >&2
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
i=0
for p in "${PROFILES[@]}"; do
  ( IDX=$i; audit_profile "$p" ) &
  i=$((i + 1))
done
wait

merge() { local j=0; for _ in "${PROFILES[@]}"; do cat "$WORK/p$j.$1" 2>/dev/null; j=$((j + 1)); done; }
merge flows.jsonl    > "$WORK/all.flows.jsonl"
merge cov.jsonl      > "$WORK/all.cov.jsonl"
merge findings.jsonl > "$WORK/all.findings.jsonl"
merge errors.jsonl   > "$WORK/all.errors.jsonl"
{ printf 'timestamp_utc\tprofile\tregion\tcommand\n'; merge cmd.log; } > "$OUTDIR/commands.log"

to_csv() {  # JSONL OUT "col1 col2 ..."
  local cols; cols=$(printf '%s\n' $3 | jq -R . | jq -s -c .)
  { printf '%s\n' "$3" | tr ' ' ','
    jq -r --argjson c "$cols" '[ .[$c[]] | if . == null then "" else tostring end ] | @csv' "$1"
  } > "$2"
}

to_csv "$WORK/all.cov.jsonl" "$OUTDIR/flowlog_coverage.csv" \
  "profile account region vpc_id vpc_name cidr is_default vpc_state coverage_status flow_log_count active_flow_log_count flow_log_ids traffic_types destination_types destinations flow_log_status deliver_logs_status deliver_logs_error max_aggregation_interval partial_coverage"

to_csv "$WORK/all.flows.jsonl" "$OUTDIR/flow_logs.csv" \
  "profile account region flow_log_id resource_id resource_kind vpc_id log_destination log_destination_type traffic_type flow_log_status deliver_logs_status deliver_logs_error max_aggregation_interval log_format deliver_logs_permission_arn creation_time"

jq -c 'select(.coverage_status == "NO_FLOW_LOG" or .coverage_status == "INACTIVE" or .coverage_status == "DELIVERY_FAILED")' \
  "$WORK/all.cov.jsonl" > "$WORK/missing.jsonl"
to_csv "$WORK/missing.jsonl" "$OUTDIR/missing_vpcs.csv" \
  "profile account region vpc_id vpc_name cidr is_default coverage_status flow_log_ids deliver_logs_error partial_coverage"

jq -s -c 'def rank: {"Critical":0,"High":1,"Medium":2,"Low":3}[.] // 9;
          sort_by((.severity | rank), .profile, .region, .vpc_id)
          | to_entries[] | .value + {finding_id: ("F-" + ((.key + 1) | tostring | ("0000" + .)[-4:])), status: "Open"}' \
   "$WORK/all.findings.jsonl" > "$WORK/all.findings.sorted.jsonl"
to_csv "$WORK/all.findings.sorted.jsonl" "$OUTDIR/findings.csv" \
  "finding_id severity status profile account region vpc_id vpc_name is_default coverage_status flow_log_ids traffic_types destination_types destinations issue recommendation evidence"

to_csv "$WORK/all.errors.jsonl" "$OUTDIR/errors.csv" "profile account region step error_code message"

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
lines() { wc -l < "$1" | tr -d ' '; }
NVPC=$(lines "$WORK/all.cov.jsonl"); NFL=$(lines "$WORK/all.flows.jsonl")
NMISS=$(lines "$WORK/missing.jsonl"); NFIND=$(lines "$WORK/all.findings.jsonl"); NERR=$(lines "$WORK/all.errors.jsonl")

{
  echo "VPC Flow Log coverage audit"
  echo "Run (UTC):  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Profiles:   ${PROFILES[*]}"
  [ "$SKIP_DEFAULT" = true ] && echo "Default VPCs excluded"
  echo
  echo "VPCs assessed:            $NVPC"
  echo "Flow logs found:          $NFL"
  if [ "$NVPC" -gt 0 ]; then
    echo "Coverage:"
    jq -s -r 'group_by(.coverage_status) | map("  \(.[0].coverage_status): \(length)") | .[]' "$WORK/all.cov.jsonl"
  fi
  if [ "$NFL" -gt 0 ]; then
    echo "Destination types:"
    jq -s -r 'group_by(.log_destination_type) | map("  \(.[0].log_destination_type): \(length)") | .[]' "$WORK/all.flows.jsonl"
  fi
  echo "VPCs missing flow logs:   $NMISS"
  echo "Findings:                 $NFIND"
  jq -s -r 'def rank: {"Critical":0,"High":1,"Medium":2,"Low":3}[.] // 9;
            group_by(.severity) | sort_by(.[0].severity | rank) | map("  \(.[0].severity): \(length)") | .[]' \
     "$WORK/all.findings.jsonl"
  echo "API errors:               $NERR"
} | tee "$OUTDIR/summary.txt"

if [ "$NFIND" -gt 0 ]; then
  echo
  { printf 'ID\tSEV\tPROFILE\tREGION\tVPC\tSTATUS\tDEFAULT\n'
    jq -r '[.finding_id, .severity, .profile, .region, .vpc_id, .coverage_status, (.is_default | tostring)] | @tsv' \
      "$WORK/all.findings.sorted.jsonl"
  } | if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi
fi
echo
echo "Evidence: $OUTDIR/"

if   [ "$NFIND" -gt 0 ]; then exit 1
elif [ "$NERR" -gt 0 ];  then exit 2
else                          exit 0
fi
