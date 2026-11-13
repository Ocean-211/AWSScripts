#!/usr/bin/env bash
#
# public_subnet_eni_audit.sh - TC1: public-subnet inventory and ENI placement review.
#
# For every profile x region:
#   1. aws ec2 describe-route-tables + describe-subnets
#      A subnet is public when its effective route table (explicit association,
#      otherwise the VPC's main route table) has a route with GatewayId igw-*.
#   2. aws ec2 describe-network-interfaces --filters Name=subnet-id,Values=<public subnets>
#   3. Each ENI is mapped to its resource (EC2, RDS, ELB, Lambda, NAT GW, VPC endpoint,
#      ECS, EFS, ElastiCache, ...). It uses elbv2/elb describe-load-balancers to resolve
#      the LB scheme and rds describe-db-instances to resolve the DB.
#   4. Unexpected placements become findings. NAT gateways and internet-facing
#      load balancers count as expected. Everything else is flagged unless it is allowlisted.
#
# Evidence written to the output directory:
#   public_subnets.csv   public-subnet inventory
#   eni_matrix.csv       every ENI in a public subnet, mapped to its resource
#   findings.csv         unexpected placements, with severity (opens in Excel or Sheets)
#   errors.csv           API calls that failed (permissions, expired SSO, and so on)
#   commands.log         every AWS CLI command run, with a timestamp
#   raw/<profile>/<region>/*.json   the raw API responses
#
# The script is read-only. It needs the AWS CLI (v1 or v2), jq 1.6 or later, and bash 3.2 or later.
#
# Usage:
#   ./public_subnet_eni_audit.sh                         # all profiles, all enabled regions
#   ./public_subnet_eni_audit.sh -p prod -p staging      # only the named profiles
#   ./public_subnet_eni_audit.sh -r us-east-1,ap-south-1 # only the named regions
#   ./public_subnet_eni_audit.sh -a allowlist.txt -o evidence_dir
#
# Allowlist file: one pattern per line ('*' wildcard, '#' comments). Each pattern is matched
# against the ENI ID, the resource ID, and "<ResourceType>:<ResourceId>". Examples:
#   i-0abc123def4567890        # approved bastion
#   EC2:i-0abc*
#   Lambda:edge-*
#   eni-0123456789abcdef0
#
# Exit codes: 0 = no findings, 1 = findings, 2 = no findings but some API errors, 3 = usage

set -uo pipefail
export AWS_PAGER=""

PROFILES=()
REGIONS=""
OUTDIR="public_subnet_audit_$(date +%Y%m%d_%H%M%S)"
ALLOW_FILE=""
CHUNK=50   # subnet IDs per describe-network-interfaces filter

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }
need_arg() { [ "$1" -ge 2 ] || { echo "Missing value for $2" >&2; usage; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--profile)   need_arg $# "$1"; PROFILES+=("$2"); shift 2 ;;
    -r|--regions)   need_arg $# "$1"; REGIONS="${2//,/ }"; shift 2 ;;
    -o|--output)    need_arg $# "$1"; OUTDIR="$2"; shift 2 ;;
    -a|--allowlist) need_arg $# "$1"; ALLOW_FILE="$2"; shift 2 ;;
    -h|--help)      usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found in PATH" >&2; exit 3; }
command -v jq  >/dev/null 2>&1 || { echo "jq not found (brew install jq / apt install jq)" >&2; exit 3; }

if [ ${#PROFILES[@]} -eq 0 ]; then
  while IFS= read -r p; do [ -n "$p" ] && PROFILES+=("$p"); done < <(aws configure list-profiles)
fi
[ ${#PROFILES[@]} -gt 0 ] || { echo "No AWS CLI profiles found" >&2; exit 3; }

ALLOW_JSON='[]'
if [ -n "$ALLOW_FILE" ]; then
  [ -f "$ALLOW_FILE" ] || { echo "Allowlist not found: $ALLOW_FILE" >&2; exit 3; }
  ALLOW_JSON=$(sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$ALLOW_FILE" \
               | grep -v '^$' | jq -R . | jq -s -c .)
fi

mkdir -p "$OUTDIR/raw" || exit 3
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# jq: work out which subnets are public (route tables + subnets -> public-subnet objects)
# ---------------------------------------------------------------------------
PUBLIC_JQ=$(cat <<'JQ'
def tag($k): [(.Tags // [])[] | select(.Key == $k) | .Value][0] // "";
($rt[0].RouteTables // []) as $rts
| [ ($sn[0].Subnets // [])[]
    | . as $s
    | ([ $rts[] | select(any(.Associations[]?; .SubnetId == $s.SubnetId)) ][0]) as $explicit
    | ($explicit // [ $rts[] | select(.VpcId == $s.VpcId and any(.Associations[]?; .Main == true)) ][0]) as $r
    | select($r != null)
    | [ ($r.Routes // [])[] | select((.GatewayId // "") | startswith("igw-")) ] as $igw
    | select($igw | length > 0)
    | { profile: $profile, account: $account, region: $region,
        vpc_id: $s.VpcId, subnet_id: $s.SubnetId, subnet_name: ($s | tag("Name")),
        availability_zone: $s.AvailabilityZone,
        ipv4_cidr: ($s.CidrBlock // ""),
        ipv6_cidr: ([ ($s.Ipv6CidrBlockAssociationSet // [])[].Ipv6CidrBlock ] | join(" ")),
        map_public_ip_on_launch: ($s.MapPublicIpOnLaunch // false),
        available_ips: ($s.AvailableIpAddressCount // ""),
        route_table_id: $r.RouteTableId,
        rt_association: (if $explicit then "explicit" else "main (implicit)" end),
        igw_id: ([ $igw[].GatewayId ] | unique | join(" ")),
        igw_destinations: ([ $igw[] | (.DestinationCidrBlock // .DestinationIpv6CidrBlock // .DestinationPrefixListId // "") ] | join(" ")),
        igw_route_state: ([ $igw[] | (.State // "") ] | unique | join(" ")),
        default_route_v4: any($igw[]; .DestinationCidrBlock == "0.0.0.0/0"),
        default_route_v6: any($igw[]; .DestinationIpv6CidrBlock == "::/0") } ]
JQ
)

# ---------------------------------------------------------------------------
# jq: map each ENI to its resource and assess the placement
# ---------------------------------------------------------------------------
ANALYZE_JQ=$(cat <<'JQ'
def glob2re: "^" + (gsub("(?<c>[.+?^${}()|\\[\\]\\\\])"; "\\\(.c)") | gsub("\\*"; ".*")) + "$";

def assess:
  .resource_type as $ty | .internet_exposed as $x |
  if $ty == "NAT Gateway" then null
  elif $ty == "ELB" then
    if .scheme == "internet-facing" then null
    elif .scheme == "internal" then
      {severity: "Low", issue: "Internal load balancer has nodes in a public subnet",
       recommendation: "Place internal load balancers in private subnets"}
    else
      {severity: "Low", issue: "Load balancer in a public subnet; scheme could not be resolved",
       recommendation: "Confirm the load balancer is meant to be internet-facing"}
    end
  elif $ty == "RDS" then
    if $x or .rds_public then
      {severity: "Critical", issue: "RDS database in a public subnet and publicly reachable (PubliclyAccessible=true or public IP)",
       recommendation: "Set PubliclyAccessible=false and rebuild the DB subnet group with private subnets only"}
    else
      {severity: "High", issue: "RDS database network interface in a public subnet",
       recommendation: "Rebuild the DB subnet group with private subnets only"}
    end
  elif any(["ElastiCache","EFS","Redshift","OpenSearch","DMS"][]; . == $ty) then
    {severity: (if $x then "Critical" else "High" end), issue: "\($ty) data-store interface in a public subnet",
     recommendation: "Move the resource to private subnets"}
  elif $ty == "EC2" then
    if $x then
      {severity: "High", issue: "EC2 instance in a public subnet with a public IP",
       recommendation: "Move it to a private subnet behind a load balancer or NAT gateway, or allowlist it if it is an approved bastion or edge host"}
    else
      {severity: "Medium", issue: "EC2 instance in a public subnet (no public IP on this ENI)",
       recommendation: "Move it to a private subnet; an Elastic IP or MapPublicIpOnLaunch could expose it later"}
    end
  elif $ty == "ECS Task" then
    {severity: (if $x then "High" else "Medium" end), issue: "ECS task (awsvpc) in a public subnet",
     recommendation: "Run tasks in private subnets with assignPublicIp=DISABLED"}
  elif $ty == "Lambda" then
    {severity: "Medium", issue: "Lambda function attached to a public subnet",
     recommendation: "Attach the function to private subnets routed through a NAT gateway. Lambda ENIs never get public IPs, so a public subnet gives no internet egress"}
  elif $ty == "VPC Endpoint" then
    {severity: "Low", issue: "Interface VPC endpoint in a public subnet",
     recommendation: "Place endpoints in private subnets"}
  elif $ty == "Unattached" then
    {severity: (if $x then "Medium" else "Low" end), issue: "Unattached ENI in a public subnet",
     recommendation: "Delete it if unused and release any associated Elastic IP"}
  else
    {severity: "Low", issue: "Unclassified ENI (\(.interface_type)) in a public subnet",
     recommendation: "Identify the owner and confirm the placement is intended"}
  end;

($allow | map(glob2re)) as $allowre
| (reduce ($pub[0] // [])[] as $p ({}; .[$p.subnet_id] = $p)) as $subnets
| ($v2[0].LoadBalancers // []) as $lbv2
| ($v1[0].LoadBalancerDescriptions // []) as $clbs
| ($rds[0].DBInstances // []) as $dbs
| [ ($eni[0].NetworkInterfaces // [])[]
    | . as $e
    | ($subnets[$e.SubnetId] // {}) as $sn
    | ($e.InterfaceType // "interface") as $t
    | ($e.Description // "") as $d
    | ($e.RequesterId // "") as $req
    | [ ($e.Groups // [])[].GroupId ] as $sgs
    | ($e.Association.PublicIp // "") as $pip
    | ([ ($e.Ipv6Addresses // [])[].Ipv6Address ] | join(" ")) as $v6
    | ( if ($d | startswith("arn:aws:ecs:")) then
          {type: "ECS Task", sub: "awsvpc", id: ($d | split("/") | last), detail: $d}
        elif ($e.Attachment.InstanceId // "") != "" then
          {type: "EC2", sub: "instance", id: $e.Attachment.InstanceId,
           detail: ("device-index=" + (($e.Attachment.DeviceIndex // "") | tostring))}
        elif $t == "lambda" or ($d | startswith("AWS Lambda VPC ENI")) then
          {type: "Lambda", sub: "function",
           id: ($d | sub("^AWS Lambda VPC ENI[-: ]*"; "")
                   | sub("-?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"; "")),
           detail: "Hyperplane ENI; functions sharing this subnet+SG set reuse it"}
        elif $d == "RDSNetworkInterface" or $req == "amazon-rds" then
          ([ $dbs[]
             | select(any(.DBSubnetGroup.Subnets[]?; .SubnetIdentifier == $e.SubnetId))
             | select(any(.VpcSecurityGroups[]?; .VpcSecurityGroupId as $g | any($sgs[]; . == $g))) ]) as $c
          | {type: "RDS", sub: "db-instance", id: ([ $c[].DBInstanceIdentifier ] | join(" ")),
             rds_public: any($c[]; .PubliclyAccessible == true),
             detail: (if ($c | length) == 0 then "No DB matched on subnet group + SG (check Aurora/DocumentDB/Neptune manually)"
                      elif ($c | length) > 1 then "Several candidate DBs share this subnet group + SG"
                      else "PubliclyAccessible=\($c[0].PubliclyAccessible)" end)}
        elif ($d | test("^ELB (app|net|gwy)/")) or $t == "network_load_balancer" or $t == "gateway_load_balancer" then
          (($d | capture("^ELB (?<k>app|net|gwy)/(?<n>[^/]+)/")) // {k: "", n: ""}) as $m
          | ([ $lbv2[] | select(.LoadBalancerName == $m.n and (.LoadBalancerArn | contains("/" + $m.k + "/"))) ][0]) as $lb
          | {type: "ELB", sub: ({"app": "ALB", "net": "NLB", "gwy": "GWLB"}[$m.k] // "ELBv2"), id: $m.n,
             scheme: ($lb.Scheme // "unknown"), detail: ("scheme=" + ($lb.Scheme // "unknown"))}
        elif ($d | startswith("ELB ")) then
          ($d | ltrimstr("ELB ")) as $n
          | ([ $clbs[] | select(.LoadBalancerName == $n) ][0]) as $lb
          | {type: "ELB", sub: "CLB", id: $n, scheme: ($lb.Scheme // "unknown"),
             detail: ("scheme=" + ($lb.Scheme // "unknown"))}
        elif $t == "nat_gateway" then
          {type: "NAT Gateway", sub: "", id: ($d | sub("^Interface for NAT Gateway "; "")), detail: ""}
        elif $t == "vpc_endpoint" or ($d | startswith("VPC Endpoint Interface")) then
          {type: "VPC Endpoint", sub: "interface", id: ($d | sub("^VPC Endpoint Interface "; "")), detail: ""}
        elif $t == "efs" or ($d | startswith("EFS mount target")) then
          {type: "EFS", sub: "mount-target", id: (($d | capture("(?<f>fs-[0-9a-f]+)") | .f) // ""), detail: $d}
        elif ($d | startswith("ElastiCache")) then
          {type: "ElastiCache", sub: "", id: ($d | sub("^ElastiCache "; "")), detail: ""}
        elif $d == "RedshiftNetworkInterface" then
          {type: "Redshift", sub: "", id: "", detail: ""}
        elif $req == "amazon-elasticsearch" or ($d | startswith("ES ")) then
          {type: "OpenSearch", sub: "", id: ($d | sub("^ES "; "")), detail: ""}
        elif $d == "DMSNetworkInterface" then
          {type: "DMS", sub: "", id: "", detail: ""}
        elif $t == "transit_gateway" then
          {type: "Transit Gateway", sub: "attachment", id: "", detail: $d}
        elif $t == "api_gateway_managed" then
          {type: "API Gateway", sub: "vpc-link", id: "", detail: $d}
        elif ($e.Status // "") == "available" then
          {type: "Unattached", sub: "", id: "", detail: $d}
        else
          {type: "Other", sub: $t, id: "", detail: $d}
        end ) as $r
    | ([ $e.NetworkInterfaceId, ($r.type + ":" + $r.id) ] + ($r.id | split(" "))) as $keys
    | ([ $allowre[] as $re | $keys[] | select(. != "") | select(test($re)) ] | length > 0) as $allowed
    | { profile: $profile, account: $account, region: $region,
        vpc_id: ($e.VpcId // ""), subnet_id: $e.SubnetId, subnet_name: ($sn.subnet_name // ""),
        availability_zone: ($e.AvailabilityZone // ""),
        eni_id: $e.NetworkInterfaceId, interface_type: $t, eni_status: ($e.Status // ""),
        private_ip: ($e.PrivateIpAddress // ""), public_ip: $pip, ipv6_addresses: $v6,
        internet_exposed: (($pip != "") or ($v6 != "" and ($sn.default_route_v6 // false))),
        security_groups: ($sgs | join(" ")),
        resource_type: $r.type, resource_subtype: ($r.sub // ""), resource_id: ($r.id // ""),
        resource_detail: ($r.detail // ""),
        requester_id: $req, requester_managed: ($e.RequesterManaged // false),
        attachment_owner: ($e.Attachment.InstanceOwnerId // ""), description: $d,
        allowlisted: $allowed, scheme: ($r.scheme // ""), rds_public: ($r.rds_public // false) }
    | . + {assessment: assess}
    | . + {placement: (if .assessment == null then "Expected" elif .allowlisted then "Allowlisted" else "Unexpected" end),
           severity: (.assessment.severity // "")}
  ] as $rows
| { enis: [ $rows[] | del(.scheme, .rds_public, .assessment) ],
    findings: [ $rows[] | select(.placement == "Unexpected")
                | { severity, profile, account, region, vpc_id, subnet_id, subnet_name, eni_id,
                    resource_type, resource_subtype, resource_id, public_ip, internet_exposed,
                    security_groups, issue: .assessment.issue, recommendation: .assessment.recommendation,
                    evidence: (.resource_detail) } ] }
JQ
)

err_code() {
  local c
  c=$(grep -oE '\([A-Za-z]+\)' "$1" 2>/dev/null | head -1 | tr -d '()')
  echo "${c:-Error}"
}

# run_aws OUTFILE PROFILE REGION <aws args...>   (logs the command and writes JSON to OUTFILE)
run_aws() {
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
  local profile=$1 account=$2 region=$3 d n k chunk ids a
  a="$ENIS.analysis.json"
  d="$OUTDIR/raw/$(printf '%s' "$profile" | tr '/ ' '__')/$region"
  mkdir -p "$d"

  run_aws "$d/route-tables.json" "$profile" "$region" ec2 describe-route-tables \
    || { record_err "$profile" "$account" "$region" "ec2 describe-route-tables" "$d/route-tables.json.err"; return; }
  run_aws "$d/subnets.json" "$profile" "$region" ec2 describe-subnets \
    || { record_err "$profile" "$account" "$region" "ec2 describe-subnets" "$d/subnets.json.err"; return; }

  jq -n --arg profile "$profile" --arg account "$account" --arg region "$region" \
        --slurpfile rt "$d/route-tables.json" --slurpfile sn "$d/subnets.json" \
        "$PUBLIC_JQ" > "$d/public-subnets.json"
  jq -c '.[]' "$d/public-subnets.json" >> "$SUBNETS"

  ids=( $(jq -r '.[].subnet_id' "$d/public-subnets.json") )
  n=${#ids[@]}
  [ "$n" -eq 0 ] && return

  # describe-network-interfaces filtered on the public subnets, in chunks
  k=0
  while [ $k -lt $n ]; do
    chunk=$(IFS=,; echo "${ids[*]:$k:$CHUNK}")
    run_aws "$d/network-interfaces.part$k.json" "$profile" "$region" \
      ec2 describe-network-interfaces --filters "Name=subnet-id,Values=$chunk" \
      || record_err "$profile" "$account" "$region" "ec2 describe-network-interfaces" "$d/network-interfaces.part$k.json.err"
    k=$((k + CHUNK))
  done
  jq -s '{NetworkInterfaces: (map(.NetworkInterfaces // []) | add // [])}' \
     "$d"/network-interfaces.part*.json > "$d/network-interfaces.json" 2>/dev/null \
     || echo '{"NetworkInterfaces":[]}' > "$d/network-interfaces.json"
  rm -f "$d"/network-interfaces.part*.json

  # Look up load balancers and RDS only when the ENIs show they are needed
  echo '{}' > "$d/elbv2-load-balancers.json"; echo '{}' > "$d/elb-load-balancers.json"; echo '{}' > "$d/rds-db-instances.json"
  if jq -e '[.NetworkInterfaces[] | select((.Description // "" | startswith("ELB ")) or (.InterfaceType // "" | test("load_balancer")))] | length > 0' \
       "$d/network-interfaces.json" >/dev/null; then
    run_aws "$d/elbv2-load-balancers.json" "$profile" "$region" elbv2 describe-load-balancers \
      || { record_err "$profile" "$account" "$region" "elbv2 describe-load-balancers" "$d/elbv2-load-balancers.json.err"; echo '{}' > "$d/elbv2-load-balancers.json"; }
    run_aws "$d/elb-load-balancers.json" "$profile" "$region" elb describe-load-balancers \
      || { record_err "$profile" "$account" "$region" "elb describe-load-balancers" "$d/elb-load-balancers.json.err"; echo '{}' > "$d/elb-load-balancers.json"; }
  fi
  if jq -e '[.NetworkInterfaces[] | select(.Description == "RDSNetworkInterface" or .RequesterId == "amazon-rds")] | length > 0' \
       "$d/network-interfaces.json" >/dev/null; then
    run_aws "$d/rds-db-instances.json" "$profile" "$region" rds describe-db-instances \
      || { record_err "$profile" "$account" "$region" "rds describe-db-instances" "$d/rds-db-instances.json.err"; echo '{}' > "$d/rds-db-instances.json"; }
  fi

  jq -n --arg profile "$profile" --arg account "$account" --arg region "$region" \
        --argjson allow "$ALLOW_JSON" \
        --slurpfile pub "$d/public-subnets.json" --slurpfile eni "$d/network-interfaces.json" \
        --slurpfile v2 "$d/elbv2-load-balancers.json" --slurpfile v1 "$d/elb-load-balancers.json" \
        --slurpfile rds "$d/rds-db-instances.json" \
        "$ANALYZE_JQ" > "$a" 2>"$a.err" || {
          echo "[$profile/$region] analysis failed: $(cat "$a.err")" >&2; rm -f "$a" "$a.err"; return; }
  rm -f "$a.err"
  jq -c '.enis[]' "$a" >> "$ENIS"
  jq -c '.findings[]' "$a" >> "$FINDS"
  rm -f "$a"
}

audit_profile() {
  local profile=$1 idx=$2 account regions region home errf
  CMDLOG="$WORK/p$idx.cmd.log"; SUBNETS="$WORK/p$idx.subnets.jsonl"; ENIS="$WORK/p$idx.enis.jsonl"
  FINDS="$WORK/p$idx.findings.jsonl"; ERRS="$WORK/p$idx.errors.jsonl"
  : > "$CMDLOG"; : > "$SUBNETS"; : > "$ENIS"; : > "$FINDS"; : > "$ERRS"
  errf="$WORK/p$idx.sts.err"

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
  for region in $regions; do
    audit_region "$profile" "$account" "$region"
  done
  echo "[$profile] done." >&2
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
i=0
for p in "${PROFILES[@]}"; do
  ( audit_profile "$p" "$i" ) &
  i=$((i + 1))
done
wait

merge() { local suffix=$1 j=0; for _ in "${PROFILES[@]}"; do cat "$WORK/p$j.$suffix" 2>/dev/null; j=$((j + 1)); done; }

merge subnets.jsonl  > "$WORK/all.subnets.jsonl"
merge enis.jsonl     > "$WORK/all.enis.jsonl"
merge findings.jsonl > "$WORK/all.findings.jsonl"
merge errors.jsonl   > "$WORK/all.errors.jsonl"
{ printf 'timestamp_utc\tprofile\tregion\tcommand\n'; merge cmd.log; } > "$OUTDIR/commands.log"

# to_csv JSONL OUT "col1 col2 ..."
to_csv() {
  local cols; cols=$(printf '%s\n' $3 | jq -R . | jq -s -c .)
  { printf '%s\n' "$3" | tr ' ' ','
    jq -r --argjson c "$cols" '[ .[$c[]] | if . == null then "" else tostring end ] | @csv' "$1"
  } > "$2"
}

to_csv "$WORK/all.subnets.jsonl" "$OUTDIR/public_subnets.csv" \
  "profile account region vpc_id subnet_id subnet_name availability_zone ipv4_cidr ipv6_cidr map_public_ip_on_launch available_ips route_table_id rt_association igw_id igw_destinations igw_route_state"

to_csv "$WORK/all.enis.jsonl" "$OUTDIR/eni_matrix.csv" \
  "profile account region vpc_id subnet_id subnet_name availability_zone eni_id interface_type eni_status private_ip public_ip ipv6_addresses internet_exposed security_groups resource_type resource_subtype resource_id resource_detail requester_id requester_managed attachment_owner description placement severity allowlisted"

# Findings: sort by severity, then number them F-0001...
jq -s -c 'def rank: {"Critical":0,"High":1,"Medium":2,"Low":3}[.] // 9;
          sort_by((.severity | rank), .profile, .region, .subnet_id)
          | to_entries[] | .value + {finding_id: ("F-" + ((.key + 1) | tostring | ("0000" + .)[-4:])), status: "Open"}' \
   "$WORK/all.findings.jsonl" > "$WORK/all.findings.sorted.jsonl"
to_csv "$WORK/all.findings.sorted.jsonl" "$OUTDIR/findings.csv" \
  "finding_id severity status profile account region vpc_id subnet_id subnet_name eni_id resource_type resource_subtype resource_id public_ip internet_exposed security_groups issue recommendation evidence"

to_csv "$WORK/all.errors.jsonl" "$OUTDIR/errors.csv" "profile account region step error_code message"

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
lines() { wc -l < "$1" | tr -d ' '; }
NSUB=$(lines "$WORK/all.subnets.jsonl"); NENI=$(lines "$WORK/all.enis.jsonl")
NFIND=$(lines "$WORK/all.findings.jsonl"); NERR=$(lines "$WORK/all.errors.jsonl")
NALLOW=$(jq -s '[.[] | select(.placement == "Allowlisted")] | length' "$WORK/all.enis.jsonl")

{
  echo "TC1 - Public subnet ENI placement audit"
  echo "Run (UTC):  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Profiles:   ${PROFILES[*]}"
  echo
  echo "Public subnets:           $NSUB"
  echo "ENIs in public subnets:   $NENI"
  echo "Allowlisted placements:   $NALLOW"
  echo "Findings:                 $NFIND"
  jq -s -r 'def rank: {"Critical":0,"High":1,"Medium":2,"Low":3}[.] // 9;
            group_by(.severity) | sort_by(.[0].severity | rank) | map("  \(.[0].severity): \(length)") | .[]' \
     "$WORK/all.findings.jsonl"
  echo "API errors:               $NERR"
  echo
  echo "ENIs by resource type:"
  jq -s -r 'group_by(.resource_type) | map("  \(.[0].resource_type): \(length)") | .[]' "$WORK/all.enis.jsonl"
} | tee "$OUTDIR/summary.txt"

if [ "$NFIND" -gt 0 ]; then
  echo
  { printf 'ID\tSEV\tPROFILE\tREGION\tSUBNET\tTYPE\tRESOURCE\tPUBLIC_IP\n'
    jq -r '[.finding_id, .severity, .profile, .region, .subnet_id, .resource_type,
            (if .resource_id == "" then "-" else .resource_id end),
            (if .public_ip == "" then "-" else .public_ip end)] | @tsv' "$WORK/all.findings.sorted.jsonl"
  } | if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi
fi
echo
echo "Evidence: $OUTDIR/"

if   [ "$NFIND" -gt 0 ]; then exit 1
elif [ "$NERR" -gt 0 ];  then exit 2
else                          exit 0
fi
