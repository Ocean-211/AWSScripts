#!/usr/bin/env bash
#
# enumerate-aws-iam.sh
#
# Fault-tolerant enumeration of IAM roles, role trust policies, attached
# managed policies, inline policies and customer-managed policies across
# every profile configured in the local AWS CLI.
#
# Design goals:
#   - Never abort the whole run because one API call is denied
#   - Never write a truncated/empty JSON file on failure
#   - Clearly distinguish SUCCESS / EMPTY / DENIED / ERROR per operation
#   - Produce a machine-readable status log for audit evidence
#
# Usage:
#   ./enumerate-aws-iam.sh [output-directory] [profile1 profile2 ...]
#
# Requirements: aws cli v2, jq
#

set -uo pipefail

############################################################################
# Configuration
############################################################################

OUTPUT_ROOT="${1:-aws-iam-enumeration}"
shift || true

export AWS_PAGER=""
export AWS_RETRY_MODE="standard"
export AWS_MAX_ATTEMPTS="5"

# Seconds before an individual AWS call is abandoned
CLI_READ_TIMEOUT="30"
CLI_CONNECT_TIMEOUT="10"

RUN_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

############################################################################
# Pre-flight checks
############################################################################

for BINARY in aws jq; do
    if ! command -v "$BINARY" >/dev/null 2>&1; then
        echo "[FATAL] Required binary not found: $BINARY" >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_ROOT"

STATUS_LOG="$OUTPUT_ROOT/enumeration-status.csv"
RUN_LOG="$OUTPUT_ROOT/run.log"

if [[ ! -f "$STATUS_LOG" ]]; then
    echo '"Timestamp","Profile","AccountId","Operation","Target","Status","Detail"' > "$STATUS_LOG"
fi

############################################################################
# Logging helpers
############################################################################

log() {
    local level="$1"; shift
    local message="$*"
    local stamp
    stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[$level] $message"
    echo "$stamp [$level] $message" >> "$RUN_LOG"
}

csv_escape() {
    printf '%s' "${1//\"/\"\"}"
}

# record_status <profile> <account> <operation> <target> <status> <detail>
record_status() {
    local profile="$1" account="$2" operation="$3"
    local target="$4" status="$5" detail="$6"

    detail="$(printf '%s' "$detail" | tr '\n' ' ' | cut -c1-500)"

    printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
        "$(csv_escape "$RUN_TIMESTAMP")" \
        "$(csv_escape "$profile")" \
        "$(csv_escape "$account")" \
        "$(csv_escape "$operation")" \
        "$(csv_escape "$target")" \
        "$(csv_escape "$status")" \
        "$(csv_escape "$detail")" \
        >> "$STATUS_LOG"
}

############################################################################
# Core fault-tolerant AWS invocation
#
# run_aws <operation> <target> <output_file> -- <aws command...>
#
# Returns:
#   0 -> success, output_file contains valid JSON
#   1 -> failure, output_file NOT created, status recorded
############################################################################

CURRENT_PROFILE=""
CURRENT_ACCOUNT=""
PROFILE_DENIED=0
PROFILE_ERRORS=0
PROFILE_SUCCESS=0

run_aws() {
    local operation="$1"
    local target="$2"
    local output_file="$3"
    shift 3

    if [[ "${1:-}" == "--" ]]; then
        shift
    fi

    local tmp_out tmp_err
    tmp_out="${output_file}.tmp"
    tmp_err="${output_file}.err"

    mkdir -p "$(dirname "$output_file")"

    if "$@" \
        --cli-read-timeout "$CLI_READ_TIMEOUT" \
        --cli-connect-timeout "$CLI_CONNECT_TIMEOUT" \
        --output json \
        > "$tmp_out" 2> "$tmp_err"; then

        # Validate JSON before accepting the file
        if jq empty "$tmp_out" >/dev/null 2>&1; then
            mv "$tmp_out" "$output_file"
            rm -f "$tmp_err"
            PROFILE_SUCCESS=$((PROFILE_SUCCESS + 1))
            record_status "$CURRENT_PROFILE" "$CURRENT_ACCOUNT" \
                "$operation" "$target" "SUCCESS" ""
            return 0
        fi

        rm -f "$tmp_out"
        local detail
        detail="$(cat "$tmp_err" 2>/dev/null)"
        rm -f "$tmp_err"
        PROFILE_ERRORS=$((PROFILE_ERRORS + 1))
        log "WARN" "Invalid JSON returned: $operation ($target)"
        record_status "$CURRENT_PROFILE" "$CURRENT_ACCOUNT" \
            "$operation" "$target" "INVALID_JSON" "$detail"
        return 1
    fi

    local error_text
    error_text="$(cat "$tmp_err" 2>/dev/null)"
    rm -f "$tmp_out" "$tmp_err"

    local status="ERROR"
    case "$error_text" in
        *AccessDenied*|*"not authorized"*|*UnauthorizedOperation*|*AuthorizationError*)
            status="ACCESS_DENIED"
            PROFILE_DENIED=$((PROFILE_DENIED + 1))
            ;;
        *ExpiredToken*|*InvalidClientTokenId*|*TokenRefreshRequired*|*SSOError*|*"credentials"*)
            status="CREDENTIAL_FAILURE"
            PROFILE_ERRORS=$((PROFILE_ERRORS + 1))
            ;;
        *Throttling*|*RequestLimitExceeded*|*TooManyRequests*)
            status="THROTTLED"
            PROFILE_ERRORS=$((PROFILE_ERRORS + 1))
            ;;
        *NoSuchEntity*)
            status="NOT_FOUND"
            ;;
        *)
            PROFILE_ERRORS=$((PROFILE_ERRORS + 1))
            ;;
    esac

    log "SKIP" "$status :: $operation :: $target"
    record_status "$CURRENT_PROFILE" "$CURRENT_ACCOUNT" \
        "$operation" "$target" "$status" "$error_text"
    return 1
}

# Safe jq read: returns empty string instead of failing when file is absent
jq_safe() {
    local filter="$1" file="$2"
    [[ -f "$file" ]] || return 0
    jq -r "$filter" "$file" 2>/dev/null || true
}

# Filesystem-safe name
sanitize() {
    printf '%s' "$1" | tr '/:\\ ' '____'
}

############################################################################
# Profile discovery
############################################################################

if [[ $# -gt 0 ]]; then
    PROFILES=("$@")
else
    mapfile -t PROFILES < <(aws configure list-profiles 2>/dev/null)
fi

if [[ "${#PROFILES[@]}" -eq 0 ]]; then
    log "FATAL" "No AWS CLI profiles found."
    exit 1
fi

log "INFO" "Output directory: $OUTPUT_ROOT"
log "INFO" "Profiles to process: ${#PROFILES[@]} (${PROFILES[*]})"

############################################################################
# Per-profile enumeration
############################################################################

process_role() {
    local profile="$1" role_name="$2" role_dir="$3"

    local this_role_dir="$role_dir/$(sanitize "$role_name")"
    mkdir -p "$this_role_dir"

    # --- Role detail (trust policy, permissions boundary, tags) ---------
    run_aws "iam:GetRole" "$role_name" \
        "$this_role_dir/role-details.json" -- \
        aws iam get-role --profile "$profile" --role-name "$role_name" || true

    # --- Attached managed policies --------------------------------------
    if run_aws "iam:ListAttachedRolePolicies" "$role_name" \
        "$this_role_dir/attached-managed-policies.json" -- \
        aws iam list-attached-role-policies \
            --profile "$profile" --role-name "$role_name"; then

        local attached_arns
        attached_arns="$(jq_safe '.AttachedPolicies[]?.PolicyArn' \
            "$this_role_dir/attached-managed-policies.json")"

        if [[ -z "$attached_arns" ]]; then
            record_status "$profile" "$CURRENT_ACCOUNT" \
                "iam:ListAttachedRolePolicies" "$role_name" "EMPTY" \
                "No managed policies attached"
        fi

        local policy_arn policy_name safe_name meta_file version_id
        while IFS= read -r policy_arn; do
            [[ -n "$policy_arn" ]] || continue
            policy_name="${policy_arn##*/}"
            safe_name="$(sanitize "$policy_name")"
            meta_file="$this_role_dir/attached-managed-policies/${safe_name}-metadata.json"

            run_aws "iam:GetPolicy" "$policy_arn" "$meta_file" -- \
                aws iam get-policy --profile "$profile" \
                    --policy-arn "$policy_arn" || continue

            version_id="$(jq_safe '.Policy.DefaultVersionId' "$meta_file")"
            [[ -n "$version_id" ]] || continue

            run_aws "iam:GetPolicyVersion" "$policy_arn ($version_id)" \
                "$this_role_dir/attached-managed-policies/${safe_name}-permissions.json" -- \
                aws iam get-policy-version --profile "$profile" \
                    --policy-arn "$policy_arn" --version-id "$version_id" || true
        done <<< "$attached_arns"
    fi

    # --- Inline policies -------------------------------------------------
    if run_aws "iam:ListRolePolicies" "$role_name" \
        "$this_role_dir/inline-policies.json" -- \
        aws iam list-role-policies \
            --profile "$profile" --role-name "$role_name"; then

        local inline_names
        inline_names="$(jq_safe '.PolicyNames[]?' \
            "$this_role_dir/inline-policies.json")"

        if [[ -z "$inline_names" ]]; then
            record_status "$profile" "$CURRENT_ACCOUNT" \
                "iam:ListRolePolicies" "$role_name" "EMPTY" \
                "No inline policies present"
        fi

        local inline_name safe_inline
        while IFS= read -r inline_name; do
            [[ -n "$inline_name" ]] || continue
            safe_inline="$(sanitize "$inline_name")"

            run_aws "iam:GetRolePolicy" "$role_name/$inline_name" \
                "$this_role_dir/inline-policies/${safe_inline}-permissions.json" -- \
                aws iam get-role-policy --profile "$profile" \
                    --role-name "$role_name" \
                    --policy-name "$inline_name" || true
        done <<< "$inline_names"
    fi

    # --- Instance profiles ----------------------------------------------
    run_aws "iam:ListInstanceProfilesForRole" "$role_name" \
        "$this_role_dir/instance-profiles.json" -- \
        aws iam list-instance-profiles-for-role \
            --profile "$profile" --role-name "$role_name" || true
}

process_managed_policies() {
    local profile="$1" profile_dir="$2" scope="$3" subdir="$4"

    local list_file="$profile_dir/${subdir}-list.json"
    local base_dir="$profile_dir/$subdir"

    if ! run_aws "iam:ListPolicies(scope=$scope)" "$profile" \
        "$list_file" -- \
        aws iam list-policies --profile "$profile" --scope "$scope"; then
        return 1
    fi

    local arns
    arns="$(jq_safe '.Policies[]?.Arn' "$list_file")"

    if [[ -z "$arns" ]]; then
        record_status "$profile" "$CURRENT_ACCOUNT" \
            "iam:ListPolicies(scope=$scope)" "$profile" "EMPTY" \
            "No policies returned for scope $scope"
        return 0
    fi

    local policy_arn policy_name safe_name policy_dir version_id
    while IFS= read -r policy_arn; do
        [[ -n "$policy_arn" ]] || continue
        policy_name="${policy_arn##*/}"
        safe_name="$(sanitize "$policy_name")"
        policy_dir="$base_dir/$safe_name"

        run_aws "iam:GetPolicy" "$policy_arn" \
            "$policy_dir/metadata.json" -- \
            aws iam get-policy --profile "$profile" \
                --policy-arn "$policy_arn" || continue

        version_id="$(jq_safe '.Policy.DefaultVersionId' "$policy_dir/metadata.json")"

        if [[ -n "$version_id" ]]; then
            run_aws "iam:GetPolicyVersion" "$policy_arn ($version_id)" \
                "$policy_dir/default-version-permissions.json" -- \
                aws iam get-policy-version --profile "$profile" \
                    --policy-arn "$policy_arn" \
                    --version-id "$version_id" || true
        fi

        run_aws "iam:ListPolicyVersions" "$policy_arn" \
            "$policy_dir/all-versions.json" -- \
            aws iam list-policy-versions --profile "$profile" \
                --policy-arn "$policy_arn" || true

        run_aws "iam:ListEntitiesForPolicy" "$policy_arn" \
            "$policy_dir/attached-entities.json" -- \
            aws iam list-entities-for-policy --profile "$profile" \
                --policy-arn "$policy_arn" || true
    done <<< "$arns"

    return 0
}

build_summaries() {
    local profile_dir="$1" role_dir="$2"

    # Roles summary
    if [[ -f "$profile_dir/roles.json" ]]; then
        {
            echo '"RoleName","RoleArn","CreateDate","MaxSessionDuration","PermissionsBoundary"'
            jq -r '
                .Roles[]? |
                [
                    .RoleName,
                    .Arn,
                    (.CreateDate // ""),
                    (.MaxSessionDuration // ""),
                    (.PermissionsBoundary.PermissionsBoundaryArn // "NONE")
                ] | @csv
            ' "$profile_dir/roles.json" 2>/dev/null || true
        } > "$profile_dir/roles-summary.csv"
    fi

    # Role -> policy mapping, including explicit NOT_ENUMERATED markers
    {
        echo '"RoleName","PolicyType","PolicyName","PolicyArn","EnumerationStatus"'

        local dir role_name
        for dir in "$role_dir"/*/; do
            [[ -d "$dir" ]] || continue
            role_name="$(basename "$dir")"

            if [[ -f "$dir/attached-managed-policies.json" ]]; then
                jq -r --arg r "$role_name" '
                    (.AttachedPolicies // []) as $p |
                    if ($p | length) == 0 then
                        [$r,"Managed","(none)","","OK_EMPTY"] | @csv
                    else
                        $p[] | [$r,"Managed",.PolicyName,.PolicyArn,"OK"] | @csv
                    end
                ' "$dir/attached-managed-policies.json" 2>/dev/null || true
            else
                printf '"%s","Managed","","","NOT_ENUMERATED"\n' "$role_name"
            fi

            if [[ -f "$dir/inline-policies.json" ]]; then
                jq -r --arg r "$role_name" '
                    (.PolicyNames // []) as $n |
                    if ($n | length) == 0 then
                        [$r,"Inline","(none)","","OK_EMPTY"] | @csv
                    else
                        $n[] | [$r,"Inline",.,"","OK"] | @csv
                    end
                ' "$dir/inline-policies.json" 2>/dev/null || true
            else
                printf '"%s","Inline","","","NOT_ENUMERATED"\n' "$role_name"
            fi
        done
    } > "$profile_dir/role-policy-mapping.csv"
}

process_profile() {
    local profile="$1"

    CURRENT_PROFILE="$profile"
    CURRENT_ACCOUNT="UNKNOWN"
    PROFILE_DENIED=0
    PROFILE_ERRORS=0
    PROFILE_SUCCESS=0

    log "INFO" "==================================================="
    log "INFO" "Processing profile: $profile"

    local profile_dir="$OUTPUT_ROOT/$(sanitize "$profile")"
    local role_dir="$profile_dir/roles"
    mkdir -p "$role_dir"

    # --- Identity / credential validation --------------------------------
    if ! run_aws "sts:GetCallerIdentity" "$profile" \
        "$profile_dir/caller-identity.json" -- \
        aws sts get-caller-identity --profile "$profile"; then

        log "WARN" "Profile unusable (authentication failed): $profile"
        echo "AUTHENTICATION_FAILED" > "$profile_dir/PROFILE_STATUS.txt"
        return 0
    fi

    CURRENT_ACCOUNT="$(jq_safe '.Account' "$profile_dir/caller-identity.json")"
    local caller_arn
    caller_arn="$(jq_safe '.Arn' "$profile_dir/caller-identity.json")"

    log "INFO" "Account: $CURRENT_ACCOUNT | Caller: $caller_arn"

    # --- Roles -------------------------------------------------------------
    if run_aws "iam:ListRoles" "$profile" \
        "$profile_dir/roles.json" -- \
        aws iam list-roles --profile "$profile"; then

        local role_names
        role_names="$(jq_safe '.Roles[]?.RoleName' "$profile_dir/roles.json")"

        if [[ -z "$role_names" ]]; then
            log "INFO" "No roles returned for $profile"
            record_status "$profile" "$CURRENT_ACCOUNT" \
                "iam:ListRoles" "$profile" "EMPTY" "No roles returned"
        else
            local role_count
            role_count="$(printf '%s\n' "$role_names" | grep -c . || true)"
            log "INFO" "Roles discovered: $role_count"

            local role_name
            while IFS= read -r role_name; do
                [[ -n "$role_name" ]] || continue
                process_role "$profile" "$role_name" "$role_dir"
            done <<< "$role_names"
        fi
    else
        log "WARN" "Role enumeration unavailable for $profile"
    fi

    # --- Customer managed policies (includes unattached) -------------------
    process_managed_policies "$profile" "$profile_dir" "Local" "customer-managed-policies" || true

    # --- Attached AWS-managed policies inventory (optional, useful context) -
    run_aws "iam:ListPolicies(attached-only)" "$profile" \
        "$profile_dir/attached-policies-all-scopes.json" -- \
        aws iam list-policies --profile "$profile" --scope All --only-attached || true

    # --- Account context (best effort) -------------------------------------
    run_aws "iam:GetAccountAuthorizationDetails" "$profile" \
        "$profile_dir/account-authorization-details.json" -- \
        aws iam get-account-authorization-details --profile "$profile" || true

    # --- Summaries ----------------------------------------------------------
    build_summaries "$profile_dir" "$role_dir"

    # --- Profile verdict -----------------------------------------------------
    local verdict
    if [[ "$PROFILE_DENIED" -eq 0 && "$PROFILE_ERRORS" -eq 0 ]]; then
        verdict="COMPLETE"
        log "INFO" "COMPLETE: $profile (successful calls: $PROFILE_SUCCESS)"
    else
        verdict="PARTIAL"
        log "WARN" "PARTIAL: $profile (success: $PROFILE_SUCCESS, denied: $PROFILE_DENIED, errors: $PROFILE_ERRORS)"
    fi

    {
        echo "Profile: $profile"
        echo "AccountId: $CURRENT_ACCOUNT"
        echo "Caller: $caller_arn"
        echo "Verdict: $verdict"
        echo "SuccessfulCalls: $PROFILE_SUCCESS"
        echo "AccessDenied: $PROFILE_DENIED"
        echo "OtherErrors: $PROFILE_ERRORS"
        echo "CompletedAt: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$profile_dir/PROFILE_STATUS.txt"

    printf '"%s","%s","%s","%s","%s","%s"\n' \
        "$profile" "$CURRENT_ACCOUNT" "$verdict" \
        "$PROFILE_SUCCESS" "$PROFILE_DENIED" "$PROFILE_ERRORS" \
        >> "$OUTPUT_ROOT/profile-summary.csv"
}

############################################################################
# Main loop - a failure inside one profile never stops the run
############################################################################

echo '"Profile","AccountId","Verdict","SuccessfulCalls","AccessDenied","OtherErrors"' \
    > "$OUTPUT_ROOT/profile-summary.csv"

for PROFILE in "${PROFILES[@]}"; do
    [[ -n "$PROFILE" ]] || continue
    process_profile "$PROFILE" || \
        log "ERROR" "Unhandled failure while processing profile: $PROFILE"
done

############################################################################
# Final reporting
############################################################################

log "INFO" "==================================================="
log "INFO" "Enumeration finished."
log "INFO" "Results:        $OUTPUT_ROOT"
log "INFO" "Status log:     $STATUS_LOG"
log "INFO" "Profile summary:$OUTPUT_ROOT/profile-summary.csv"

echo
echo "Profile verdicts:"
column -s, -t "$OUTPUT_ROOT/profile-summary.csv" 2>/dev/null \
    || cat "$OUTPUT_ROOT/profile-summary.csv"

DENIED_TOTAL="$(grep -c '"ACCESS_DENIED"' "$STATUS_LOG" 2>/dev/null || true)"
if [[ "${DENIED_TOTAL:-0}" -gt 0 ]]; then
    echo
    echo "[!] ${DENIED_TOTAL} operation(s) were blocked by insufficient permissions."
    echo "    Treat the corresponding data as NOT ENUMERATED, not as 'no configuration present'."
fi

exit 0
