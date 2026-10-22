aws iam get-account-authorization-details --profile <profile_name> \
  --output json > iam_auth_details_<profile>.json

python3 - <<'EOF'
import json, urllib.parse

with open("iam_auth_details_<profile>.json") as f:
    data = json.load(f)

def check_doc(doc, source, name):
    doc = urllib.parse.unquote(json.dumps(doc)) if isinstance(doc, str) else doc
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        actions = s.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        if any(a.lower().startswith("rds-data:") or a == "*" for a in actions):
            print(f"[{source}] {name}: Action={actions} Resource={s.get('Resource')} Effect={s.get('Effect')}")

for role in data.get("RoleDetailList", []):
    for p in role.get("RolePolicyList", []):
        check_doc(p["PolicyDocument"], "Role-Inline", role["RoleName"])
    for p in role.get("AttachedManagedPolicies", []):
        pass  # cross-reference with Policies list below

for user in data.get("UserDetailList", []):
    for p in user.get("UserPolicyList", []):
        check_doc(p["PolicyDocument"], "User-Inline", user["UserName"])

for policy in data.get("Policies", []):
    for v in policy.get("PolicyVersionList", []):
        if v.get("IsDefaultVersion"):
            check_doc(v["Document"], "Managed-Policy", policy["PolicyName"])
EOF
