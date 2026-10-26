#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir "$temporary/bin"
cat >"$temporary/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == api ]]
case $2 in
  repos/fixture/maestro) cat "$FIXTURES/repository.json" ;;
  repos/fixture/maestro/private-vulnerability-reporting) echo '{"enabled":true}' ;;
  repos/fixture/maestro/actions/permissions) cat "$FIXTURES/permissions.json" ;;
  repos/fixture/maestro/actions/permissions/workflow) echo '{"default_workflow_permissions":"read"}' ;;
  repos/fixture/maestro/actions/permissions/selected-actions) cat "$FIXTURES/selected.json" ;;
  repos/fixture/maestro/rulesets\?includes_parents=true) cat "$FIXTURES/rulesets.json" ;;
  repos/fixture/maestro/rulesets/7) cat "$FIXTURES/ruleset.json" ;;
  repos/fixture/maestro/environments/release) echo '{"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}' ;;
  graphql) [[ $4 == id=RRS_fixture ]]; cat "$FIXTURES/graphql.json" ;;
  *) exit 2 ;;
esac
SH
sed -i "1c#!${BASH}" "$temporary/bin/gh"
chmod +x "$temporary/bin/gh"
policy="$repo_root/modules/ci/authority/_source/github/security-policy.json"
rules="$repo_root/modules/ci/authority/_source/github/main-ruleset.json"
jq '{default_branch:"main",security_and_analysis:{secret_scanning:{status:.secret_scanning},secret_scanning_push_protection:{status:.secret_scanning_push_protection}}}' "$policy" >"$temporary/repository.json"
jq '.actions + {enabled:true}' "$policy" >"$temporary/permissions.json"
jq .selected_actions "$policy" >"$temporary/selected.json"
jq '[{id:7,name:.name,enforcement:"active"}]' "$rules" >"$temporary/rulesets.json"
reset() {
  jq '. + {id:7,node_id:"RRS_fixture"}' "$rules" >"$temporary/ruleset.json"
  echo '{"data":{"node":{"databaseId":7,"bypassActors":{"totalCount":0}}}}' >"$temporary/graphql.json"
}
invoke() {
  FIXTURES="$temporary" PATH="$temporary/bin:$PATH" GITHUB_REPOSITORY=fixture/maestro \
    MAESTRO_GITHUB_SECURITY_POLICY="$policy" MAESTRO_MAIN_RULESET="$rules" \
    bash "$repo_root/modules/ci/authority/_source/policy-drift.sh" >/dev/null 2>&1
}
reject() {
  if invoke; then echo 'Policy check accepted missing or unsafe bypass evidence' >&2; exit 1; fi
}
reset
invoke
jq '.bypass_actors=[{actor_id:1,actor_type:"Team",bypass_mode:"always"}]' "$temporary/ruleset.json" >"$temporary/changed.json"
mv "$temporary/changed.json" "$temporary/ruleset.json"
reject
reset
jq 'del(.bypass_actors)' "$temporary/ruleset.json" >"$temporary/changed.json"
mv "$temporary/changed.json" "$temporary/ruleset.json"
invoke
for alteration in '.data.node.databaseId=8' '.data.node.bypassActors.totalCount=1' '.data.node.bypassActors.totalCount=null' '.data.node=null' '.errors=[{message:"Resource inaccessible"}]'; do
  echo '{"data":{"node":{"databaseId":7,"bypassActors":{"totalCount":0}}}}' | jq "$alteration" >"$temporary/graphql.json"
  reject
done
echo 'Policy bypass visibility, identity and API failure fixtures passed'
