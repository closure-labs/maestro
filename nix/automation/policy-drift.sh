#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
trap 'echo "GitHub policy drift check failed at line $LINENO; verify settings and repository-scoped Administration read access." >&2' ERR
: "${GITHUB_REPOSITORY:?}" "${MAESTRO_GITHUB_SECURITY_POLICY:?}" "${MAESTRO_MAIN_RULESET:?}"
policy=$MAESTRO_GITHUB_SECURITY_POLICY
repository=$(gh api "repos/$GITHUB_REPOSITORY")
jq -e --slurpfile policy "$policy" '
  .default_branch == "main" and
  .security_and_analysis.secret_scanning.status == $policy[0].secret_scanning and
  .security_and_analysis.secret_scanning_push_protection.status == $policy[0].secret_scanning_push_protection
' <<<"$repository" >/dev/null
reporting=$(gh api "repos/$GITHUB_REPOSITORY/private-vulnerability-reporting")
jq -e --slurpfile policy "$policy" '.enabled == $policy[0].private_vulnerability_reporting' <<<"$reporting" >/dev/null
permissions=$(gh api "repos/$GITHUB_REPOSITORY/actions/permissions")
jq -e --slurpfile policy "$policy" '
  .enabled == true and .allowed_actions == $policy[0].actions.allowed_actions and
  .sha_pinning_required == $policy[0].actions.sha_pinning_required
' <<<"$permissions" >/dev/null
workflow=$(gh api "repos/$GITHUB_REPOSITORY/actions/permissions/workflow")
jq -e --slurpfile policy "$policy" '.default_workflow_permissions == $policy[0].actions.default_workflow_permissions' <<<"$workflow" >/dev/null
selected=$(gh api "repos/$GITHUB_REPOSITORY/actions/permissions/selected-actions")
jq -e --slurpfile policy "$policy" '
  .github_owned_allowed == $policy[0].selected_actions.github_owned_allowed and
  .verified_allowed == $policy[0].selected_actions.verified_allowed and
  (.patterns_allowed | sort) == ($policy[0].selected_actions.patterns_allowed | sort)
' <<<"$selected" >/dev/null
rulesets=$(gh api "repos/$GITHUB_REPOSITORY/rulesets?includes_parents=true")
rule_id=$(jq -er --slurpfile expected "$MAESTRO_MAIN_RULESET" '
  [.[] | select(.name == $expected[0].name and .enforcement == "active")] |
  select(length == 1) | .[0].id
' <<<"$rulesets")
ruleset=$(gh api "repos/$GITHUB_REPOSITORY/rulesets/$rule_id")
# REST hides actor details from read-only integrations. Require an explicit
# empty REST list or the GraphQL connection's authoritative count for this
# exact ruleset; never turn a missing/redacted field into an empty list.
if jq -e 'has("bypass_actors")' <<<"$ruleset" >/dev/null; then
  jq -e '.bypass_actors == []' <<<"$ruleset" >/dev/null
else
  rule_node=$(jq -er .node_id <<<"$ruleset")
  # GraphQL variables stay literal in the query.
  # shellcheck disable=SC2016
  bypass=$(gh api graphql -f id="$rule_node" -f 'query=query($id:ID!){node(id:$id){... on RepositoryRuleset{databaseId bypassActors(first:1){totalCount}}}}')
  jq -e --argjson rule_id "$rule_id" '
    (.errors // [] | length) == 0 and
    .data.node.databaseId == $rule_id and
    .data.node.bypassActors.totalCount == 0
  ' <<<"$bypass" >/dev/null
fi
jq -e --slurpfile expected "$MAESTRO_MAIN_RULESET" '
  .enforcement == "active" and .target == "branch" and
  (.conditions.ref_name.include | index("~DEFAULT_BRANCH")) != null and
  (.conditions.ref_name.exclude | length) == 0 and
  (.rules | contains($expected[0].rules))
' <<<"$ruleset" >/dev/null
release=$(gh api "repos/$GITHUB_REPOSITORY/environments/release")
jq -e --slurpfile policy "$policy" '.deployment_branch_policy == $policy[0].release_environment' <<<"$release" >/dev/null
echo 'GitHub security policy matches the declared repository contract.'
