# SPDX-License-Identifier: Apache-2.0
# The CodeQL exception uses the same shared action from protected source, never
# candidate helpers. Keep checkout, setup guard and task directory bound together.
def protected_codeql_setup:
  $workflow == "codeql.yml" and .key == "analyze" and
  (.value.steps as $steps |
    any($steps[];
      (.uses // "" | startswith("actions/checkout@")) and
      .with.path == "controller" and .with["persist-credentials"] == false and
      .with.ref == "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.sha }}" and
      .if == "matrix.language == 'rust'") and
    any($steps[];
      .uses == "./controller/.github/actions/setup-nix" and
      .if == "matrix.language == 'rust'") and
    all($steps[] | select((.run // "") | test("(^|[[:space:]])nix[[:space:]]"));
      .["working-directory"] == "controller" and .if == "matrix.language == 'rust'"));

all(to_entries[];
  . as $entry | .key as $job | .value |
  if any(.steps[]?; ((.run // "") | test("(^|[[:space:]])nix[[:space:]]")))
  then any(.steps[]?; .uses == "$/.github/actions/setup-nix") or
    ($workflow == "ci.yml" and $job == "retained" and
     any(.steps[]?; .uses == "./controller/.github/actions/setup-nix") and
     (.if | contains("github.event.pull_request.base.ref"))) or
    ($entry | protected_codeql_setup)
  else true end)
