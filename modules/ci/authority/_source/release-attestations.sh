#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${GITHUB_REPOSITORY:?}" "${SOURCE_SHA:?}" "${RELEASE_TAG:?}" "${RUNNER_TEMP:?}"
[[ $SOURCE_SHA =~ ^[0-9a-f]{40}$ && $RELEASE_TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
filename="maestro-$RELEASE_TAG.iso"
installer="$RUNNER_TEMP/$filename"
checksum="release/$filename.sha256"
sbom=candidate/maestro-system.spdx.json
[[ -f $installer && ! -L $installer && -f $checksum && ! -L $checksum && -f $sbom && ! -L $sbom ]]
expected=$(<"$checksum")
digest=${expected%% *}
[[ $digest =~ ^[0-9a-f]{64}$ && $expected == "$digest  $filename" ]]
actual=$(sha256sum -- "$installer")
[[ ${actual%% *} == "$digest" ]]
jq -e '.spdxVersion == "SPDX-2.3"' "$sbom" >/dev/null

# Checking out SOURCE_SHA does not change the caller's OIDC source identity.
# Verify the new final-name attestations before either public publication.
verify_args=(--repo "$GITHUB_REPOSITORY"
  --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"
  --source-ref refs/heads/main --source-digest "$SOURCE_SHA" --signer-digest "$SOURCE_SHA"
  --deny-self-hosted-runners --format json)
for predicate_type in https://slsa.dev/provenance/v1 https://spdx.dev/Document/v2.3; do
  verified=$(gh attestation verify "$installer" "${verify_args[@]}" --predicate-type "$predicate_type")
  jq -e --arg filename "$filename" --arg digest "$digest" --arg type "$predicate_type" \
    --slurpfile sbom "$sbom" '
      type == "array" and length > 0 and any(.[];
        .verificationResult.statement as $statement |
        $statement.predicateType == $type and
        any($statement.subject[]; .name == $filename and .digest.sha256 == $digest) and
        ($type != "https://spdx.dev/Document/v2.3" or $statement.predicate == $sbom[0]))
    ' <<<"$verified" >/dev/null
done
