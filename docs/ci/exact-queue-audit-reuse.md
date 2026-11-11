<!-- SPDX-License-Identifier: Apache-2.0 -->
# Exact-commit queue audit reuse

A successful merge queue validates the same commit that GitHub subsequently
pushes to main. Repeating the complete repository audit cannot change that
commit's immutable check outputs. Main may reuse the queue's validation
evidence, but not its authority, signing credentials or release decisions.

The reuse reader runs only for a clean checkout of the exact `GITHUB_SHA` on a
protected-main push. It requires an authenticated GitHub API response identifying
a successful `merge_group` run of `.github/workflows/ci.yml` in this repository,
including the same head repository and SHA. Both audit execution and reference
binding steps, and the required CI verdict, must have succeeded in that exact
attempt. The source artifact must have been created during that attempt, remain
unexpired, and be at most 24 hours old. Run and artifact identity are rechecked
after downloading.

The reader verifies GitHub's SHA-256 archive digest, bounded archive and member
sizes, the source reference's producer and evidence hashes, and the complete
successful twenty-obligation manifest. It copies only audit and timing JSON;
no NAR, executable, credential or old reference is imported. The usual fresh
graph-reference task checks every output identity against the newly evaluated
candidate graph and binds `reuse.json` to this main run's own reference. The
source cannot itself be a reused audit. There is no reusable success flag or
cross-revision cache key.

Any missing, stale, ambiguous, corrupted or unverifiable source is a cache miss:
run the full audit. Fresh inventory preflight and formatting remain mandatory,
as do current security scanning, equivalence, maintainer authority, main signing
and the required verdict. Scheduled, dispatched, pull-request and merge-group
runs always execute their normal full audit. In particular, force-validation
workflow dispatch remains an independent audit escape hatch.

This change reuses **validation of immutable build outputs**, not unsigned store
contents. Artifact loss or GitHub API availability affects performance only;
it cannot make an unchecked candidate pass. Fresh security and independent
approval are intentionally not deduplicated. No permissions beyond the existing
read-only Actions token are needed. Hosted validation must establish the first
queue-to-main reuse before any measured savings are claimed.
