<!-- SPDX-License-Identifier: Apache-2.0 -->
# Stage 1: ordinary flake validation

`flake-checks.yml` is a temporary, non-required, read-only comparison on PR,
merge-group and main revisions. It has no publication, signing, cache-upload,
packet, decision, inspector or recovery role. Existing required CI, CodeQL,
Gitleaks, App authority and merge queue remain unchanged. No review/settings
cutover is included; the future accepted one-human-review policy, including
Dependabot, must be applied only through a separately approved change.

The single `ci:flake:validate` task realizes all ordinary flake checks with
`nix flake check`, including every current twenty-plan obligation and existing
CLI, runtime-security VM, storage and file-restore checks. It then builds the
appliance, installer ISO, pinned XO, compiled menu, CLI and deployment wrapper. Those VM tests cover XO/Redis service startup, TLS, management ingress,
NFS/CIFS/VHD storage and privilege boundaries. Build and test failures stop the
job. No substitute success receipt or advisory finding baseline is generated.
The task inherits exactly the existing URLs/keys from `modules/flake/caches.nix`
through its package, preserving setup's baseline configuration. It adds no cache,
key or credential, and does not accept arbitrary flake settings. Phase labels go
to stderr and native build logs remain visible. The earlier evaluation-only trial
and its ignored-cache timings cannot establish parity. Existing required
installer boot qualification remains unchanged; an ISO build
in this workflow does not claim to replace its boot evidence.

## One-cycle exit and deletion

Observe one agreed PR/merge-group validation cycle on matching source revisions.
The cutover checklist is:

- Product builds and the named tests pass on the compared revision; existing
  required ISO boot qualification also passes.
- Classify all twenty existing validation obligations as retained product
  checks, replacement checks, or explicitly approved controller-only removals.
  This selected workflow does not claim complete parity on its own.
- Keep every unexplained failure or coverage omission blocking the migration.

After that cycle, the next reviewed cutover should replace redundant `ci.yml`
routing/comparison/equivalence/retained-evidence work with ordinary checks/builds
and a stable required verdict, preserving actual product assertions and boot
coverage. Delete `flake-checks.yml` in that same cutover; reuse its small native
task only if it becomes the ordinary validation entry point. Do not extend the
parallel trial into a permanent second gate or add a proof/benchmark controller.
If parity fails, remove the temporary workflow and fix the named gap before
another specifically agreed trial. Publication/admission and required-review
changes are later stages with their own explicit security-guarantee decisions.
