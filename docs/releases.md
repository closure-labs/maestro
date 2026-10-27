<!-- SPDX-License-Identifier: Apache-2.0 -->
# Prepare and stage a release

Maestro releases one appliance, `nixosConfigurations.maestro`. A release has
three separate checkpoints: reviewed source, a retained and attested product
packet, and approved publication. Source preparation alone does not establish
that installer bytes have been qualified or published.

## Prepare the source

1. Start a clean `jj` change from current protected `main`. Review commits since
   the latest published tag and choose the semantic version. The automatic
   selector treats breaking conventional commits as major, `feat` commits as
   minor, and other changes as patch updates.
2. Update the README and affected guides against the implementation. Move the
   current changelog into a dated section for the selected version, leave an
   `Unreleased` heading, and preserve every earlier release entry.
3. Record coherent documentation and version checkpoints with `jj`. Keep input
   pins and appliance policy changes out of documentation preparation.
4. Push a release bookmark and open a pull request as `cl-decider[bot]` using a
   short-lived repository-scoped installation token. Verify the returned author.
   Independent maintainer review, CodeQL, **Required CI verdict**, and the normal
   protected merge queue remain required.

`VERSION` normally contains the next development version. The release workflow
prepares its selected stable value through a protected, VERSION-only PR. A
manually reviewed preparation may set that same stable value beforehand; select
an explicit workflow bump that agrees with the prepared changelog and VERSION.
Do not dispatch against main before those source changes have merged.

Local checks must stay within the repository's 512 MiB limit. Validate release
note extraction and documentation links locally; complete Nix evaluation,
audits, product builds, and VM tests run in hosted CI.

## Stage the verified product

After the source PR merges, dispatch **Release Maestro** (`release.yml`) from
`main` with the selected bump. Keep event continuation disabled unless its
separate pilot has been reviewed and enabled. The workflow:

1. Refuses conflicting pending release work and resolves the stable version.
   If VERSION needs a protected merge, it acquires a new source context before
   final qualification and signing.
2. Dispatches qualification for the exact source. Native checks authenticate
   retained products or require new qualification; graph equality alone never
   authorizes evidence reuse.
3. Verifies inventory, current scan evidence, upstream XO handoff, and
   attestations. The `release:stage` task extracts the dated changelog section,
   splits the installer into parts below GitHub's asset limit, and writes SBOM
   archives, checksums, and the release manifest.
4. Retains the exact prepared packet as `maestro-release-product` and attests
   the versioned installer and its bound SPDX inventory.

These hosted tasks require real authenticated candidate artifacts and producer
identities. A source checkout or a local release-note preview cannot substitute
for the prepared packet. Preserve its workflow run and exact source identity
when handing it to publication.

## Approve and publish

`release-publication.yml` reconciles the retained packet after the required
human decisions. Current complete security findings and the exact release
product require their separate approvals as described in
[CI and security](ci-security.md). A draft, a passing build, or an old receipt
supplies no publication authority.

Publication checks existing destinations before writing, verifies hosted bytes,
and records native receipts. Active destinations are Cachix and GitHub releases;
new Maestro versions are no longer published to FlakeHub. Existing FlakeHub
versions and historical receipts remain readable. Successful publication makes
the GitHub release immutable and advances VERSION to the next patch development
version through the protected process.

For an interrupted release, use the existing authenticated recovery and
reconciliation controls. Preserve the exact admitted product and immutable
assets rather than rebuilding under the same version. See
[project reference](project-reference.md) for artifact formats and
[CI and security](ci-security.md) for selection, freshness, and recovery gates.
