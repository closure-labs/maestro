# Security findings review and implementation sequence

Reviewed on 2026-10-12 against commit
`b7990e2143f77dbe786e83da87b1275e60c20a8f`, the [successful qualification
run](https://github.com/closure-labs/maestro/actions/runs/38331315241),
[scanner report](https://github.com/closure-labs/maestro/actions/runs/38331315241/artifacts/11784463514),
and its matching evidence artifact (ID `11784687650`). The accompanying
[finding ledger](security-findings-2026-10-12.json) accounts for all 204
normalized findings, including the 12 critical and 98 high findings.

The requested `great_cto` skill was unavailable in the installed skill
directories. This review uses a CTO decision structure: evidence, reachable
interfaces, ownership, ordered changes, acceptance criteria, and rollback.

## Decision

Prioritize complete inventories and dependency identity, then repair older
runtime dependency copies and narrow the image-tooling closure. Several
critical findings are already fixed in the locked sources. No reported CVE
has yet been demonstrated exploitable on a running Maestro appliance.
There are plausible client, image-parser, and operator attack surfaces that
require remediation or more specific runtime evidence.

This is a review and implementation plan. It does not change package pins,
runtime configuration, the vulnerability baseline, or the report-only policy.
Repository defaults were inspected; no deployed appliance was accessed.
Absence of a configured feature is provisional until tested against the
evaluated system and the operator's actual deployment.

## Evidence quality and scope

- The system CycloneDX document contains 1,063 components and a dependency
  graph. Grype produced 224 raw matches, normalized to 204 findings; all
  matches use Nix artifacts and generic CPE matching. These matches do not
  account for Nixpkgs backports.
- The XO supply document contains 97 components. All 97 lack package URLs;
  96 lack a separate version. Names such as `openssl-3.6.3` are unsplit store
  names. Its zero Grype matches does not establish a clean XO dependency set.
- The system document also has 430 blank versions. Some are expected for
  generated configuration files, but executable names such as
  `nodejs-slim-22.23.2` need proper identity. Neither document enumerates the
  installed npm dependency tree. RustSec's zero findings covers the TUI's
  Cargo lockfile only.
- Normalization currently merges findings by advisory, component, version,
  and severity. Different derivations can have different patches while sharing
  a version. Preserve derivation/output identity before applying dispositions.
- Root Nixpkgs is `6fcc160353f63555b560f25588925133c8f61f2a`.
  XO's independent Nixpkgs is
  `83199d0d373dd3ac2b9a1996b1d0263f76ab7a4c`; Determinate Nix's is
  `c5c4a43b0e8056328ec4529f735cabdb8f1942bb`.
  Refreshing all Maestro inputs preserves these upstream-pinned dependency
  trees. A current top-level lockfile can therefore retain older libraries.

The SBOM dependency graph is evidence of closure membership, not proof that a
specific function runs. [sbomnix normally inventories runtime references](https://github.com/tiiuae/sbomnix/blob/main/README.md).
Its derivation-level graph and selected output metadata still need correlation
with exact executable and library paths on the runner.

## Relevant interfaces

| Boundary | Declared behavior | Security consequence |
|---|---|---|
| Network to XO | HTTP 80 and HTTPS 443; Node runtime from the XO package | Unauthenticated HTTP/TLS parsing and authenticated administration deserve first review. XO npm coverage is currently incomplete. |
| Network to SSH | Port 22 opened by the SSH module; only `maestro`; public keys; root/password/keyboard-interactive login disabled | Pre-authentication parsing remains reachable even with key-only authentication. Operator compromise can become root through declared sudo policy. |
| XO to XCP-ng/storage | Outbound pool connections; NFS/CIFS/VHD enabled | Malicious or compromised peers, backups, and guest images are relevant inputs. A client-side CVE can matter without a local listening server. |
| XO to root helper | Narrow sudo command; mount/image operations; broad bounding set needed for those helpers | Preserve privilege separation and test path containment under concurrent mutation. This is a separate design concern, not a scanner-confirmed CVE. |
| Local tools | Vim, Nmap, libguestfs and other operator utilities | Hostile files or remote peers can target tools used by a sudo-capable operator. |
| Appliance to hypervisor | Maestro is an XCP-ng guest; Xen guest agent enabled | Xen hypervisor bugs do not become Maestro hypervisor bugs merely because Xen tools are in its closure. Review XCP-ng host patching separately. |

Valkey uses a Unix socket with TCP disabled. The repository does not enable
telnetd, inetd, a Samba server, a libssh SSH server, libvirtd, Avahi, Bluetooth,
or a SPICE listening service. NFS enables rpcbind but not an NFS server;
verify actual listeners and firewall rules, including IPv6. QEMU is pulled
in by libguestfs, and dnsmasq by libvirt: transient subprocesses still need
inspection during actual image/file-restore operations.

## Findings that change the remediation order

| Finding group | Assessment | Implementation implication |
|---|---|---|
| inetutils 2.7: critical CVE-2026-24061 and CVE-2026-32746; high CVE-2026-28372 | The [locked package definition](https://github.com/NixOS/nixpkgs/blob/6fcc160353f63555b560f25588925133c8f61f2a/pkgs/by-name/in/inetutils/package.nix) includes named backports for all three. No telnet service is declared. The first issue is genuinely serious in exposed telnetd deployments, as the [GNU advisory](https://www.openwall.com/lists/oss-security/2026/01/20/2) explains. | Record exact patched derivations. Replace broad inetutils dependencies with the tools actually needed; do not label Maestro remotely vulnerable to telnetd based on the version string. |
| libssh2 1.11.1: one critical and eight high findings | The root, XO, and Determinate dependency revisions were read. Each declares the backports for all nine, including the [packet-length fix](https://github.com/libssh2/libssh2/commit/97acf3dfda80c91c3a8c9f2372546301d4a1a7a8). | Record patch evidence per derivation. These are relevant client attack paths in principle, but additional copies of the same backports are unnecessary. |
| GnuTLS 3.8.13: two critical and four high findings | [Upstream advisories](https://www.gnutls.org/security-new.html) identify fixes in 3.8.10, 3.8.12, or 3.8.13 for the reported six issues. The scanned version contains those fixes. | Correct version applicability with evidence; keep scanner severity unchanged in raw reports. |
| Perl 5.42.3: two critical, one high, one medium | [Perl's release notes](https://github.com/Perl/perl5/blob/v5.42.3/pod/perldelta.pod) include fixes for CVE-2026-8376, CVE-2026-13221 and CVE-2026-57432. The locked interpreter adds named patches for medium CVE-2026-15534. The 32-bit overflow also does not describe this x86_64 appliance. | Record fixed-source evidence; no emergency Perl upgrade justified by these matches. |
| OpenSSL 3.6.3: two critical and twelve high findings, plus lower-severity issues | Root packages use 3.6.5; XO and Determinate retain 3.6.3. XO's Node package declares shared OpenSSL. Most flagged issues require CMP, QUIC, DTLS, special OCSP flags or non-default cryptographic APIs. Those conditions are not established for XO's ordinary HTTPS listener. [OpenSSL's September advisory](https://openssl-library.org/news/secadv/20260929.txt) also describes certificate-processing memory pressure, which deserves client-side review. | Advance the upstream runtime dependencies to patched releases, preserving supported Node/Determinate versions and cache publication. Test XO's actual Node crypto version and shared libraries. Do not infer that replacing the system `openssl` command updates Node or Nix. |
| libxml2 2.15.3 and 2.15.4 | Older 2.15.3 is retained through libarchive 3.8.8 in the independent dependency tree. [Upstream release history](https://github.com/GNOME/libxml2/blob/v2.15.4/NEWS) includes parser fixes in 2.15.4; the xmlBuildQName fix flagged as CVE-2025-6021 predates both versions. | Advance old libarchive/libxml2 consumers and check actual archive-processing paths. Do not suppress the 2.15.3 parser findings merely because the system also has 2.15.4. |
| Vim 9.2.0541: fifteen high and nine lower-severity findings | The locked source has no security backports for newer patch levels. Hostile spell, swap, undo, completion or terminal inputs are conditional operator attack paths. Some findings require absent build features: [CVE-2026-73078 requires GUI menus](https://github.com/vim/vim/security/advisories/GHSA-rcr7-f3wr-22r2), and Python completion requires a Python-enabled build. | Update the terminal Vim package to a supported patch level covering the reviewed advisories, or deliberately choose a supported replacement. Verify build features and preserve `vi`/editor behavior. Treat the operator's sudo authority as an impact multiplier. |
| libguestfs → QEMU → SPICE/Capstone/media libraries | Real closure expansion: QEMU brings SPICE, GStreamer, font/image/audio parsers; libvirt brings dnsmasq and related clients. The Capstone critical advisory [requires control of a custom memory hook](https://github.com/capstone-engine/capstone/security/advisories/GHSA-85f5-6xr3-q76r), not just arbitrary instruction bytes. SPICE/media and device-emulation findings depend on enabled interfaces. | Replace the full image-tooling dependency chain with the smallest supported headless configuration that passes real restore tests. Verify older fixes individually. Do not remove VHD or guest-file restore capabilities without proving an equivalent path. |
| SQLite 3.51.2, PCRE2 10.46, libcap 2.77, zlib 1.3.2 | Conditional database, regex, capability-setting and compression call paths. SQLite FTS5 needs a crafted database and a specific query; Nix's own state DB is not an arbitrary uploaded DB. [One PCRE2 high finding is 32-bit-only](https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-q8g2-wprr-34m9), while the JIT finding needs separate review. libcap needs privileged capability updates in attacker-writable paths. zlib's report concerns a specific nonblocking write sequence. | Verify backports and callers before assigning exposure. Prefer upstream fixes for shared libraries; test capability application and Nix state handling without breaking supported deployment behavior. |
| OpenSSH, Samba and Xen generic matches | CVE-2008-3844 concerns unofficial trojaned RHEL packages; CVE-2011-2411 concerns HP NonStop, not this NixOS build. CVE-2026-3497 concerns an added GSSAPI key-exchange patch; the inspected default OpenSSH package differs from the separate GSSAPI variant. Xen CVE-2011-1763 concerns hypervisor event-channel handling. Other SSH findings still need their own configuration checks. | Record narrowly scoped product/feature dispositions. Keep SSH maintained and test pre-authentication behavior. Track XCP-ng host patching outside this appliance repository. |

Other findings in the ledger remain conditional or awaiting patch/caller
verification. In particular, absence of an Avahi/BlueZ/Samba daemon does not
prove every library function is unused. Lower-severity certificate parsing,
Nmap packet parsing and archive extraction must remain in the work queue.
No generic package-wide suppression is justified by this review.

## Ordered implementation checkpoints

The owner roles below are proposed responsibilities, not assignments to
additional people. Each checkpoint should be a coherent `jj` change and a
reviewable PR or update to the existing draft PR.

| Order | Owner role | Concrete changes | Acceptance gate and rollback |
|---|---|---|---|
| 1. Inventory and disposition contract | Maestro CI maintainer; XO package maintainer | Preserve derivation/output identities, dependency parents, source revision and patch evidence in normalized findings. Require valid component identities for executable/library records. Produce the installed production npm tree, including bundled native dependencies, from the immutable XO package. Fix the upstream supply SBOM producer and regenerate its bound assertion/checksums. Keep raw artifacts. | Fixture scans must detect a known vulnerable Nix and npm component; malformed/unscannable inventory must fail rather than return clean. Fixed and unpatched copies of one version must receive separate verdicts. Existing evidence/attestation verification must still reject substitutions. Roll back the producer/schema and consumer together; keep report mode. |
| 2. Correct proven dispositions | Maestro security maintainer | Add explicit, source-bound fixed/product/feature records for verified cases above. Extend policy handling beyond the current permanent version-only baseline. Bind dispositions to derivation or immutable input identity and invalidate them when source, patches, configuration, platform or scanner semantics change. Give conditional findings owners and deadlines. | Test a patch removal without a version bump, a second unpatched derivation, source drift, severity escalation and expiry. All must reopen the finding. Do not convert all 110 high/critical records into accepted risk. Roll back disposition records independently of package fixes. |
| 3. Advance retained runtime trees and Vim | XO package maintainer; Determinate integration maintainer; Maestro maintainer | First obtain supported upstream packages built against patched OpenSSL/libxml2 dependencies; at this review date OpenSSL's 3.6 branch fixes are in 3.6.5 and libxml2's reviewed parser fixes in 2.15.4. Verify current releases again when implementing. Publish through the existing upstream cache gate, then update Maestro's inputs and synchronize devenv.lock. Independently update/backport terminal Vim. Avoid changing transitive `follows` or merely replacing a CLI library path. | GitHub runners must show the exact Node/Nix library paths and crypto versions, rerun scans and both lock checks, build XO/appliance/ISO, and run TLS, pool-connection, update/rollback and cache-substitution checks. Verify source/vendor hashes from actual fetches. Retain the last qualified input/boot generation for rollback. |
| 4. Reduce optional execution surface | Maestro runtime maintainer | Audit pinned XO calls to guestfs/Xen tools. Supply a supported headless, narrowly configured QEMU/libguestfs chain; remove GUI/audio/media/network-server dependencies where restore behavior permits. Replace CLI/TUI's inetutils use with specific hostname/network tools and check Xen's remaining dependency. Keep NFS/CIFS/VHD functionality and operator diagnostics that are actually required. | Compare exact before/after runtime closures and CVE disposition counts. Test NFS/CIFS backup, VHD/VHDX inspection, guest-file restore, operator status and failure recovery on GitHub runners and a disposable XCP-ng guest. Missing functionality blocks this checkpoint. Roll back the narrow package overrides without undoing security patches. |
| 5. Runtime boundaries and deployment evidence | Maestro runtime maintainer; appliance operator | Add evaluated configuration and VM assertions for allowed TCP/UDP listeners, IPv6, Valkey socket permissions, SSH restrictions, disabled auxiliary daemons, and capabilities. Inspect subprocesses during storage operations. Review root-helper pathname validation for concurrent rename/symlink changes; if containment cannot be proven, replace that boundary with descriptor-based containment in a focused helper. Add management-network restrictions only using the operator's actual CIDRs and a tested recovery path. | Booted VM tests exercise TLS and unauthorized storage requests, including concurrent mutation. Run backup/restore and sealing/clone/reboot acceptance on a disposable XCP-ng target. Console/key recovery must work before network restriction is activated. Roll back to the prior generation through the declared operator. |
| 6. Enforce and release | Maestro CI/release maintainer; appliance operator | Turn report mode into enforcement only after inventory completeness, source-bound dispositions, and reachable high/critical remediation pass. Any residual accepted risk needs an owner, evidence and a maximum 30-day exception. After the workflow reaches protected main, smoke-test the organization App's policy read and signing/attestation path. Maintain weekly rescans and policy drift checks. | New actionable high/critical findings, expired exceptions, lost inventory coverage and scanner/database errors block publication. A validated false match remains visible with its evidence. Qualified main artifacts, checksum/attestation verification and disposable XCP-ng acceptance precede release. Roll back a deployment using the last qualified generation/artifact; reverting enforcement must be an explicit reviewed policy change. |

Checkpoint 1 starts first. The dependency and Vim fixes in checkpoint 3 can
proceed once their exact identities are established, without waiting for all
lower-risk records to be classified. Checkpoint 4 follows patched package
availability; checkpoint 6 depends on all preceding acceptance gates.

## Testing and resource policy

Use GitHub-hosted runners for Nix builds, vulnerability databases, Cargo,
Packer, QEMU tests and closure inspection. Workflow bodies continue to call
declared devenv tasks which delegate to focused `maestro-ci-*` commands.
Do not add a monolithic dispatcher or evaluate runtime credentials in Nix.
Keep source caches and the existing XO/libvhdi cache trust contract.

Local work is limited to source review, small metadata downloads, JSON/schema
checks and `jj` checkpoints. This review downloaded the small scanner/evidence
reports and package definitions only; it performed no local builds, installed
no new toolchain, and fetched no installer or vulnerability database. Package
changes require the native devenv/Nix toolchain on the runners. A real XCP-ng
acceptance target and actual management CIDRs remain operator deployment
inputs; repository-source inspection cannot substitute for them.
