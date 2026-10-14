# Critical finding applicability — 2026-10-14

The reviewed Maestro scan contains 14 critical finding instances: nine native
instances have verified fixes, and five npm instances remain **UNKNOWN**. The
reviewed rules preserve the original scanner findings and attach a classification
to each exact instance. They do not establish production acceptance or turn an
incomplete review into a clean security result.

The rules in `nix/automation/security-applicability.json` expire on 2026-11-13.
They bind the advisory digest, package URL, component reference, exact output,
derivation and digest, source, complete ordered patch set, and component hashes.
A changed source, producer, output or recorded patch/code identity stops matching
and requires a new review. The three Perl environment outputs have separate
rules; their names alone do not establish applicability.

Fixed-source decisions are independent of appliance configuration. The rule
therefore does not freeze a runtime-context value. The evaluator still checks
each finding against the current inventory and records its context in the
assessment. Conditional exposure decisions would also require verified runtime
and code guards. Missing evidence or a failed guard leaves the finding UNKNOWN.

## Native findings: nine fixed instances

### Perl: eight instances across four outputs

Both CVE-2026-13221 and CVE-2026-8376 appear against three Perl environment outputs
and the interpreter's manual output. [Perl 5.42.3 release notes](https://perldoc.perl.org/5.42.3/perl5423delta)
identify both fixes. The reviewed source archive includes the upstream regex
trie distance check and substring byte-length overflow check. The ordered native
patches preserve that compilation code.

| Reviewed evidence | SHA256 |
| --- | --- |
| `perl-5.42.3.tar.gz` | `1137740985837b5cdf15f0cfab932279dcb4352f912fed6fc144e8b4f0823627` |
| Final `regcomp_study.c` | `1cadbfecc09b015f1675b1560be23856581904a1162d2d0810ab0d1abb115bd5` |
| Contained interpreter executable | `91d5e8a79c0a0d630dde96cfb499252d4a766f7e1ea751e08d9184c23993c30e` |

The source archive was downloaded from
[the exact upstream release](https://cpan.metacpan.org/src/5.0/perl-5.42.3.tar.gz).
Its hash matches the recorded fixed-output source producer. The compilation
file has the fixes from [03f74bb](https://github.com/Perl/perl5/commit/03f74bbbd3a68350d926ee93d56ee4808c28c4c7)
and [5e7f119](https://github.com/Perl/perl5/commit/5e7f119eb2bb1181be908701f22bf7068e722f1c).
Applying the three recorded Perl patches leaves that file's hash unchanged.
The additional CVE-2026-15534 patches affect `regexec.c`.

Each reviewed environment wrapper resolves to
`/nix/store/llas6flzd2875r7zzhhvwnynwqi349jb-perl-5.42.3/bin/perl`.
The recorded wrapper producer's chosen outputs and launch command identify the
same interpreter. Executing the exact wrappers confirmed that path. The
interpreter reports `ptrsize=8` and `sizesize=8`, and its ELF header is 64-bit.
These observations support the review, but the rules use the verified source
fixes rather than a blanket architecture exemption.

The matched manual output belongs to that same fixed interpreter producer.
Its classification relies on the source fix; it is not a general exemption for
manual or documentation outputs. A new environment wrapper, alternate
interpreter or producer digest requires its own review even if its version
label remains `5.42.3`.

### libssh2: one verified upstream backport

The libssh2 1.11.1 instance includes the fix for CVE-2026-7598 from
[upstream commit 256d04b](https://github.com/libssh2/libssh2/commit/256d04b60d80bf1190e96b0ad1e91b2174d744b1).
The installed patch payload is byte-for-byte identical to that commit's diff.
Applying all 11 recorded patches to the exact source archive preserves the three
authentication bounds checks.

| Reviewed evidence | SHA256 |
| --- | --- |
| `libssh2-1.11.1.tar.gz` | `d9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7` |
| CVE-2026-7598 patch payload | `70c6da78d7fb589f87f2c8b2e8eb1c82619c53122d1708d7e218478334eeb695` |
| Final `src/userauth.c` after all patches | `4fff87fde157b9936c536fe545c2966a1b2d7f4e387db352849220020f98eadc` |
| Installed `libssh2.so.1.0.1` | `efa041e8fd910fa6eeb9bcc7eb3ce8626998e20f9ac9d2700cf79a2c464e0ade` |

The first hunk applies with fuzz 1 using normal Nixpkgs patch flags; subsequent
hunks use line offsets. A separate fuzz-0 attempt failed. The successful check
reconstructed the complete patch chain and inspected the resulting guards; it
does not claim that fuzz-0 application passed. A patch filename containing a CVE
number is insufficient evidence.

The dependency graph includes curl, libgit2, nmap and the restore appliance.
Host SSH login settings do not prove those consumers avoid libssh2 password
authentication. The fixed-source decision does not depend on that assumption.

## npm findings: five remain UNKNOWN

No npm applicability rules are included. The reviewed installed XO output is
`/nix/store/pmy7arxjj9zdwzxgbh31i4b53cax82cs-xen-orchestra-ce-6.9.1`.
Other package channels and outputs must repeat the checks against their actual
installed trees.

| Finding | Installed version | Evidence needed for a different classification |
| --- | --- | --- |
| [tar GHSA-23hp-3jrh-7fpw](https://github.com/isaacs/node-tar/security/advisories/GHSA-23hp-3jrh-7fpw) | 6.2.1 | An actual fixed root dependency, or complete resolved runtime roots and imports proving the affected root copy cannot be invoked. |
| [Handlebars GHSA-8r5x-fm3f-whwj](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-8r5x-fm3f-whwj) | 4.7.9 | Exact consumer and template identities proving every compile/partial input is an immutable UTF-8 string; effective plugin roots must exclude unreviewed consumers. |
| [Handlebars GHSA-p8wg-vrv2-v86f](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-p8wg-vrv2-v86f) | 4.7.9 | Exact consumers proving restrictive prototype permissions, immutable templates, and no unreviewed runtime wrappers or plugins. |
| [proxy-addr GHSA-jqcg-44mw-7w3h](https://github.com/jshttp/proxy-addr/security/advisories/GHSA-jqcg-44mw-7w3h) | 2.0.7 | An actual fixed dependency, or enforced effective forwarded-header trust settings with all configuration layers bound to the runtime context. |
| [shell-quote GHSA-pqg4-j6r4-53mv](https://github.com/ljharb/shell-quote/security/advisories/GHSA-pqg4-j6r4-53mv) | 1.8.4 | An actual fixed dependency, or a complete runtime graph and code proof excluding its affected quote-to-shell flow. |

Built-in XO report plugins read immutable templates as UTF-8 strings and use
ordinary Handlebars calls. These inspected consumers support possible
conditional decisions, but do not establish the effective deployed plugin root
set. Shipped XO configuration permits additional plugin lookup locations.
Unreviewed plugins or other consumers invalidate a server-only argument.

The shipped proxy-addr setting `['loopback']` is a reviewed safe configuration.
An exact-runtime probe distinguished it from an unsafe mapped-IPv6 trust subnet.
Maestro does not yet prove that every effective configuration layer retains that
safe setting. Management network restrictions do not supply the missing proof.

The backups workspace resolves a separate fixed tar 7.5.22 copy. That does not
fix the flagged root tar 6.2.1 copy. Traversing the installed server/plugin
dependency graph also excludes root tar and shell-quote from that declared graph,
but dynamic plugin discovery prevents treating it as a complete call graph.

## Gate acceptance

The evaluator must preserve all raw findings, validate their inventory bindings,
and make changed, missing, ambiguous, malformed or expired proof fail closed.
The nine native rules may attach `fixed`; the five npm findings must remain
UNKNOWN until verified guards or dependency fixes are available. Report mode
must continue to show those unresolved findings. An enforce-mode assessment
must reject unresolved critical findings; enabling production enforcement still
requires the planned acceptance checks.

Acceptance covers exact native matches; advisory/source/output/patch drift;
expired reviews; missing or conflicting inventory evidence; unresolved npm
findings; and configuration drift for any future conditional rule. Neither
repository may infer safety solely from NixOS, a package name, a component's
version suffix, a disabled plugin observed once, or an operator-supplied exposure
boolean.
