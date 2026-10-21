# Maestro release recovery

archetype: infra
secondary: devtools
approval-level: gates-only
phase: review
size: small
mode: production

Fix current qualification and publication failures across Maestro and xo-nixpkg.
Simplify CI, scans and caching where exact product identity, complete current
security evidence and live human release authority remain independently verified.
Use isolated checkouts and jj. Preserve existing operator branches and policies.
QA and security review must pass before proposing publication. Native protected
main and human decision checks remain authoritative for hosted release actions.
