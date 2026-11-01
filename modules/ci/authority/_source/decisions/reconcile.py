#!/usr/bin/env python3
"""Persist authenticated evidence and propose bounded App-authored human decisions."""
import sys
import os
import security_recovery
from pathlib import Path
from common import parser, config, require, emit, run
from reconciliation import reconcile


def main():
    cli = parser(__doc__)
    cli.add_argument('--scans', type=Path)
    cli.add_argument('--product', type=Path)
    cli.add_argument('--directory', type=Path)
    cli.add_argument('--kind', choices=('security-findings', 'security-revocation', 'release-product'), required=True)
    cli.add_argument('--rationale', default='Review the complete authenticated native evidence and exact proposed scope.')
    cli.add_argument('--disposition', choices=('accepted', 'rejected'), default='accepted')
    cli.add_argument('--decision-hash')
    cli.add_argument('--security-recovery', type=Path, help='Explicit complete recovery request JSON')
    args = cli.parse_args()
    cfg = config(args.config, live=True)
    require(args.rationale.strip(), 'Decision rationale required')
    recovery = None
    request = os.environ.get('SECURITY_RECOVERY_REQUEST', '')
    if request:
        require(args.security_recovery is None and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and os.environ.get('GITHUB_REF') == 'refs/heads/main',
                'Hosted recovery requires explicit protected-main manual dispatch')
        recovery = security_recovery.load_request(request)
    elif args.security_recovery is not None:
        recovery = security_recovery.load_request(args.security_recovery.read_text())
    if recovery is not None:
        args.rationale, args.disposition = recovery['rationale'], recovery['disposition']
    directory = args.directory or (args.scans.parent if args.scans else Path('.'))
    emit(reconcile(cfg, args.scans, args.product, args.kind, directory, args.rationale,
                   args.disposition, args.decision_hash, recovery=recovery), args.output)


if __name__ == '__main__':
    sys.exit(run(main))
