#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the pinned scanner; confirm ledger-key exceptions against complete lines."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

LEDGER = re.compile(r'automation/decisions/security/[a-f0-9]{64}\.json')
KEY_LINE = re.compile(rb'          "key": "[a-f0-9]{64}",\n?')
REPORT_LIMIT = 16 * 1024 * 1024


def canonical_key(root, finding):
    if not isinstance(finding, dict) or finding.get('RuleID') != 'generic-api-key':
        return False
    name, number = finding.get('File'), finding.get('StartLine')
    if (not isinstance(name, str) or not LEDGER.fullmatch(name)
            or type(number) is not int or not 1 <= number <= 2_000_000
            or finding.get('EndLine') != number):
        return False
    path = root / name
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        return False
    # A fragmented scanner context may end inside the public digest. Never
    # relax the expression to match that partial context: use the original
    # complete line with the same canonical path and shape as .gitleaks.toml.
    with path.open('rb') as stream:
        for index in range(1, number + 1):
            line = stream.readline(1024 * 1024 + 1)
            if not line or len(line) > 1024 * 1024:
                return False
            if index == number:
                return KEY_LINE.fullmatch(line) is not None
    return False


def main():
    root = Path.cwd()
    with tempfile.TemporaryDirectory(prefix='maestro-source-security-') as temporary:
        report = Path(temporary) / 'redacted.json'
        result = subprocess.run(['gitleaks', 'dir', '--redact', '--no-banner',
                                 '--config', str(root / '.gitleaks.toml'), '--report-format', 'json',
                                 '--report-path', str(report), '.'], check=False)
        if result.returncode not in (0, 1):
            return result.returncode if result.returncode > 0 else 1
        if not report.is_file() or report.stat().st_size > REPORT_LIMIT:
            raise ValueError('Missing or oversized source-security report')
        findings = json.loads(report.read_text())
        if not isinstance(findings, list) or len(findings) > 10_000:
            raise ValueError('Invalid source-security report')
        if result.returncode == 1 and not findings:
            raise ValueError('Failed source scan has no findings')
        if result.returncode == 0 and findings:
            raise ValueError('Successful source scan has unexpected findings')
        remaining = sum(not canonical_key(root, finding) for finding in findings)
        print(f'Source security: {remaining} findings; {len(findings) - remaining} canonical ledger identities confirmed.')
        return 1 if remaining else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError):
        raise SystemExit('Source-security verification failed (details withheld)')
