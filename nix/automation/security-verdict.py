#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Source-bound vulnerability decisions; report mode never hides scan errors."""
from datetime import date
import json
import re
import sys


SEVERITIES = {"critical", "high", "medium", "low", "negligible", "unknown"}
KEYS = {"advisory", "component", "version", "severity", "identity"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def finding(record):
    require(all(isinstance(record.get(k), str) and record[k] for k in KEYS), "missing finding identity")
    require(record["severity"] in SEVERITIES, "invalid severity")
    require(re.fullmatch(r"[0-9a-f]{64}", record["identity"]) is not None, "invalid source identity")
    return tuple(record[k] for k in sorted(KEYS))


def evaluate(findings, policy, today=None):
    today = today or date.today()
    require(isinstance(policy, dict) and set(policy) == {"schema_version", "mode", "dispositions", "exceptions"}, "invalid policy shape")
    require(policy["schema_version"] == 2 and policy["mode"] in {"report", "enforce"}, "invalid policy version/mode")
    accepted = set()
    for category in ["dispositions", "exceptions"]:
        require(isinstance(policy[category], list), "invalid policy records")
        for record in policy[category]:
            require(isinstance(record, dict), "invalid policy record")
            fields = KEYS | {"owner", "reason", "evidence", "created", "expires"}
            if category == "dispositions":
                fields.add("kind")
                require(record.get("kind") in {"fixed", "not_affected"}, "invalid disposition kind")
            require(set(record) == fields, "unexpected policy record fields")
            key = finding(record)
            require(key not in accepted, "duplicate policy decision")
            require(all(isinstance(record.get(k), str) and record[k].strip() for k in ["owner", "reason"]), "missing decision owner/reason")
            require(isinstance(record["evidence"], list) and record["evidence"] and all(isinstance(url, str) and url.startswith("https://") for url in record["evidence"]), "missing decision evidence")
            created, expires = date.fromisoformat(record["created"]), date.fromisoformat(record["expires"])
            require(created <= today < expires, "expired or future security decision")
            require(0 < (expires - created).days <= 30, "security decisions expire within 30 days")
            accepted.add(key)
    require(isinstance(findings, list), "invalid findings")
    seen, violations = set(), []
    for record in findings:
        require(isinstance(record, dict), "invalid finding record")
        key = finding(record)
        require(key not in seen, "duplicate finding instance")
        seen.add(key)
        if record["severity"] in {"high", "critical", "unknown"} and key not in accepted:
            violations.append(record)
    return violations


if __name__ == "__main__":
    try:
        with open(sys.argv[1]) as handle:
            findings = json.load(handle)
        with open(sys.argv[2]) as handle:
            policy = json.load(handle)
        violations = evaluate(findings, policy)
        print(json.dumps(violations, indent=2, sort_keys=True))
        if policy["mode"] == "enforce" and violations:
            print("High/critical/unscored findings require an exact source-bound decision or remediation.", file=sys.stderr)
            sys.exit(1)
        if policy["mode"] == "report":
            print("Security policy is report-only until inventory, remediation and deployment gates pass.", file=sys.stderr)
    except (ValueError, KeyError, TypeError, IndexError) as error:
        print(f"Invalid security policy/findings: {error}", file=sys.stderr)
        sys.exit(2)
