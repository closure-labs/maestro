# SPDX-License-Identifier: Apache-2.0
"""Exact exception for a notification-only workflow; no repository code executes."""
from pathlib import Path
import sys

RELAY='''# SPDX-License-Identifier: Apache-2.0
name: Collect maintainer decision events
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review, edited]
  pull_request_review:
    types: [submitted, edited, dismissed]
  pull_request_review_comment:
    types: [created, edited, deleted]
  issue_comment:
    types: [created, edited, deleted]
  merge_group:
    types: [checks_requested]
permissions: {}
jobs:
  collect:
    if: github.event_name != 'issue_comment' || github.event.issue.pull_request != null
    runs-on: ubuntu-slim
    timeout-minutes: 5
    steps:
      - name: Signal repository activity
        run: printf '%s\\n' 'Repository activity observed.'
'''


def validate(text):
    if text != RELAY:
        raise ValueError('Signal relay must match the approved no-checkout/no-credential/no-write template')


if __name__=='__main__':
    validate(Path(sys.argv[1]).read_text())
