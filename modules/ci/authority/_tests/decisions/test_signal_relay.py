# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path
import unittest
CORE=Path(__file__).resolve().parents[5]
CORE = CORE / 'modules/ci/authority/_source/decisions'
sys.path.insert(0,str(CORE))
import signal_relay as relay

class Relay(unittest.TestCase):
    def test_workflow_and_audit_templates_match_notification_only_relay(self):
        root = CORE.parents[4]
        for path in ('.github/workflows/decision-events.yml', 'modules/ci/checks/_lib/signal-relay.yml'):
            relay.validate((root / path).read_text())
        for event in ('pull_request_review:', 'pull_request_review_comment:', 'issue_comment:'):
            self.assertIn(event, relay.RELAY)
        workflow = (root / '.github/workflows/decisions.yml').read_text()
        self.assertIn('Continue Maestro release, Verify maintainer decision authority]', workflow)
        self.assertIn('ref: main', workflow)
        self.assertIn("github.event.workflow_run.name != 'Verify maintainer decision authority'", workflow)
        self.assertIn("github.event.issue.pull_request != null", relay.RELAY)
        self.assertIn("github.event.workflow_run.head_branch == 'main'", workflow)

    def test_exception_rejects_checkout_secrets_data_writes_and_nix(self):
        for unsafe in ('uses: actions/checkout@evil','env: { TOKEN: "${{ secrets.TOKEN }}" }',
                       'run: nix run .#controller','uses: actions/download-artifact@evil',
                       'run: gh api --method POST fixture','run: echo "${{ github.event.pull_request.title }}"'):
            with self.subTest(unsafe=unsafe),self.assertRaises(ValueError):
                relay.validate(relay.RELAY+'      - '+unsafe+'\n')

if __name__=='__main__':unittest.main()
