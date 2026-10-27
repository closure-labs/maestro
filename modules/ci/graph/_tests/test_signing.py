#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Signing accepts only the exact scheduling mode and current protected producer."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

SIGNER = Path(os.environ.get('MAESTRO_SIGNER_SOURCE', Path(__file__).parents[4] /
                           'modules/features/installer/_source/sign-check.sh'))


class SigningMode(unittest.TestCase):
    def execute(self, expected='active', actual='active', revision=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer = dict(GITHUB_REPOSITORY='closure-labs/maestro', GITHUB_SHA=revision or 'a' * 40,
                            GITHUB_RUN_ID='9', GITHUB_RUN_ATTEMPT='1')
            value = dict(schemaVersion=1, planSha256='b' * 64, producer=producer,
                         completeValidationRequired=True, schedulingMode=actual)
            data = json.dumps(value).encode()
            (root / 'ci-result.json').write_bytes(data)
            (root / 'maestro-qualification-state.json').write_text(json.dumps({'source_commit': 'a' * 40}))
            binary = root / 'bin'
            binary.mkdir()
            validate = binary / 'maestro-ci-validate-state'
            validate.write_text('#!' + shutil.which('bash') + '\nexit 0\n')
            validate.chmod(0o755)
            gh = binary / 'gh'
            gh.write_text('#!' + sys.executable + '\n' + '''
import json,os,sys
assert sys.argv[1] == 'api'
sha=os.environ['GITHUB_SHA']
print(json.dumps({'protected':True,'commit':{'sha':sha}} if '/branches/' in sys.argv[2]
                 else {'merge_base_commit':{'sha':sha}}))
''')
            gh.chmod(0o755)
            env = dict(os.environ, **dict(producer, GITHUB_SHA='a' * 40),
                       GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='push',
                       GRAPH_RESULT_REQUIRED='true', CI_RESULT_SHA256=hashlib.sha256(data).hexdigest(),
                       CI_GRAPH_PLAN_SHA256='b' * 64, GRAPH_SCHEDULING_MODE=expected,
                       PATH=str(binary)+os.pathsep+os.environ['PATH'])
            return subprocess.run(['bash', str(SIGNER)], cwd=root, env=env, capture_output=True).returncode

    def test_mode_and_producer_remain_mandatory_after_digest_validation(self):
        self.assertEqual(self.execute(), 0)
        self.assertEqual(self.execute(expected='shadow', actual='shadow'), 0)
        self.assertNotEqual(self.execute(expected='shadow'), 0)
        self.assertNotEqual(self.execute(actual='shadow'), 0)
        self.assertNotEqual(self.execute(expected='unknown', actual='unknown'), 0)
        self.assertNotEqual(self.execute(revision='c' * 40), 0)


if __name__ == '__main__':
    unittest.main()
