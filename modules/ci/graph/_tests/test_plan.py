#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise native graph fallback with real immutable Git archives and fake Nix."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import shutil
import sys
import tempfile
import unittest

from test_graph import fixture, graph
from test_verdict import route

SOURCE = Path(__file__).parents[1] / '_source'


class NativePlan(unittest.TestCase):
    def execute(self, *, active=True, unknown_base=False, legacy=False, unmapped=False,
                force=False, fork=False, validate_only=False, retained=False, bad_native=False, interrupted=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                       PYTHONDONTWRITEBYTECODE='1')
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, env=env, text=True).strip()
            git('init', '-q')
            git('config', 'user.name', 'Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            candidate = fixture()
            if active:
                candidate.update(mode='active', gatingEnabled=True)
            base = fixture()
            if unknown_base:
                base['schemaVersion'] = 99
            (root / 'docs').mkdir()
            (root / 'docs/feature-outputs.md').write_text(graph.ownership(candidate))
            (root / 'README.md').write_text('fixture\n')
            git('add', '.')
            git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'base')
            base_revision = git('rev-parse', 'HEAD')
            changed = root / ('future/unknown.nix' if unmapped else 'docs/change.md')
            changed.parent.mkdir(exist_ok=True)
            changed.write_text('fixture change\n')
            git('add', '.')
            git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'candidate')
            revision = git('rev-parse', 'HEAD')
            (root / 'candidate-graph.json').write_text(json.dumps(candidate))
            (root / 'base-graph.json').write_text(json.dumps(base))
            initial = route('skip' if validate_only else 'reuse')
            if retained:
                initial['retained_evidence'] = {'schema': 1}
            if legacy:
                initial.pop('retained_evidence')
                initial['schema_version'] = 3
            (root / 'maestro-qualification-state.json').write_text(json.dumps(
                {'source_commit': 'a' * 40, 'artifact_run_id': 1}))
            binary = root / 'bin'
            binary.mkdir()
            def executable(name, content):
                p = binary / name
                p.write_text(content)
                p.chmod(0o755)
            executable('nix', '#!' + sys.executable + '\n' + '''
import os,sys
from pathlib import Path
if sys.argv[1] == 'eval':
    kind = 'base' if '/base#' in sys.argv[-1] else 'candidate'
    print(Path(os.environ['FIXTURE_ROOT'],kind+'-graph.json').read_text())
elif sys.argv[1:3] == ['derivation','show']:
    print('{}')
else:
    raise RuntimeError('Unexpected Nix work: '+repr(sys.argv))
''')
            executable('maestro-ci-graph', '#!' + shutil.which('bash') + '\nexec ' + shlex.quote(sys.executable)
                       + ' ' + shlex.quote(str((SOURCE / 'graph.py').resolve())) + ' "$@"\n')
            executable('maestro-ci-route', '#!' + sys.executable + '\n' + '''
import json,os
from pathlib import Path
assert os.environ['FORCE_BUILD'] == 'true'
assert os.environ['FORCE_ARTIFACT'] == 'true'
assert os.environ['ALLOW_REUSE'] == 'false'
if os.environ['FIXTURE_INTERRUPT'] == 'true':
    raise SystemExit(1)
value=json.loads(os.environ['CI_PLAN'])
value.update(schema_version=4, retained_evidence=None)
value['qualification'].update(required=True,mode='qualify-media',artifact_run_id=99,
    media_run_id=99,evidence_run_id=99,media_input='a'*64,evidence_input='b'*64)
if os.environ['FIXTURE_BAD_NATIVE'] == 'true':
    value['qualification']['mode']='reuse'
Path(os.environ['MAESTRO_CI_ROUTE_OUTPUT']).write_text(json.dumps(value))
Path('maestro-qualification-state.json').write_text(json.dumps(
    {'source_commit':os.environ['GITHUB_SHA'],'artifact_run_id':99}))
''')
            output = root / 'outputs.txt'
            output.touch()
            env.update(PATH=str(binary) + os.pathsep + os.environ['PATH'], FIXTURE_ROOT=str(root),
                       FIXTURE_BAD_NATIVE=str(bad_native).lower(), FIXTURE_INTERRUPT=str(interrupted).lower(),
                       GITHUB_SHA=revision, GITHUB_RUN_ID='99', GITHUB_EVENT_NAME='workflow_dispatch',
                       GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY='', RUNNER_TEMP=str(root),
                       MAESTRO_SYSTEM_ROOT=str(root), MAESTRO_GRAPH_OUTPUT='ci-graph',
                       MERGE_BASE_SHA='', PR_BASE_SHA='', PUSH_BASE_SHA='',
                       FORCE_BUILD=str(force).lower(), FORCE_ARTIFACT=str(force).lower(),
                       GRAPH_FORK=str(fork).lower(), VALIDATE_ONLY=str(validate_only).lower(),
                       CI_PLAN=json.dumps(initial))
            result = subprocess.run(['bash', str((SOURCE / 'plan.sh').resolve())], cwd=root, env=env,
                                    capture_output=True, text=True)
            plan = json.loads((root / 'ci-graph/plan.json').read_text())
            final = json.loads((root / 'ci-graph/route.json').read_text())
            state = json.loads((root / 'maestro-qualification-state.json').read_text())
            outputs = dict(line.split('=', 1) for line in output.read_text().splitlines())
            return result, plan, final, state, outputs, revision, base_revision

    def test_exact_native_reuse_never_claims_its_authority_from_derivation_equality(self):
        result, plan, final, state, outputs, revision, base = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(plan['candidateRevision'], revision)
        self.assertEqual(plan['baseRevision'], base)
        self.assertFalse(plan['evidenceReuseAuthorized'])
        self.assertFalse(plan['routeRegenerated'])
        self.assertEqual(state['artifact_run_id'], 1)
        self.assertFalse(plan['decisions']['jobs']['appliance']['required'])
        self.assertTrue(plan['decisions']['jobs']['scan']['required'])
        self.assertEqual(json.loads(outputs['route_plan']), final)
        self.assertEqual(json.loads(outputs['job_plan']), plan['decisions']['jobs'])
        self.assertEqual(plan['decisions']['routePlanSha256'], graph.digest(final))

    def test_fallback_regenerates_both_plan_and_current_producer_state(self):
        for case in ({'unknown_base': True}, {'legacy': True}, {'unmapped': True},
                     {'force': True}, {'fork': True}, {'retained': True}):
            with self.subTest(case=case):
                result, plan, final, state, outputs, revision, _ = self.execute(**case)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(plan['completeQualificationRequired'])
                self.assertTrue(plan['routeRegenerated'])
                self.assertTrue(plan['fallbackReasons'])
                self.assertEqual(final['qualification']['mode'], 'qualify-media')
                self.assertEqual(final['qualification']['artifact_run_id'], 99)
                self.assertEqual(state, {'source_commit': revision, 'artifact_run_id': 99})
                self.assertTrue(plan['decisions']['jobs']['installer']['required'])
                self.assertEqual(json.loads(outputs['route_plan']), final)
                self.assertEqual(plan['decisions']['routePlanSha256'], graph.digest(final))

    def test_explicit_validation_only_is_preserved_but_force_overrides_it(self):
        result, plan, final, _, _, _, _ = self.execute(validate_only=True, unknown_base=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(plan['completeQualificationRequired'])
        self.assertEqual(final['qualification']['mode'], 'skip')
        result, plan, final, _, _, _, _ = self.execute(validate_only=True, force=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(plan['routeRegenerated'])
        self.assertEqual(final['qualification']['mode'], 'qualify-media')

    def test_shadow_retains_legacy_native_routing(self):
        result, plan, final, state, _, _, _ = self.execute(active=False, legacy=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(plan['gatingEnabled'])
        self.assertFalse(plan['routeRegenerated'])
        self.assertEqual(final['schema_version'], 3)
        self.assertEqual(state['artifact_run_id'], 1)

    def test_bad_or_interrupted_native_fallback_cannot_emit_gate_outputs(self):
        for case in ({'bad_native': True}, {'interrupted': True}):
            with self.subTest(case=case):
                result, _, _, _, outputs, _, _ = self.execute(unknown_base=True, **case)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('manifest_sha256', outputs)
                self.assertNotIn('route_plan', outputs)


if __name__ == '__main__':
    unittest.main()
