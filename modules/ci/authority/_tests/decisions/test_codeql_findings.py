#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded negative fixtures for report authenticity and explicit human acceptance."""
import copy
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / 'modules/ci/authority/_source/decisions'))
import codeql_findings as mod

REPO = 'closure-labs/maestro'
HEAD, QUEUE, WORKFLOW = 'a' * 40, 'b' * 40, 'c' * 40


def sarif(findings=False):
    rule = {'id': 'py/security', 'properties': {'security-severity': '9.0'}}
    results = [{'ruleId': rule['id'], 'message': {'text': 'review required'},
                'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'file.py'},
                                                   'region': {'startLine': 1}}}]}] if findings else []
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL', 'rules': [rule]}},
                                       'results': results}]}


def archive(doc, name='results.sarif'):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as zipped:
        zipped.writestr(name, json.dumps(doc))
    return output.getvalue()


class API:
    def __init__(self, findings=False, target=HEAD):
        self.target = target
        self.workflow = WORKFLOW
        self.runs = [{'id': 42, 'run_attempt': 1, 'path': mod.WORKFLOW, 'head_sha': target,
                      'repository': {'full_name': REPO}, 'status': 'completed', 'conclusion': 'success',
                      'event': 'pull_request' if target == HEAD else 'merge_group',
                      'run_started_at': '2026-11-09T06:00:00Z'}]
        self.payloads = {index: archive(sarif(findings and index == 1)) for index in range(1, 5)}
        self.artifacts = [dict(id=index, name='codeql-' + language + '-1', expired=False,
                               size_in_bytes=len(self.payloads[index]),
                               digest='sha256:' + hashlib.sha256(self.payloads[index]).hexdigest(),
                               workflow_run={'id': 42, 'head_sha': target},
                               created_at='2026-11-09T06:01:00Z')
                          for index, language in enumerate(mod.LANGUAGES, 1)]
        self.jobs = [dict(name='Scan (actions)' if lang == 'actions' else f'Analyze ({lang})',
                          run_id=42, run_attempt=1, head_sha=target, status='completed', conclusion='success')
                     for lang in mod.LANGUAGES]
        self.calls = []

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        if '/actions/workflows/codeql.yml/runs?' in endpoint:
            return {'total_count': len(self.runs), 'workflow_runs': self.runs}
        if '/attempts/' in endpoint and '/jobs?' in endpoint:
            return {'total_count': len(self.jobs), 'jobs': self.jobs}
        if '/contents/' in endpoint:
            return {'type': 'file', 'sha': WORKFLOW if endpoint.endswith('ref=main') else self.workflow}
        if endpoint.endswith('/artifacts?per_page=100'):
            return {'total_count': len(self.artifacts), 'artifacts': self.artifacts}
        raise AssertionError(endpoint)

    def load(self, repository, artifact_id):
        assert repository == REPO
        return self.payloads[artifact_id]

    def evidence(self):
        return mod.evidence(self, REPO, self.target, self.runs[0]['event'], self.load)

    def enforce(self):
        return mod.enforce(self, REPO, 7, HEAD, self.target, self.load)


class Findings(unittest.TestCase):
    def test_two_stage_protocol_can_only_opt_in_not_opt_out(self):
        plain = '# SPDX-License-Identifier: Apache-2.0\nname: CodeQL Advanced\n'
        marked = '# maestro-codeql-findings-protocol: 1\n' + plain
        def blob(text):
            raw = text.encode()
            return {'type': 'file', 'path': mod.WORKFLOW, 'encoding': 'base64', 'size': len(raw),
                    'content': base64.b64encode(raw).decode(),
                    'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        for main, candidate, expected in [(plain, plain, False), (plain, marked, True),
                                          (marked, plain, True), (marked, marked, True)]:
            def read(endpoint):
                return blob(main if endpoint.endswith('ref=main') else candidate)
            self.assertIs(mod.enabled(read, REPO, HEAD), expected)
        for bad in [dict(blob(marked), sha='f' * 40), dict(blob(marked), encoding='none'),
                    dict(blob(marked), size=True), dict(blob(marked), content='!!!'),
                    blob('# maestro-codeql-findings-protocol: 2\n'),
                    blob('# maestro-codeql-findings-protocol: 1\n' * 2)]:
            with self.subTest(bad=bad), self.assertRaises((mod.authority.AuthorityError, ValueError)):
                mod.enabled(lambda _: bad, REPO, HEAD)

    def test_clean_reports_need_no_extra_review(self):
        api = API()
        with mock.patch.object(mod.authority, 'approval') as approval:
            self.assertEqual(api.enforce()['count'], 0)
            approval.assert_not_called()

    def test_findings_acceptance_is_one_normal_exact_head_review(self):
        api = API(True)
        digest = api.evidence()['digest']
        body = f'/maestro accept-codeql {HEAD} {digest}'
        with mock.patch.object(mod.authority, 'approval', return_value={'state': 'APPROVED', 'body': body}) as approval:
            self.assertEqual(api.enforce()['count'], 1)
            approval.assert_called_once_with(api, REPO, 7, HEAD)

    def test_ordinary_approval_cannot_accept_findings(self):
        api = API(True)
        for review in [{'state': 'APPROVED', 'body': ''}, {'state': 'COMMENTED', 'body': 'accept'},
                       {'state': 'APPROVED', 'body': f'/maestro accept-codeql {HEAD} ' + 'f' * 64},
                       {'state': 'APPROVED', 'body': f'/maestro accept-codeql {QUEUE} {api.evidence()["digest"]}'}]:
            with self.subTest(review=review), mock.patch.object(mod.authority, 'approval', return_value=review):
                with self.assertRaises(mod.authority.AuthorityError):
                    api.enforce()

    def test_current_eligible_human_authority_is_not_cached(self):
        api = API(True)
        with mock.patch.object(mod.authority, 'approval', side_effect=mod.authority.AuthorityError('dismissed')):
            with self.assertRaises(mod.authority.AuthorityError):
                api.enforce()

    def test_identical_queue_findings_share_exact_head_acceptance(self):
        pr, queue = API(True), API(True, QUEUE)
        self.assertEqual(pr.evidence()['digest'], queue.evidence()['digest'])
        body = f'/maestro accept-codeql {HEAD} {pr.evidence()["digest"]}'
        with mock.patch.object(mod.authority, 'approval', return_value={'state': 'APPROVED', 'body': body}):
            self.assertEqual(queue.enforce()['count'], 1)

    def test_codeql_extension_rules_and_reference_identity(self):
        doc = sarif(True)
        tool = doc['runs'][0]['tool']
        tool['extensions'] = [{'name': 'codeql/python-queries', 'rules': tool['driver']['rules']}]
        tool['driver']['rules'] = []
        finding = doc['runs'][0]['results'][0]
        finding['rule'] = {'id': finding['ruleId'], 'index': 0, 'toolComponent': {'index': 0}}
        self.assertEqual(len(mod.parse_sarif(json.dumps(doc).encode(), 'python')), 1)
        finding['rule']['toolComponent']['index'] = 1
        with self.assertRaises(mod.authority.AuthorityError):
            mod.parse_sarif(json.dumps(doc).encode(), 'python')

    def test_suppression_and_levels_never_silence_a_finding(self):
        doc = sarif(True)
        doc['runs'][0]['results'][0].update(level='none', baselineState='unchanged',
                                         suppressions=[{'kind': 'inSource', 'status': 'accepted'}])
        self.assertEqual(len(mod.parse_sarif(json.dumps(doc).encode(), 'python')), 1)

    def test_rule_or_full_finding_changes_change_digest(self):
        original = mod.parse_sarif(json.dumps(sarif(True)).encode(), 'python')
        for mutate in [lambda r: r['results'][0]['message'].update(text='different'),
                       lambda r: r['tool']['driver']['rules'][0]['properties'].update(**{'security-severity': '8.0'}),
                       lambda r: r['results'][0].update(codeFlows=[{'threadFlows': []}])]:
            doc = sarif(True)
            mutate(doc['runs'][0])
            self.assertNotEqual(mod.canonical(original), mod.canonical(mod.parse_sarif(json.dumps(doc).encode(), 'python')))

    def test_changed_workflow_requires_explicit_acceptance_even_when_clean(self):
        api = API()
        original = api.evidence()['digest']
        api.workflow = 'd' * 40
        report = api.evidence()
        self.assertTrue(report['workflowChanged'])
        self.assertNotEqual(report['digest'], original)
        with mock.patch.object(mod.authority, 'approval', return_value={'state': 'APPROVED', 'body': ''}):
            with self.assertRaises(mod.authority.AuthorityError):
                api.enforce()
        body = f'/maestro accept-codeql {HEAD} {report["digest"]}'
        with mock.patch.object(mod.authority, 'approval', return_value={'state': 'APPROVED', 'body': body}):
            self.assertEqual(api.enforce()['count'], 0)

    def test_missing_duplicate_expired_wrong_origin_and_corrupt_artifacts(self):
        mutations = [lambda a: a.artifacts.pop(), lambda a: a.artifacts.append(a.artifacts[0]),
                     lambda a: a.artifacts[0].update(expired=True),
                     lambda a: a.artifacts[0]['workflow_run'].update(head_sha=QUEUE),
                     lambda a: a.artifacts[0]['workflow_run'].update(id=99),
                     lambda a: a.artifacts[0].update(id=True),
                     lambda a: a.artifacts[0].update(size_in_bytes=mod.MAX_BYTES + 1),
                     lambda a: a.artifacts[0].update(digest=''),
                     lambda a: a.payloads.update({1: b'corrupt'}),
                     lambda a: a.artifacts[0].update(created_at='2026-11-09T05:59:59Z')]
        for mutate in mutations:
            api = API()
            mutate(api)
            with self.subTest(mutation=mutate), self.assertRaises(mod.authority.AuthorityError):
                api.enforce()

    def test_bad_producer_cannot_reuse_older_green_run(self):
        for mutation in [dict(conclusion='failure'), dict(status='cancelled'), dict(head_sha=QUEUE),
                         dict(path='.github/workflows/fake.yml'), dict(event='push'),
                         dict(repository={'full_name': 'other/repo'}), dict(run_attempt=True)]:
            api = API()
            api.runs.append(dict(api.runs[0], id=43, **mutation))
            with self.subTest(mutation=mutation), self.assertRaises(mod.authority.AuthorityError):
                api.enforce()

    def test_analysis_change_during_download_fails(self):
        api = API()
        def load(repo, artifact_id):
            if artifact_id == 4:
                api.runs[0]['run_attempt'] += 1
            return api.load(repo, artifact_id)
        # API fixtures must imitate independent JSON API snapshots.
        def snapshot(endpoint):
            return copy.deepcopy(api(endpoint))
        with self.assertRaises(mod.authority.AuthorityError):
            mod.enforce(snapshot, REPO, 7, HEAD, HEAD, load)

    def test_bad_sarif_fails_closed(self):
        cases = [{}, {'version': '2.1.0', 'runs': []}]
        for mutate in [lambda r: r.pop('results'), lambda r: r['tool']['driver'].update(name='fake'),
                       lambda r: r['results'][0].update(ruleId='unknown'),
                       lambda r: r.update(invocations=[{'executionSuccessful': False}]),
                       lambda r: r['tool']['driver']['rules'].append(r['tool']['driver']['rules'][0])]:
            doc = sarif(True)
            mutate(doc['runs'][0]); cases.append(doc)
        for doc in cases:
            with self.subTest(doc=doc), self.assertRaises(mod.authority.AuthorityError):
                mod.parse_sarif(json.dumps(doc).encode(), 'python')
        with self.assertRaises(mod.authority.AuthorityError):
            mod.parse_sarif(b'{"version":"2.1.0","version":"2.1.0","runs":[]}', 'python')

    def test_unsafe_zip_members_and_oversize_are_rejected(self):
        for name in ['../results.sarif', '/results.sarif', 'dir/results.sarif', 'results.txt', '.hidden.sarif', 'a\\b.sarif']:
            with self.subTest(name=name), self.assertRaises(mod.authority.AuthorityError):
                mod.parse_archive(archive(sarif(), name), 'python')
        with mock.patch.object(mod, 'MAX_BYTES', 4), self.assertRaises(mod.authority.AuthorityError):
            mod.parse_archive(b'oversized', 'python')

    def test_transport_and_parser_exceptions_become_blocking_authority_errors(self):
        for error in [OSError('private transport details'), zipfile.BadZipFile('bad'), RuntimeError('compression')]:
            api = API()
            with mock.patch.object(mod, 'evidence', side_effect=error):
                with self.assertRaisesRegex(mod.authority.AuthorityError, 'could not be authenticated'):
                    api.enforce()


if __name__ == '__main__':
    unittest.main()
