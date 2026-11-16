# SPDX-License-Identifier: Apache-2.0
"""Read CodeQL evidence as bounded data; require explicit live human findings acceptance."""
import hashlib
import base64
import datetime as dt
import io
import json
import re
import resource
import stat
import subprocess
import tempfile
import time
import zipfile

import decision_authority as authority

WORKFLOW = '.github/workflows/codeql.yml'
LANGUAGES = ('actions', 'javascript-typescript', 'python', 'rust')
MAX_BYTES = 32 * 1024 * 1024
MAX_RESULTS = 10000


def require(ok, message):
    if not ok:
        raise authority.AuthorityError('CodeQL findings: ' + message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse_sarif(raw, language):
    require(len(raw) <= MAX_BYTES, 'oversized SARIF')
    doc = json.loads(raw, object_pairs_hook=unique_object,
                     parse_constant=lambda _: require(False, 'nonfinite JSON number'))
    require(isinstance(doc, dict) and doc.get('version') == '2.1.0', 'unsupported SARIF')
    runs = doc.get('runs')
    require(isinstance(runs, list) and len(runs) == 1, 'one complete SARIF run required per language')
    run = runs[0]
    require(isinstance(run, dict), 'invalid SARIF run')
    driver = run.get('tool', {}).get('driver', {})
    require(driver.get('name') == 'CodeQL', 'unexpected SARIF tool')
    extensions = run.get('tool', {}).get('extensions', [])
    require(isinstance(extensions, list) and len(extensions) <= 100, 'invalid tool extensions')
    components = [driver] + extensions
    by_id, components_by_id = {}, {}
    for component_index, component in enumerate(components):
        require(isinstance(component, dict), 'invalid tool component')
        rules = component.get('rules', [])
        require(isinstance(rules, list) and len(rules) <= MAX_RESULTS, 'oversized rule inventory')
        for index, rule in enumerate(rules):
            require(isinstance(rule, dict) and isinstance(rule.get('id'), str) and rule['id'] not in by_id,
                    'invalid or ambiguous rule')
            by_id[rule['id']] = rule
            components_by_id[rule['id']] = (component_index, index)
    invocations = run.get('invocations', [])
    require(isinstance(invocations, list), 'invalid invocation inventory')
    for invocation in invocations:
        require(isinstance(invocation, dict) and invocation.get('executionSuccessful') is not False,
                'unsuccessful analyzer invocation')
        require(not any(n.get('level') == 'error' for n in invocation.get('toolExecutionNotifications', [])),
                'analyzer error notification')
    results = run.get('results')
    require(isinstance(results, list) and len(results) <= MAX_RESULTS, 'missing or oversized results')
    findings = []
    for result in results:
        require(isinstance(result, dict), 'invalid finding')
        reference = result.get('rule', {})
        require(isinstance(reference, dict), 'invalid rule reference')
        rule_id = result.get('ruleId', reference.get('id'))
        require(isinstance(rule_id, str) and rule_id in by_id, 'finding has unknown rule')
        require(reference.get('id', rule_id) == rule_id, 'conflicting rule identity')
        component_index, index = components_by_id[rule_id]
        if 'index' in reference or 'ruleIndex' in result:
            actual_index = reference.get('index', result.get('ruleIndex'))
            require(type(actual_index) is int and actual_index == index
                    and result.get('ruleIndex', actual_index) == actual_index, 'conflicting rule index')
        if 'toolComponent' in reference:
            tool_component = reference['toolComponent']
            require(isinstance(tool_component, dict) and type(tool_component.get('index')) is int
                    and tool_component['index'] + 1 == component_index, 'conflicting rule component')
        # Do not trust baselineState, level or suppressions as an approval. Bind
        # the complete finding/rule data, including flows and related locations.
        findings.append({'language': language, 'rule': by_id[rule_id], 'result': result})
    return sorted(findings, key=canonical)


def parse_archive(raw, language):
    require(len(raw) <= MAX_BYTES, 'oversized artifact archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        require(len(members) == 1, 'exactly one SARIF member required')
        member = members[0]
        require(member.filename.endswith('.sarif') and '/' not in member.filename
                and '\\' not in member.filename and not member.filename.startswith('.')
                and not member.is_dir(), 'unsafe SARIF member')
        mode = member.external_attr >> 16
        require(not stat.S_ISLNK(mode) and member.file_size <= MAX_BYTES
                and member.compress_size <= MAX_BYTES and not member.flag_bits & 1,
                'unsafe or oversized SARIF member')
        with archive.open(member) as stream:
            raw = stream.read(MAX_BYTES + 1)
        return parse_sarif(raw, language)


def download(repository, artifact_id):
    require(type(artifact_id) is int and artifact_id > 0, 'invalid artifact ID')
    # gh follows the GitHub-issued artifact redirect. Never accept a URL from
    # SARIF or run commands/paths from the candidate artifact. Bound disk and time.
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BYTES, MAX_BYTES))
    with tempfile.TemporaryFile() as stream:
        result = subprocess.run(['gh', 'api', f'repos/{repository}/actions/artifacts/{artifact_id}/zip'],
                                stdout=stream, stderr=subprocess.DEVNULL, timeout=90,
                                check=False, preexec_fn=limits)
        require(result.returncode == 0, 'artifact download failed')
        stream.seek(0)
        return stream.read(MAX_BYTES + 1)


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value),
            'invalid evidence timestamp')
    return dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)


class AnalysisPending(authority.AuthorityError):
    """Only incomplete scanner work may be polled; errors fail closed."""


def scan_jobs(api, repository, run):
    value = api(f'repos/{repository}/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}/jobs?per_page=100')
    jobs = value.get('jobs') if isinstance(value, dict) else None
    require(isinstance(jobs, list) and type(value.get('total_count')) is int
            and len(jobs) == value['total_count'] and len(jobs) <= 100, 'incomplete current-attempt job inventory')
    pending = False
    for language in LANGUAGES:
        name = 'Scan (actions)' if language == 'actions' else f'Analyze ({language})'
        matches = [job for job in jobs if isinstance(job, dict) and job.get('name') == name]
        if not matches:
            pending = True
            continue
        require(len(matches) == 1, 'ambiguous scanner job')
        job = matches[0]
        require(job.get('run_id') == run['id'] and job.get('run_attempt') == run['run_attempt']
                and job.get('head_sha') == run['head_sha'], 'scanner job identity mismatch')
        if job.get('status') in ('queued', 'waiting', 'in_progress', 'pending'):
            pending = True
            continue
        require(job.get('status') == 'completed' and job.get('conclusion') == 'success',
                'a current-attempt scanner failed, was cancelled or skipped')
    if pending:
        raise AnalysisPending('CodeQL scanner jobs are still running')


def wait_for_analysis(api, repository, sha, event, *, seconds=2700, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + seconds
    while True:
        try:
            return latest_run(api, repository, sha, event)
        except AnalysisPending:
            require(clock() < deadline, 'timed out waiting for scanner jobs')
            sleep(min(15, max(0, deadline - clock())))


def workflow_protocol(api, repository, ref):
    value = api(f'repos/{repository}/contents/{WORKFLOW}?ref={ref}')
    require(isinstance(value, dict) and value.get('type') == 'file' and value.get('path') == WORKFLOW
            and value.get('encoding') == 'base64' and type(value.get('size')) is int
            and 0 < value['size'] <= 128 * 1024 and isinstance(value.get('content'), str)
            and len(value['content']) <= 256 * 1024, 'invalid protocol workflow response')
    raw = base64.b64decode(''.join(value['content'].split()), validate=True)
    require(len(raw) == value['size'] and value.get('sha') ==
            hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'protocol workflow byte identity mismatch')
    declarations = [line for line in raw.decode('utf-8').splitlines()
                    if line.startswith('# maestro-codeql-findings-protocol:')]
    require(not declarations or declarations == ['# maestro-codeql-findings-protocol: 1'],
            'unsupported or ambiguous findings protocol')
    return bool(declarations)


def enabled(api, repository, target):
    # During the reviewed two-stage cutover a candidate can only opt IN. Once
    # protected main declares v1, removing its marker in a candidate never
    # disables enforcement. Missing/unreadable trusted policy is not a bypass.
    trusted = workflow_protocol(api, repository, 'main')
    candidate = workflow_protocol(api, repository, target)
    return trusted or candidate


def latest_run(api, repository, sha, event):
    value = api(f'repos/{repository}/actions/workflows/codeql.yml/runs?head_sha={sha}&event={event}&per_page=100')
    runs = value.get('workflow_runs') if isinstance(value, dict) else None
    require(isinstance(runs, list) and type(value.get('total_count')) is int
            and len(runs) == value['total_count'] and 0 < len(runs) <= 100,
            'complete exact-revision analysis is required')
    for run in runs:
        require(isinstance(run, dict) and type(run.get('id')) is int and run['id'] > 0
                and run.get('path') == WORKFLOW and run.get('head_sha') == sha
                and run.get('event') == event and run.get('repository', {}).get('full_name') == repository,
                'analysis producer identity mismatch')
    run = max(runs, key=lambda item: item['id'])
    require(type(run.get('run_attempt')) is int and run['run_attempt'] > 0, 'invalid analysis attempt')
    if run.get('status') in ('queued', 'waiting', 'pending'):
        raise AnalysisPending('CodeQL run has not started')
    require(run.get('status') == 'in_progress' or
            (run.get('status') == 'completed' and run.get('conclusion') == 'success'),
            'latest exact-revision analysis is not viable')
    scan_jobs(api, repository, run)
    return run


def evidence(api, repository, sha, event, loader=download):
    run = latest_run(api, repository, sha, event)
    # Bind workflow bytes, not a spoofable job name. Changes require explicit acceptance.
    trusted = api(f'repos/{repository}/contents/{WORKFLOW}?ref=main')
    candidate = api(f'repos/{repository}/contents/{WORKFLOW}?ref={sha}')
    require(isinstance(trusted, dict) and trusted.get('type') == 'file'
            and isinstance(trusted.get('sha'), str) and authority.SHA.fullmatch(trusted['sha'])
            and isinstance(candidate, dict) and candidate.get('type') == 'file'
            and isinstance(candidate.get('sha'), str) and authority.SHA.fullmatch(candidate['sha']),
            'analysis workflow identity unavailable')
    workflow_changed = candidate['sha'] != trusted['sha']
    endpoint = f'repos/{repository}/actions/runs/{run["id"]}/artifacts?per_page=100'
    value = api(endpoint)
    artifacts = value.get('artifacts') if isinstance(value, dict) else None
    require(isinstance(artifacts, list) and type(value.get('total_count')) is int
            and len(artifacts) == value['total_count'] and len(artifacts) <= 100,
            'incomplete artifact inventory')
    findings, identities = [], []
    for language in LANGUAGES:
        matches = [a for a in artifacts if isinstance(a, dict) and a.get('name') == f'codeql-{language}-{run["run_attempt"]}']
        require(len(matches) == 1, 'missing or ambiguous language artifact: ' + language)
        artifact = matches[0]
        digest = artifact.get('digest', '')
        origin = artifact.get('workflow_run', {})
        require(type(artifact.get('id')) is int and artifact['id'] > 0 and artifact.get('expired') is False
                and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_BYTES
                and isinstance(digest, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', digest)
                and origin.get('id') == run['id'] and origin.get('head_sha') == sha,
                'invalid, expired or unbound analysis artifact')
        # Reruns must provide fresh reports for all languages, never silently mix
        # an earlier attempt's SARIF with a newer successful run.
        require(timestamp(artifact.get('created_at')) >= timestamp(run.get('run_started_at')), 'artifact predates latest attempt')
        raw = loader(repository, artifact['id'])
        require(hashlib.sha256(raw).hexdigest() == digest.removeprefix('sha256:'), 'artifact digest mismatch')
        findings.extend(parse_archive(raw, language))
        identities.append((artifact['id'], digest))
    digest = hashlib.sha256(canonical({'workflow': candidate['sha'], 'findings': sorted(findings, key=canonical)})).hexdigest()
    latest = latest_run(api, repository, sha, event)
    require((latest['id'], latest['run_attempt']) == (run['id'], run['run_attempt']), 'analysis changed during verification')
    return {'digest': digest, 'count': len(findings), 'run': run['id'], 'attempt': run['run_attempt'],
            'artifacts': identities, 'workflowChanged': workflow_changed}


def review_snapshot(api, repository, number):
    reviews = authority.collection(api, f'repos/{repository}/pulls/{number}/reviews')
    rows = []
    for review in reviews:
        require(isinstance(review, dict) and type(review.get('id')) is int and review['id'] > 0
                and isinstance(review.get('user'), dict), 'invalid review snapshot')
        row = {key: review.get(key) for key in ('id', 'state', 'commit_id', 'body', 'submitted_at')}
        row['user'] = {key: review['user'].get(key) for key in ('id', 'type', 'login')}
        rows.append(row)
    require(len({r['id'] for r in rows}) == len(rows), 'duplicate review snapshot')
    return hashlib.sha256(canonical(sorted(rows, key=lambda row: row['id']))).hexdigest()


def artifact_snapshot(api, repository, run_id, attempt, sha):
    value = api(f'repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100')
    artifacts = value.get('artifacts') if isinstance(value, dict) else None
    require(isinstance(artifacts, list) and type(value.get('total_count')) is int
            and len(artifacts) == value['total_count'] and len(artifacts) <= 100, 'incomplete artifact snapshot')
    identities = []
    for language in LANGUAGES:
        matches = [a for a in artifacts if isinstance(a, dict) and a.get('name') == f'codeql-{language}-{attempt}']
        require(len(matches) == 1, 'missing or ambiguous current artifact')
        a = matches[0]
        require(a.get('expired') is False and type(a.get('id')) is int and a['id'] > 0
                and isinstance(a.get('digest'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', a['digest'])
                and a.get('workflow_run', {}).get('id') == run_id
                and a.get('workflow_run', {}).get('head_sha') == sha, 'artifact snapshot identity mismatch')
        identities.append([a['id'], a['digest']])
    return identities


# Separate from successful authority receipts: this record announces data only.
READY_CHECK = 'CodeQL findings ready'
READY_APP_ID = 5384448
READY_MARKER = re.compile(r'\n<!-- maestro-codeql-report-ready (\{[^\n]+\}) -->$')
READY_KEYS = {'schema', 'repository', 'pullRequest', 'head', 'run', 'attempt', 'digest', 'artifacts'}


def ready_record(repository, number, head, report):
    value = {key: report[key] for key in ('run', 'attempt', 'digest', 'artifacts')}
    value.update(schema=1, repository=repository, pullRequest=number, head=head)
    # Normalize tuple-based parser output to the on-wire JSON representation.
    return json.loads(canonical(value))


def ready_checks(api, repository, number, head):
    value = api(f'repos/{repository}/commits/{head}/check-runs?check_name=CodeQL%20findings%20ready&filter=all&per_page=100')
    checks = value.get('check_runs') if isinstance(value, dict) else None
    require(isinstance(checks, list) and type(value.get('total_count')) is int
            and len(checks) == value['total_count'] and len(checks) <= 100,
            'complete report-ready check inventory required')
    rows, ids = [], set()
    for check in checks:
        if not isinstance(check, dict) or check.get('name') != READY_CHECK or check.get('app', {}).get('id') != READY_APP_ID:
            continue
        require(type(check.get('id')) is int and check['id'] > 0 and check['id'] not in ids
                and check.get('head_sha') == head, 'invalid report-ready App identity')
        ids.add(check['id'])
        require(check.get('status') == 'completed' and check.get('conclusion') == 'neutral',
                'report-ready check cannot grant authority')
        summary = check.get('output', {}).get('summary')
        require(isinstance(summary, str) and len(summary) <= 65536, 'invalid report-ready summary')
        match = READY_MARKER.search(summary)
        require(match is not None, 'missing report-ready binding')
        record = json.loads(match[1], object_pairs_hook=unique_object)
        require(isinstance(record, dict) and set(record) == READY_KEYS
                and type(record['schema']) is int and record['schema'] == 1
                and record['repository'] == repository and record['head'] == head
                and type(record['pullRequest']) is int and record['pullRequest'] == number
                and all(type(record[k]) is int and record[k] > 0 for k in ('run', 'attempt'))
                and isinstance(record['digest'], str) and re.fullmatch(r'[0-9a-f]{64}', record['digest'])
                and check.get('external_id') == f'codeql-ready-v1:{record["run"]}:{record["attempt"]}:{record["digest"]}',
                'invalid report-ready binding')
        artifacts = record['artifacts']
        require(isinstance(artifacts, list) and len(artifacts) == len(LANGUAGES)
                and all(isinstance(a, list) and len(a) == 2 and type(a[0]) is int and a[0] > 0
                        and isinstance(a[1], str) and re.fullmatch(r'sha256:[0-9a-f]{64}', a[1]) for a in artifacts)
                and len({a[0] for a in artifacts}) == len(artifacts), 'invalid report-ready artifacts')
        rows.append((check['id'], timestamp(check.get('completed_at')), record))
    return rows


def ordinary_acceptance(api, repository, number, head, review, report):
    require(type(review.get('id')) is int and review['id'] > 0, 'invalid approval identity')
    submitted = timestamp(review.get('submitted_at'))
    require(review.get('commit_id') == head, 'review head differs from report-ready head')
    available = ready_checks(api, repository, number, head)
    require(not any(row[1] == submitted for row in available), 'report and approval timestamp ordering is ambiguous')
    rows = [row for row in available if row[1] < submitted]
    require(rows, 'Approve after the protected findings-ready check is available')
    # Latest pre-review report is the only unambiguous thing that approval can
    # accept. A same-head scan with different findings cannot revive old consent.
    newest = max(rows, key=lambda row: row[0])
    require(newest[1] == max(row[1] for row in rows)
            and all(row[2]['digest'] == newest[2]['digest'] for row in rows if row[1] == newest[1]),
            'ambiguous report-ready ordering')
    original = newest[2]
    require(original['digest'] == report['digest'], 'findings or scanner changed since review')
    require(artifact_snapshot(api, repository, original['run'], original['attempt'], head) == original['artifacts'],
            'reviewed original reports changed or expired')
    return newest


def acceptance_binding(row, review):
    return {'readyCheckId': row[0], 'readyCompletedAt': row[1].strftime('%Y-%m-%dT%H:%M:%SZ'),
            'originalRecord': row[2], 'reviewId': review['id']}


def verify_acceptance(api, repository, number, head, digest, binding):
    require(isinstance(binding, dict) and set(binding) == {
        'readyCheckId', 'readyCompletedAt', 'originalRecord', 'reviewId'}
        and type(binding['readyCheckId']) is int and binding['readyCheckId'] > 0
        and type(binding['reviewId']) is int and binding['reviewId'] > 0,
        'invalid ordinary acceptance binding')
    reviews = authority.collection(api, f'repos/{repository}/pulls/{number}/reviews')
    matches = [r for r in reviews if isinstance(r, dict) and r.get('id') == binding['reviewId']]
    require(len(matches) == 1 and matches[0].get('state') == 'APPROVED', 'ordinary approval changed')
    row = ordinary_acceptance(api, repository, number, head, matches[0], {'digest': digest})
    require(acceptance_binding(row, matches[0]) == binding, 'ordinary acceptance binding changed')


def review_hint(repository, head, report):
    if not report['count'] and not report['workflowChanged']:
        return ''
    command = f'/maestro accept-codeql {head} {report["digest"]}'
    return (f'{report["count"]} CodeQL findings; analysis workflow changed: {report["workflowChanged"]}. '
            f'Review https://github.com/{repository}/actions/runs/{report["run"]}, then submit one '
            f'exact-head Approve review after the protected CodeQL findings ready check. A blank body is allowed. '
            f'Explicit digest-bound alternative: {command}')


def prepare(api, repository, target, event, loader=download):
    try:
        return evidence(api, repository, target, event, loader)
    except authority.AuthorityError:
        raise
    except Exception as error:
        raise authority.AuthorityError('CodeQL findings: evidence could not be authenticated') from error


def enforce(api, repository, number, head, target, loader=download, *, report=None):
    try:
        event = 'pull_request' if target == head else 'merge_group'
        report = report if report is not None else prepare(api, repository, target, event, loader)
        hint = review_hint(repository, head, report)
        if hint:
            try:
                review = authority.approval(api, repository, number, head)
            except authority.HumanDecisionRequired as error:
                raise authority.HumanDecisionRequired(str(error) + '. ' + hint) from error
            command = f'/maestro accept-codeql {head} {report["digest"]}'
            require(review.get('state') == 'APPROVED' and 'body' in review
                    and (review['body'] is None or isinstance(review['body'], str)), hint)
            body = review['body'] or ''
            accepted = None
            if body.strip() != command:
                require('/maestro accept-codeql' not in body, hint)
                accepted = ordinary_acceptance(api, repository, number, head, review, report)
        current = latest_run(api, repository, target, event)
        require((current['id'], current['run_attempt']) == (report['run'], report['attempt']),
                'analysis changed before authorization')
        require(artifact_snapshot(api, repository, report['run'], report['attempt'], target)
                == json.loads(canonical(report['artifacts'])), 'reports changed before authorization')
        if hint and accepted is not None:
            require(ordinary_acceptance(api, repository, number, head, review, report) == accepted,
                    'report-ready binding changed during authorization')
            report = dict(report, acceptance=acceptance_binding(accepted, review))
        return report
    except authority.AuthorityError:
        raise
    except Exception as error:
        # Candidate reports and transport failures never retain a previous green
        # authority verdict or expose attacker-controlled error text in checks.
        raise authority.AuthorityError('CodeQL findings: evidence could not be authenticated') from error
