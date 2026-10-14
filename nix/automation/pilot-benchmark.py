#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Model the overlap DAG from observed successful GitHub job/step timings."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('jobs', type=Path, help='Unmodified GitHub runs/{id}/jobs JSON')
parser.add_argument('--audit-job-overhead-seconds', type=int, default=60,
                    help='Explicit modeled extra audit job startup/queue cost; default 60')
args = parser.parse_args()
if args.audit_job_overhead_seconds < 0:
    parser.error('audit job overhead must be nonnegative')
raw = args.jobs.read_bytes()
data = json.loads(raw)


def seconds(value):
    start = dt.datetime.fromisoformat(value['started_at'].replace('Z', '+00:00'))
    end = dt.datetime.fromisoformat(value['completed_at'].replace('Z', '+00:00'))
    duration = int((end - start).total_seconds())
    if duration < 0:
        raise ValueError('Negative observed duration')
    return duration


def job(name):
    matches = [j for j in data['jobs'] if j['name'] == name and j['conclusion'] == 'success']
    if len(matches) != 1 or '/repos/closure-labs/maestro/' not in matches[0]['run_url']:
        raise ValueError('Expected one successful Maestro job: ' + name)
    return matches[0]


route = job('Audit repository and route downstream work')
qualification = job('Qualify installer media and evidence')
security = job('Scan qualified dependency inventories')
if len({j['run_id'] for j in (route, qualification, security)}) != 1:
    raise ValueError('Job source run mismatch')
audit_steps = [s for s in route['steps'] if s['name'] == 'Validate repository' and s['conclusion'] == 'success']
if len(audit_steps) != 1:
    raise ValueError('Missing successful full repository audit step')
audit = seconds(audit_steps[0])
routing = seconds(route) - audit
downstream = seconds(qualification) + seconds(security)
serial = routing + audit + downstream
overlap = routing + max(audit + args.audit_job_overhead_seconds, downstream)
print(json.dumps(dict(
    schema_version=1,
    evidence_kind='modeled DAG using observed hosted durations; pilot performance not observed',
    source_run_id=route['run_id'], source_url=f"https://github.com/closure-labs/maestro/actions/runs/{route['run_id']}",
    source_jobs_sha256=hashlib.sha256(raw).hexdigest(),
    observed_seconds=dict(route=seconds(route), audit_step=audit, qualification=seconds(qualification), security=seconds(security)),
    assumptions=dict(audit_job_overhead_seconds=args.audit_job_overhead_seconds,
                     unchanged_job_durations=True, additional_cross_job_queue_delays=0,
                     concurrent_cache_and_CPU_contention='not modeled',
                     release_continuation='idle runner watch removed; release latency and protected merge waits unchanged; not measured'),
    modeled_seconds=dict(serial_until_security_and_audit_ready=serial,
                         overlap_until_security_and_audit_ready=overlap,
                         critical_path_reduction=serial-overlap,
                         additional_runner_work=args.audit_job_overhead_seconds),
), sort_keys=True, indent=2))
