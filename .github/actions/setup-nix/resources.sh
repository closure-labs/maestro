#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cpus=${1:-$(nproc)}
memory_mb=${2:-$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)}
[[ $cpus =~ ^[1-9][0-9]*$ && $memory_mb =~ ^[1-9][0-9]*$ ]]

# Leave 8 GiB for nested VM tests and runner processes, then allow 4 GiB
# per concurrent derivation and 2 GiB per core. On runners with at most 8 GiB,
# reserve 2 GiB and run one build at a time; very small runners get one core.
memory_budget=$((memory_mb - 8192))
if ((memory_mb <= 8192)); then
  memory_budget=$((memory_mb - 2048))
fi
((memory_budget >= 2048)) || memory_budget=2048
jobs=$((cpus / 2))
((jobs >= 1)) || jobs=1
memory_jobs=$((memory_budget / 4096))
((memory_jobs >= 1)) || memory_jobs=1
((memory_mb > 8192)) || memory_jobs=1
((jobs <= memory_jobs)) || jobs=$memory_jobs
((jobs <= 4)) || jobs=4
cores=$((cpus / jobs))
memory_cores=$((memory_budget / (2048 * jobs)))
((memory_cores >= 1)) || memory_cores=1
((cores <= memory_cores)) || cores=$memory_cores
printf 'Runner resources: %s CPUs, %s MiB RAM; %s build jobs, %s cores/job\n' \
  "$cpus" "$memory_mb" "$jobs" "$cores" >&2
printf 'max-jobs = %s\ncores = %s\n' "$jobs" "$cores"
