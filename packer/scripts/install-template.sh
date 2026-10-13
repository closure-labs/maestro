#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_url=${MAESTRO_REPO_URL:-https://github.com/closure-labs/maestro.git}
repo_branch=${MAESTRO_REPO_BRANCH:-main}

exec sudo -n install-maestro \
  --yes \
  --operator-key /tmp/maestro-operator.pub \
  --bootstrap-key /run/maestro-bootstrap/authorized_keys \
  --revision "${MAESTRO_REPO_REVISION:?}" \
  --repo-url "$repo_url" \
  --branch "$repo_branch"
