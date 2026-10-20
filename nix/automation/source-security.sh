#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
gitleaks dir --redact --no-banner .
