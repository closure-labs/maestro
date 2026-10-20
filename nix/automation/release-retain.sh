#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ ! -e prepared ]]
mkdir prepared
cp -R security-report/. prepared/
cp -R release/. prepared/
