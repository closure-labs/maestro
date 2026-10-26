#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

if [[ -n ${MAESTRO_CI_PATH_PREFIX:-} ]]; then
  export PATH="$MAESTRO_CI_PATH_PREFIX:$PATH"
fi
