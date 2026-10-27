#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Canonical evidence digests and fail-closed binding assertions."""
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)
