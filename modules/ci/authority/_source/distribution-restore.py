#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authenticate candidate evidence before importing its exact Nix closure."""
import importlib.util
import os
from pathlib import Path
import sys

sys.path.insert(0, os.environ["MAESTRO_DECISION_CORE"])
import common
import packet_materialization


def main():
    root = Path(os.environ.get("MAESTRO_SYSTEM_ROOT", "."))
    cfg = common.config(root / "modules/ci/authority/_source/decision-policy.json", live=True, enabled=True)
    scan_path, product_path = Path(os.environ["DECISION_SCANS"]), Path(os.environ["DECISION_PRODUCT"])
    common.gate(cfg, scan_path, product_path, os.environ.get("PUBLICATION_PURPOSE", "rolling"))
    scan, product = common.load_json(scan_path), common.load_json(product_path)
    roots = {v["storePath"]: {"storePath": v["storePath"], "narHash": v["narHash"]}
             for v in [*product["products"].values(), *product.get("roots", {}).values()]}
    spec = importlib.util.spec_from_file_location("distribution_cache", os.environ["MAESTRO_DISTRIBUTION_CACHE_SOURCE"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    closure_metadata = os.environ.get('DISTRIBUTION_CLOSURE_METADATA')
    if not closure_metadata and all(Path(path).exists() for path in roots):
        module.verify_roots(list(roots.values()))
    else:
        packet_materialization.materialize(Path(os.environ["DECISION_EVIDENCE_DIRECTORY"]))
        module.restore(Path(os.environ["DECISION_EVIDENCE_DIRECTORY"]), scan["transport"], list(roots.values()),
                       closure_metadata=closure_metadata)


if __name__ == "__main__":
    sys.exit(common.run(main))
