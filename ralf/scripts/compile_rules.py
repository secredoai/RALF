#!/usr/bin/env python3
"""Compile learned_rules.yaml to a pickle cache for fast cold-start.

Standalone runnable. Reads the YAML bundled in ``ralf/data/``, builds
a :class:`~ralf.shared.rules.RuleEngine`, and writes the pickle to
the default cache path (``~/.cache/ralf-free/rules.pkl``). Prints a
timing + size summary.

Run::

    cd /path/to/ralf
    PYTHONPATH=. python3 ralf/scripts/compile_rules.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Make ralf.* importable when invoked directly from a checkout.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ralf.shared.rules import (  # noqa: E402  (sys.path mutated above)
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_FILE,
    DEFAULT_YAML_PATH,
    RuleEngine,
)


def main() -> int:
    if not DEFAULT_YAML_PATH.exists():
        print(f"ERROR: rules YAML not found at {DEFAULT_YAML_PATH}", file=sys.stderr)
        return 1

    DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    engine = RuleEngine(DEFAULT_YAML_PATH, use_cache=False)
    load_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    engine.to_pickle(DEFAULT_CACHE_FILE)
    save_ms = (time.perf_counter() - t1) * 1000

    size_mb = DEFAULT_CACHE_FILE.stat().st_size / (1024 * 1024)

    print(f"Compiled {engine.rule_count} rules")
    print(f"YAML load:   {load_ms:8.1f} ms")
    print(f"Pickle save: {save_ms:8.1f} ms  ({size_mb:.2f} MB)")
    print(f"Output:      {DEFAULT_CACHE_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
