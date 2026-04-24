"""Merge ralf/data/gtfobins_round_7.rules.yaml into ralf/data/learned_rules.yaml.

Idempotent: dedups by rule ``id``. Writes atomically via temp file.
Run with: ``python3 -m ralf.scripts.merge_gtfobins_round7``
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_BASE_PATH = _DATA_DIR / "learned_rules.yaml"
_R7_PATH = _DATA_DIR / "gtfobins_round_7.rules.yaml"


def main() -> int:
    if not _BASE_PATH.exists():
        print(f"error: {_BASE_PATH} not found", file=sys.stderr)
        return 1
    if not _R7_PATH.exists():
        print(f"error: {_R7_PATH} not found", file=sys.stderr)
        return 1

    with _BASE_PATH.open("r", encoding="utf-8") as f:
        base = yaml.safe_load(f)
    with _R7_PATH.open("r", encoding="utf-8") as f:
        r7 = yaml.safe_load(f)

    if not isinstance(base, dict) or "rules" not in base:
        print(f"error: {_BASE_PATH} missing 'rules' key", file=sys.stderr)
        return 1
    if not isinstance(r7, dict) or "rules" not in r7:
        print(f"error: {_R7_PATH} missing 'rules' key", file=sys.stderr)
        return 1

    # Idempotent strategy: strip ANY existing round-7 rules from the base,
    # then append the fresh round-7 set. This keeps re-runs clean even when
    # the generator emits fewer rules than a previous run (e.g. after adding
    # binaries to the exclude list).
    base_rules_pre = list(base["rules"])
    base_rules_stripped = [
        r for r in base_rules_pre
        if r.get("source") != "gtfobins_round_7"
    ]
    removed = len(base_rules_pre) - len(base_rules_stripped)

    r7_ids = {r.get("id") for r in r7["rules"]}
    existing_ids = {r.get("id") for r in base_rules_stripped}
    # Avoid colliding with rule IDs outside round-7 (shouldn't happen, but
    # defensive against accidental id reuse).
    new_rules = [r for r in r7["rules"] if r.get("id") not in existing_ids]
    skipped = len(r7["rules"]) - len(new_rules)

    print(f"base rules:              {len(base_rules_pre)}")
    print(f"existing round-7 rules:  {removed}")
    print(f"base after strip:        {len(base_rules_stripped)}")
    print(f"round-7 rules to add:    {len(r7['rules'])}")
    print(f"new:                     {len(new_rules)}")
    print(f"collisions skipped:      {skipped}")

    if len(new_rules) == 0 and removed == 0:
        print("nothing to merge; exiting")
        return 0

    merged = dict(base)
    merged["rules"] = base_rules_stripped + new_rules

    tmp_path = _BASE_PATH.with_suffix(_BASE_PATH.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(merged, f, sort_keys=False, allow_unicode=True)
    os.replace(tmp_path, _BASE_PATH)

    print(f"merged → {_BASE_PATH}")
    print(f"new total: {len(merged['rules'])} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
