"""``ralf-free sync`` subcommand — refresh bundled public-knowledge catalogs.

Five sub-actions, each a deterministic fetcher that pulls from the canonical
upstream source:

- ``sync mitre-linux``  — MITRE ATT&CK STIX → ``mitre_attack_linux.json``
- ``sync mitre-macos``  — MITRE ATT&CK STIX → ``mitre_attack_macos.json``
- ``sync cwe``          — MITRE CWE XML dictionary → ``cwe_top25.json``
- ``sync loobins``      — infosecB/LOOBins GitHub archive → ``loobins_capabilities.json``
- ``sync gtfobins``     — GTFOBins GitHub archive → ``gtfobins_capabilities.json``
                          + ``gtfobins_round_7.rules.yaml`` for learned-rule merge
- ``sync all``          — run all five, print per-source success/fail

Every fetcher is opt-in, offline-safe (bundle baseline remains if the fetch
fails), and writes JSON atomically. ``--json`` output mode prints the
:class:`SyncResult` in structured form for machine consumption.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Callable


def _format_header(title: str) -> str:
    return f"\n{title}\n{'─' * len(title)}"


def _cmd_sync(args: argparse.Namespace) -> int:
    from ralf.sync import (
        sync_mitre_linux, sync_mitre_macos, sync_cwe, sync_loobins, sync_gtfobins,
        sync_cve, SyncResult,
    )

    target = args.target or "all"
    timeout = args.timeout

    def _run(name: str, fn: Callable[[], SyncResult]) -> SyncResult:
        if not args.json:
            print(f"→ {name} ... ", end="", flush=True)
        try:
            r = fn()
        except Exception as e:  # pragma: no cover — defensive
            r = SyncResult(
                source=name, url="", success=False, record_count=0,
                output_path=None, bytes_fetched=0, elapsed_sec=0.0,
                error=f"unexpected exception: {e}",
            )
        if not args.json:
            status = "ok" if r.success else "FAIL"
            detail = (f"{r.record_count} records, {r.bytes_fetched // 1024} KB"
                      if r.success else r.error)
            print(f"{status} — {detail}")
            for w in r.warnings:
                print(f"  warn: {w}")
        return r

    runners: dict[str, Callable[[], SyncResult]] = {
        "mitre-linux": lambda: sync_mitre_linux(timeout_sec=timeout),
        "mitre-macos": lambda: sync_mitre_macos(timeout_sec=timeout),
        "cwe": lambda: sync_cwe(timeout_sec=timeout),
        "loobins": lambda: sync_loobins(timeout_sec=timeout),
        "gtfobins": lambda: sync_gtfobins(timeout_sec=timeout),
        "cve": lambda: sync_cve(
            timeout_sec=max(timeout, 180.0),
            window_years=args.cve_window_years,
            ecosystems=(tuple(args.ecosystems) if args.ecosystems else None),
        ),
    }

    if target == "all":
        results = [_run(name, runner) for name, runner in runners.items()]
    else:
        runner = runners.get(target)
        if runner is None:
            print(f"error: unknown sync target {target!r}. "
                  f"Choices: {', '.join(runners)} or 'all'", file=sys.stderr)
            return 2
        results = [_run(target, runner)]

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
        return 0 if all(r.success for r in results) else 1

    # Summary
    print(_format_header("Summary"))
    total_records = sum(r.record_count for r in results)
    total_bytes = sum(r.bytes_fetched for r in results)
    total_time = sum(r.elapsed_sec for r in results)
    ok = sum(1 for r in results if r.success)
    fail = sum(1 for r in results if not r.success)
    print(f"  success: {ok}   failed: {fail}")
    print(f"  records: {total_records}")
    print(f"  bytes:   {total_bytes // 1024} KB fetched")
    print(f"  elapsed: {total_time:.2f}s")
    if fail:
        print()
        print("  Failed sources:")
        for r in results:
            if not r.success:
                print(f"    {r.source:16} {r.error}")
        return 1
    return 0


def add_subparsers(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "sync",
        help="Refresh bundled public-knowledge catalogs (MITRE, CWE, LOOBins, GTFOBins)",
        description=(
            "Pull the latest MITRE ATT&CK / CWE / LOOBins / GTFOBins catalogs "
            "from their public sources of truth and regenerate the bundled "
            "JSON files RALF Free loads. Opt-in, offline-safe, deterministic."
        ),
    )
    p.add_argument(
        "target",
        nargs="?",
        default="all",
        choices=[
            "all", "mitre-linux", "mitre-macos", "cwe",
            "loobins", "gtfobins", "cve",
        ],
        help="Which catalog to sync (default: all)",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Print machine-readable per-source results",
    )
    p.add_argument(
        "--timeout", type=float, default=60.0,
        help="HTTP timeout in seconds (default: 60; CVE uses min 180)",
    )
    p.add_argument(
        "--cve-window-years", type=int, default=10,
        help="CVE rolling-window size in years (default: 10 — covers "
             "most pinned-version vulnerabilities in mainstream packages)",
    )
    p.add_argument(
        "--ecosystems", action="append", default=None,
        choices=[
            "PyPI", "npm", "crates.io", "RubyGems", "Go", "Packagist", "NuGet",
        ],
        help="OSV ecosystems to fetch (repeatable). Default: all except NuGet "
             "(excluded because its OSV feed is CC-BY-SA-4.0 Share-Alike). "
             "Pass `--ecosystems NuGet` to opt in; you accept the SA "
             "obligation on the resulting local DB.",
    )


handlers: dict[str, Callable[[argparse.Namespace], int]] = {
    "sync": _cmd_sync,
}


__all__ = ["add_subparsers", "handlers"]
