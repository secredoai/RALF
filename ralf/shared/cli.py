"""``ralf-free`` command-line interface.

Subcommands::

    install         Wire the PreToolUse hook into ~/.claude/settings.json
    status          Print rule count, pickle cache state, config paths
    test <command>  Dry-run scoring on a single Bash command
    block <tok>     Add a first-token to the app-control block list
    allow <tok>     Add a first-token to the app-control allow list
    review <tok>    Add a first-token to the app-control review list
    remove <tok>    Remove a first-token from all app-control lists
    list            Print current app-control state
    logs [-n N]     Tail the audit log (default last 20)
    version         Print package version
    doctor          Diagnose config / cache / permission issues
    compile-rules   Force rebuild of the rules pickle cache

Each subcommand returns an integer exit code: 0 on success, non-zero
on failure. ``main(argv)`` is the argparse dispatcher and the entry
point registered as ``ralf-free`` in ``pyproject.toml``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ralf import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ralf-free",
        description="Pre-execution command firewall for AI coding agents.",
    )
    sub = parser.add_subparsers(dest="cmd", metavar="<command>")

    sub.add_parser("install", help="Wire the PreToolUse hook into ~/.claude/settings.json")
    sub.add_parser("status", help="Print rule count + cache state + config paths")

    p_test = sub.add_parser("test", help="Score a single Bash command")
    p_test.add_argument("command", help="The command to score")

    p_block = sub.add_parser("block", help="Block a first-token via app_control")
    p_block.add_argument("token")

    p_allow = sub.add_parser("allow", help="Allow a first-token via app_control")
    p_allow.add_argument("token")

    p_review = sub.add_parser("review", help="Mark a first-token for review")
    p_review.add_argument("token")

    p_remove = sub.add_parser("remove", help="Remove a first-token from app_control")
    p_remove.add_argument("token")

    p_block_domain = sub.add_parser("block-domain", help="Block a domain via app_control")
    p_block_domain.add_argument("domain")

    p_allow_domain = sub.add_parser("allow-domain", help="Allow a domain via app_control")
    p_allow_domain.add_argument("domain")

    p_remove_domain = sub.add_parser("remove-domain", help="Remove a domain from app_control")
    p_remove_domain.add_argument("domain")

    sub.add_parser("list", help="Print app_control state as YAML/JSON")

    p_logs = sub.add_parser("logs", help="Tail the audit log")
    p_logs.add_argument("-n", "--tail", type=int, default=20,
                        help="Number of entries (default 20)")

    sub.add_parser("version", help="Print the package version")
    sub.add_parser("doctor", help="Diagnose config / cache / permission issues")
    sub.add_parser("compile-rules", help="Force rebuild of the rules pickle cache")

    p_codex = sub.add_parser("codex", help="Codex CLI rules sync (read-only)")
    codex_sub = p_codex.add_subparsers(dest="codex_cmd", metavar="<sub>")
    p_codex_sync = codex_sub.add_parser(
        "sync", help="One-shot import of ~/.codex/rules/default.rules"
    )
    p_codex_sync.add_argument(
        "--path", type=Path, default=None,
        help="Override the rules file path (default ~/.codex/rules/default.rules)",
    )
    p_codex_watch = codex_sub.add_parser(
        "watch", help="Long-running mtime-poll loop on the rules file"
    )
    p_codex_watch.add_argument(
        "--path", type=Path, default=None,
        help="Override the rules file path",
    )
    p_codex_watch.add_argument(
        "--interval", type=float, default=1.0,
        help="Poll interval in seconds (default 1.0)",
    )

    p_scan = sub.add_parser("scan", help="Run host security posture checks")
    p_scan.add_argument("--watch", action="store_true",
                        help="Continuous monitoring (re-scan every 5 min)")
    p_scan.add_argument("--json", dest="json_out", action="store_true",
                        help="JSON output")
    p_scan.add_argument(
        "--category",
        choices=["all", "host_hardening", "credential", "session"],
        default="all",
        help="Check category filter (default: all)",
    )
    p_scan.add_argument(
        "--benchmark",
        choices=[
            "all", "cis-ubuntu-22", "cis-debian-12",
            "cis-macos-sonoma", "cis-macos-ventura", "mscp-sonoma",
        ],
        default=None,
        help="Filter by CIS Benchmark profile",
    )
    p_scan.add_argument(
        "--section",
        default=None,
        help="Filter by section name (e.g. 'SSH Server Configuration')",
    )

    p_audit = sub.add_parser("audit-sessions",
                             help="Scan past agent sessions for rogue commands")
    p_audit.add_argument("--agent",
                         choices=["all", "claude", "codex", "gemini"],
                         default="all")
    p_audit.add_argument("--days", type=int, default=7,
                         help="Lookback window in days (default: 7)")

    sub.add_parser("pause", help="Pause RALF — fail open and audit a paused entry")
    sub.add_parser("resume", help="Resume RALF after a pause")

    p_install_agent = sub.add_parser(
        "install-agent",
        help="Wire the PreToolUse hook into one agent's settings (claude|gemini)",
    )
    p_install_agent.add_argument(
        "--agent", choices=["claude", "gemini", "codex"], required=True,
        help="Target agent",
    )

    sub.add_parser(
        "dashboard", help="Launch the web dashboard (http://127.0.0.1:7433)"
    )

    # Threats subcommand (Objective-See IOC feed)
    p_threats = sub.add_parser("threats", help="macOS IOC threat feed (Objective-See)")
    threats_sub = p_threats.add_subparsers(dest="threats_cmd", metavar="<sub>")
    p_threats_sync = threats_sub.add_parser("sync", help="Fetch Objective-See feed")
    p_threats_sync.add_argument(
        "--source", default="objective-see",
        choices=["objective-see"],
        help="IOC feed source (default: objective-see)",
    )
    threats_sub.add_parser("status", help="Print IOC count and last-sync time")
    p_threats_scan = threats_sub.add_parser("scan", help="Check a file against IOC DB")
    p_threats_scan.add_argument("path", help="File path to hash-check")

    # Public-knowledge catalog subcommands (LOOBins / MITRE / CWE / OWASP / Semgrep)
    from ralf.shared import cli_knowledge
    cli_knowledge.add_subparsers(sub)

    # Upstream catalog sync (MITRE / CWE / LOOBins / GTFOBins)
    from ralf.shared import cli_sync
    cli_sync.add_subparsers(sub)

    return parser


# ----------------------------------------------------------------------
# subcommand handlers
# ----------------------------------------------------------------------


def _cmd_install(_args: argparse.Namespace) -> int:
    print(
        "ralf-free: 'install' is not the installer.\n"
        "\n"
        "To wire RALF into your agent, run the bundled installer:\n"
        "  ./setup.sh            # interactive: detects agents, backs up settings\n"
        "  install-agent claude  # non-interactive, per-agent\n"
        "\n"
        "The installer edits ~/.claude/settings.json (or the Codex / Gemini\n"
        "equivalent) to register the PreToolUse + PostToolUse hooks and\n"
        "runs `ralf-free compile-rules` on first use.",
        file=sys.stderr,
    )
    return 2


def _cmd_status(_args: argparse.Namespace) -> int:
    from ralf.shared.app_control import DEFAULT_CONFIG_PATH
    from ralf.shared.audit_log import DEFAULT_LOG_PATH
    from ralf.shared.rules import (
        DEFAULT_CACHE_FILE, DEFAULT_YAML_PATH, RuleEngine,
    )

    print(f"ralf-free {__version__}")
    print()
    print("Rules:")
    print(f"  YAML:         {DEFAULT_YAML_PATH}")
    print(f"                ({'present' if DEFAULT_YAML_PATH.exists() else 'MISSING'})")
    print(f"  Pickle cache: {DEFAULT_CACHE_FILE}")
    if DEFAULT_CACHE_FILE.exists():
        size_kb = DEFAULT_CACHE_FILE.stat().st_size / 1024
        print(f"                ({size_kb:.0f} KB)")
    else:
        print("                (missing — run 'ralf-free compile-rules')")
    print()
    print("Config:")
    print(f"  App control:  {DEFAULT_CONFIG_PATH}")
    print(f"                ({'present' if DEFAULT_CONFIG_PATH.exists() else 'absent'})")
    print(f"  Audit log:    {DEFAULT_LOG_PATH}")
    print(f"                ({'present' if DEFAULT_LOG_PATH.exists() else 'absent'})")
    print()

    # SAST-adapter mix availability (ruff > bandit > ast-grep; all optional)
    print("SAST adapters (optional, hook-path integrations):")
    try:
        from ralf.detection import ruff_adapter, bandit_adapter, astgrep_adapter
        for mod, label, install_hint in [
            (ruff_adapter,    "ruff    ", "pip install ruff"),
            (bandit_adapter,  "bandit  ", "pip install bandit"),
            (astgrep_adapter, "ast-grep", "pip install ast-grep-cli"),
        ]:
            if mod.is_available():
                v = mod.version() or "unknown"
                print(f"  {label}  {v}")
            else:
                print(f"  {label}  (not installed — {install_hint})")
    except Exception as exc:
        print(f"  (adapter-inventory failed: {exc})")
    print()

    try:
        engine = RuleEngine()
        print(f"Loaded {engine.rule_count} rules.")
    except Exception as exc:
        print(f"Rules engine load FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    from ralf.shared.app_control import AppDecision, check as ac_check, check_url
    from ralf.shared.verdict_engine import score_command

    first_token = args.command.strip().split()[0] if args.command.strip() else ""

    # Domain block always wins
    domain_decision = check_url(args.command)
    if domain_decision == AppDecision.BLOCK:
        print(f"Decision: BLOCK")
        print(f"Score:    100")
        print(f"Reason:   domain_control: blocked domain in command")
        return 1

    ac_decision = ac_check(first_token)
    if ac_decision == AppDecision.BLOCK:
        print(f"Decision: BLOCK")
        print(f"Score:    100")
        print(f"Reason:   app_control: {first_token} is blocked")
        return 1
    if ac_decision == AppDecision.ALLOW:
        try:
            from ralf.shared.verdict_engine import _scan_executed_file
            fscore, freasons, fhit = _scan_executed_file(args.command)
            if fscore >= 10 or (fhit is not None and fhit.blocked):
                print(f"Decision: BLOCK")
                print(f"Score:    {fscore}")
                print(f"Reason:   {first_token} allowed, file content blocked: {'; '.join(freasons)}")
                return 1
        except Exception:
            pass
        print(f"Decision: ALLOW")
        print(f"Score:    0")
        print(f"Reason:   app_control: {first_token} is allowed")
        return 0

    try:
        verdict = score_command(args.command)
    except Exception as exc:
        print(f"Scoring failed: {exc}", file=sys.stderr)
        return 2

    print(f"Decision: {verdict.decision.upper()}")
    print(f"Score:    {verdict.score}")
    print(f"Reason:   {verdict.reason}")
    if verdict.rule_hits:
        print(f"Hits:     {len(verdict.rule_hits)}")
        for h in sorted(verdict.rule_hits, key=lambda h: -h.score_floor)[:5]:
            print(f"  floor={h.score_floor:3d}  {h.rule_id}  ({h.evidence})")
    if verdict.sensitive_path:
        print("Sensitive path detected")
    return 0 if verdict.decision != "block" else 1


def _cmd_add(args: argparse.Namespace, decision_name: str) -> int:
    from ralf.shared.app_control import AppControl, AppDecision

    mapping = {
        "allow": AppDecision.ALLOW,
        "block": AppDecision.BLOCK,
        "review": AppDecision.REVIEW,
    }
    decision = mapping[decision_name]
    ac = AppControl()
    ac.add(args.token, decision)
    print(f"{decision_name}: {args.token}")
    print(f"Saved to {ac.path}")
    return 0


def _cmd_remove(args: argparse.Namespace) -> int:
    from ralf.shared.app_control import AppControl

    ac = AppControl()
    if ac.remove(args.token):
        print(f"removed: {args.token}")
        return 0
    print(f"not found: {args.token}", file=sys.stderr)
    return 1


def _cmd_add_domain(args: argparse.Namespace, decision_name: str) -> int:
    from ralf.shared.app_control import AppControl, AppDecision

    decision = {"allow": AppDecision.ALLOW, "block": AppDecision.BLOCK}[decision_name]
    ac = AppControl()
    ac.add_domain(args.domain, decision)
    print(f"{decision_name}-domain: {args.domain}")
    print(f"Saved to {ac.path}")
    return 0


def _cmd_remove_domain(args: argparse.Namespace) -> int:
    from ralf.shared.app_control import AppControl

    ac = AppControl()
    if ac.remove_domain(args.domain):
        print(f"removed domain: {args.domain}")
        return 0
    print(f"domain not found: {args.domain}", file=sys.stderr)
    return 1


def _cmd_list(_args: argparse.Namespace) -> int:
    from ralf.shared.app_control import AppControl

    ac = AppControl()
    state = ac.as_dict()
    print(f"# {ac.path}")
    print(json.dumps(state, indent=2))
    return 0


def _cmd_logs(args: argparse.Namespace) -> int:
    from ralf.shared.audit_log import DEFAULT_LOG_PATH, tail

    entries = tail(args.tail)
    if not entries:
        print(f"(empty — {DEFAULT_LOG_PATH})", file=sys.stderr)
        return 0
    for e in entries:
        print(json.dumps(e))
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"ralf-free {__version__}")
    return 0


def _cmd_doctor(_args: argparse.Namespace) -> int:
    from ralf.shared.rules import DEFAULT_CACHE_FILE, DEFAULT_YAML_PATH

    ok = True
    print("ralf-free doctor")

    # 1. YAML present?
    if DEFAULT_YAML_PATH.exists():
        print(f"  [OK] rules YAML at {DEFAULT_YAML_PATH}")
    else:
        print(f"  [FAIL] rules YAML missing: {DEFAULT_YAML_PATH}")
        ok = False

    # 2. Pickle cache fresh?
    if DEFAULT_CACHE_FILE.exists():
        try:
            if DEFAULT_YAML_PATH.exists() and (
                DEFAULT_CACHE_FILE.stat().st_mtime < DEFAULT_YAML_PATH.stat().st_mtime
            ):
                print(f"  [WARN] pickle cache stale vs YAML — run 'compile-rules'")
            else:
                print(f"  [OK] pickle cache fresh at {DEFAULT_CACHE_FILE}")
        except OSError as exc:
            print(f"  [WARN] cache stat failed: {exc}")
    else:
        print(f"  [WARN] no pickle cache — run 'ralf-free compile-rules'")

    # 3. PyYAML loader backend
    try:
        import yaml
        if hasattr(yaml, "CSafeLoader"):
            print(f"  [OK] PyYAML CSafeLoader available")
        else:
            print(f"  [WARN] libyaml not installed — YAML load is pure-python (~7x slower)")
    except ImportError:
        print(f"  [FAIL] PyYAML not importable")
        ok = False

    # 4. Platform
    try:
        from ralf.shared.platform_detect import get_platform_name
        print(f"  [OK] platform: {get_platform_name()}")
    except Exception as exc:
        print(f"  [FAIL] platform detection: {exc}")
        ok = False

    # 5. Pause sentinel
    sentinel = _pause_sentinel_path()
    if sentinel.exists():
        print(f"  [WARN] PAUSED — sentinel at {sentinel} (run 'ralf-free resume')")
    else:
        print(f"  [OK] not paused")

    # 6. Adapter wiring per agent
    _doctor_adapters()

    # 7. Codex rules file (advisory — adapter is read-only)
    _doctor_codex()

    return 0 if ok else 1


def _doctor_adapters() -> None:
    """Inspect each agent's settings file to see if our hook is wired in."""
    from ralf.scripts.install_hook import _AGENTS, _hook_present
    for name in sorted(_AGENTS):
        profile = _AGENTS[name]
        if not profile.settings_path.exists():
            print(
                f"  [--] {profile.name}: no settings file at {profile.settings_path}"
            )
            continue
        try:
            data = json.loads(profile.settings_path.read_text() or "{}")
        except json.JSONDecodeError:
            print(
                f"  [WARN] {profile.name}: settings file is not valid JSON "
                f"({profile.settings_path})"
            )
            continue
        if not isinstance(data, dict):
            print(f"  [WARN] {profile.name}: settings is not a JSON object")
            continue
        if _hook_present(data, profile):
            print(f"  [OK] {profile.name}: hook wired into {profile.settings_path}")
        else:
            print(
                f"  [--] {profile.name}: hook NOT wired — "
                f"run 'ralf-free install-agent --agent {profile.name}'"
            )


def _doctor_codex() -> None:
    from ralf.adapters.codex_cli import _default_rules_path
    p = _default_rules_path()
    if p.exists():
        print(f"  [OK] codex rules file at {p} (run 'ralf-free codex sync' to import)")
    else:
        print(f"  [--] codex rules file absent: {p}")


def _cmd_codex(args: argparse.Namespace) -> int:
    """Dispatch ``codex sync`` / ``codex watch``."""
    sub = getattr(args, "codex_cmd", None)
    if sub == "sync":
        from ralf.adapters.codex_cli import _default_rules_path, import_codex_rules
        rules_path = args.path or _default_rules_path()
        if not rules_path.exists():
            print(f"error: rules file not found: {rules_path}", file=sys.stderr)
            return 1
        imported, added = import_codex_rules(rules_path)
        print(f"Imported {imported} rules from {rules_path}")
        print(f"  app_control entries added/updated: {added}")
        return 0
    if sub == "watch":
        from ralf.adapters.codex_cli import _default_rules_path, watch_codex_rules
        rules_path = args.path or _default_rules_path()
        print(f"Watching {rules_path} every {args.interval:.1f}s (Ctrl-C to stop)")
        try:
            for imported, added in watch_codex_rules(
                rules_path, interval=args.interval
            ):
                print(f"  → re-imported {imported} rules ({added} app_control changes)")
        except KeyboardInterrupt:
            print("\nstopped")
        return 0
    print("usage: ralf-free codex {sync|watch}", file=sys.stderr)
    return 2


def _cmd_pause(_args: argparse.Namespace) -> int:
    """Create the pause sentinel; subsequent hook invocations fail open."""
    sentinel = _pause_sentinel_path()
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.touch()
    print(f"paused (sentinel at {sentinel})")
    return 0


def _cmd_resume(_args: argparse.Namespace) -> int:
    sentinel = _pause_sentinel_path()
    if sentinel.exists():
        sentinel.unlink()
        print(f"resumed (removed sentinel at {sentinel})")
    else:
        print(f"already running (no sentinel at {sentinel})")
    return 0


def _pause_sentinel_path() -> Path:
    """Same logic as ralf.adapters.claude_code._pause_sentinel — see note."""
    import os
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "ralf-free" / "paused"


def _cmd_install_agent(args: argparse.Namespace) -> int:
    """Wire the PreToolUse hook into the chosen agent's settings.json.

    Reuses :mod:`ralf.scripts.install_hook` for the JSON merge logic.
    """
    from ralf.scripts.install_hook import install_for_agent
    return install_for_agent(args.agent)


def _cmd_scan(args: argparse.Namespace) -> int:
    """Run host security posture scan."""
    from ralf.scanner.runner import run_all_checks

    if getattr(args, "watch", False):
        from ralf.scanner.sessions import watch
        print("RALF Posture Shield — watching (Ctrl-C to stop)")
        try:
            for report, transitions in watch(interval=300):
                if transitions:
                    for t in transitions:
                        print(t)
                else:
                    print(f"[{report.ts}] Score: {report.score}/100 ({report.grade}) — no changes")
        except KeyboardInterrupt:
            print("\nstopped")
        return 0

    report = run_all_checks(
        category=getattr(args, "category", "all"),
        benchmark=getattr(args, "benchmark", None),
        section=getattr(args, "section", None),
    )

    if getattr(args, "json_out", False):
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return 0


def _cmd_audit_sessions(args: argparse.Namespace) -> int:
    """Batch-scan past agent sessions for rogue commands."""
    from ralf.scanner.sessions import audit_sessions

    results = audit_sessions(
        agent=getattr(args, "agent", "all"),
        days=getattr(args, "days", 7),
    )
    for r in results:
        icon = {"pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]", "skip": "[SKIP]"}.get(r.status, "[????]")
        print(f"{icon} {r.name}")
        print(f"     {r.detail}")
        if r.remediation:
            print(f"     Fix: {r.remediation}")
        print()
    has_fail = any(r.status == "fail" for r in results)
    return 1 if has_fail else 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    """Launch the web dashboard."""
    try:
        from ralf.dashboard.app import main as run_dashboard
    except ImportError as exc:
        print(
            f"error: dashboard requires the optional 'dashboard' extra:\n"
            f"  pip install --user -e '.[dashboard]'\n"
            f"(import error: {exc})",
            file=sys.stderr,
        )
        return 1
    run_dashboard()
    return 0


def _cmd_threats(args: argparse.Namespace) -> int:
    """Dispatch ``threats sync | status | scan``."""
    sub = getattr(args, "threats_cmd", None)
    if sub == "sync":
        from ralf.threats.objective_see import sync_objective_see
        print("Syncing Objective-See IOC feed ...")
        r = sync_objective_see()
        if r.success:
            print(f"OK — {r.record_count} IOCs synced ({r.bytes_fetched // 1024} KB, {r.elapsed_sec:.1f}s)")
        else:
            print(f"FAIL — {r.error}", file=sys.stderr)
        return 0 if r.success else 1
    if sub == "status":
        from ralf.threats.ioc_store import IocStore, _default_db_path
        db = _default_db_path()
        if not db.exists():
            print(f"No IOC database found at {db}")
            print("Run: ralf-free threats sync")
            return 0
        store = IocStore()
        try:
            print(f"IOC database: {db}")
            print(f"  IOC count:  {store.count()}")
            print(f"  Last sync:  {store.last_sync_iso() or 'never'}")
        finally:
            store.close()
        return 0
    if sub == "scan":
        import hashlib
        from ralf.threats.ioc_store import IocStore, _default_db_path
        target = args.path
        db = _default_db_path()
        if not db.exists():
            print(f"No IOC database. Run: ralf-free threats sync", file=sys.stderr)
            return 2
        try:
            content = Path(target).read_bytes()
        except OSError as exc:
            print(f"Cannot read {target}: {exc}", file=sys.stderr)
            return 2
        sha = hashlib.sha256(content).hexdigest()
        store = IocStore()
        try:
            match = store.lookup_sha256(sha)
        finally:
            store.close()
        if match:
            print(f"MATCH: {target} — malware family: {match.malware_family} (sha256={sha[:16]}...)")
            return 1
        print(f"clean: {target} (sha256={sha[:16]}...)")
        return 0
    print("usage: ralf-free threats {sync|status|scan}", file=sys.stderr)
    return 2


def _cmd_compile_rules(_args: argparse.Namespace) -> int:
    import time
    from ralf.shared.rules import (
        DEFAULT_CACHE_DIR, DEFAULT_CACHE_FILE, DEFAULT_YAML_PATH, RuleEngine,
    )

    if not DEFAULT_YAML_PATH.exists():
        print(f"error: YAML missing at {DEFAULT_YAML_PATH}", file=sys.stderr)
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
    print(f"  YAML load:   {load_ms:8.1f} ms")
    print(f"  Pickle save: {save_ms:8.1f} ms  ({size_mb:.2f} MB)")
    print(f"  Output:      {DEFAULT_CACHE_FILE}")
    return 0


# ----------------------------------------------------------------------
# dispatcher
# ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd is None:
        parser.print_help()
        return 0

    from ralf.shared import cli_knowledge, cli_sync

    handlers = {
        "install": _cmd_install,
        "status": _cmd_status,
        "test": _cmd_test,
        "block": lambda a: _cmd_add(a, "block"),
        "allow": lambda a: _cmd_add(a, "allow"),
        "review": lambda a: _cmd_add(a, "review"),
        "remove": _cmd_remove,
        "block-domain": lambda a: _cmd_add_domain(a, "block"),
        "allow-domain": lambda a: _cmd_add_domain(a, "allow"),
        "remove-domain": _cmd_remove_domain,
        "list": _cmd_list,
        "logs": _cmd_logs,
        "version": _cmd_version,
        "doctor": _cmd_doctor,
        "compile-rules": _cmd_compile_rules,
        "scan": _cmd_scan,
        "audit-sessions": _cmd_audit_sessions,
        "codex": _cmd_codex,
        "pause": _cmd_pause,
        "resume": _cmd_resume,
        "install-agent": _cmd_install_agent,
        "dashboard": _cmd_dashboard,
        "threats": _cmd_threats,
        **cli_knowledge.handlers,
        **cli_sync.handlers,
    }
    handler = handlers.get(args.cmd)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
