"""RALF Free dashboard — Flask web UI.

Binds to 127.0.0.1:7433 (localhost only, no auth).
Serves a single-page app with tabs: Live Feed, App Control, Test, Rules & Knowledge, Host Scan.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request, render_template

from ralf.shared.app_control import AppControl, AppDecision
from ralf.shared import audit_log
from ralf.shared.verdict_engine import score_command, score_file_write, Verdict

DASHBOARD_PORT = 7433

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)


def _pause_sentinel_path() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "ralf-free" / "paused"


def _rules_cache_path() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "ralf-free" / "rules.pkl"


def _agent_status() -> dict:
    """Check which agents have hooks wired."""
    agents = {}
    try:
        from ralf.scripts.install_hook import _AGENTS, _hook_present
        for name, profile in _AGENTS.items():
            if not profile.settings_path.exists():
                agents[name] = "not installed"
                continue
            try:
                data = json.loads(profile.settings_path.read_text() or "{}")
                agents[name] = "wired" if _hook_present(data, profile) else "not wired"
            except Exception:
                agents[name] = "error"
    except Exception:
        pass
    return agents


def _status_info() -> dict:
    paused = _pause_sentinel_path().exists()
    cache = _rules_cache_path()
    cache_age = None
    if cache.exists():
        age_sec = time.time() - cache.stat().st_mtime
        if age_sec < 3600:
            cache_age = f"{int(age_sec / 60)}m ago"
        elif age_sec < 86400:
            cache_age = f"{int(age_sec / 3600)}h ago"
        else:
            cache_age = f"{int(age_sec / 86400)}d ago"

    rule_count = 0
    try:
        from ralf.shared.verdict_engine import _get_engine
        rule_count = len(_get_engine()._rules)
    except Exception:
        pass

    return {
        "paused": paused,
        "rule_count": rule_count,
        "cache_age": cache_age or "no cache",
        "agents": _agent_status(),
    }


def _quick_stats() -> dict:
    entries = audit_log.tail(500)
    blocked = sum(1 for e in entries if e.get("decision") == "block")
    reviewed = sum(1 for e in entries if e.get("decision") == "review")
    allowed = sum(1 for e in entries if e.get("decision") == "allow")
    recent = []
    for e in reversed(entries[-5:]):
        recent.append({
            "decision": e.get("decision", "?"),
            "binary": (e.get("command", "") or "").split()[0] if e.get("command") else e.get("tool", "?"),
        })
    return {"blocked": blocked, "reviewed": reviewed, "allowed": allowed, "recent": recent}


# ── Page routes ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── API routes ───────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    return jsonify({**_status_info(), "stats": _quick_stats()})


@app.route("/api/feed")
def api_feed():
    n = request.args.get("n", 100, type=int)
    decision_filter = request.args.get("decision", "")
    entries = audit_log.tail(min(n, 500))
    entries.reverse()
    if decision_filter:
        entries = [e for e in entries if e.get("decision") == decision_filter]
    return jsonify(entries)


@app.route("/api/app-control")
def api_app_control_get():
    ac = AppControl()
    return jsonify(ac.as_dict())


@app.route("/api/app-control", methods=["POST"])
def api_app_control_set():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    action = data.get("action", "").strip()
    kind = data.get("kind", "binary").strip()
    if not token:
        return jsonify({"error": "token required"}), 400
    ac = AppControl()
    if kind == "domain":
        if action == "remove":
            ac.remove_domain(token)
            return jsonify({"ok": True, "removed": token, "kind": "domain"})
        decision_map = {"allow": AppDecision.ALLOW, "block": AppDecision.BLOCK}
        decision = decision_map.get(action)
        if decision is None:
            return jsonify({"error": f"invalid action for domain: {action}"}), 400
        ac.add_domain(token, decision)
        return jsonify({"ok": True, "token": token, "action": action, "kind": "domain"})
    else:
        if action == "remove":
            ac.remove(token)
            return jsonify({"ok": True, "removed": token, "kind": "binary"})
        decision_map = {"allow": AppDecision.ALLOW, "block": AppDecision.BLOCK, "review": AppDecision.REVIEW}
        decision = decision_map.get(action)
        if decision is None:
            return jsonify({"error": f"invalid action: {action}"}), 400
        ac.add(token, decision)
        return jsonify({"ok": True, "token": token, "action": action, "kind": "binary"})


@app.route("/api/test", methods=["POST"])
def api_test():
    data = request.get_json(silent=True) or {}
    command = data.get("command", "").strip()
    if not command:
        return jsonify({"error": "command required"}), 400

    # Check app_control — domain blocks first (beat binary allows),
    # then binary checks, then fall through to scoring.
    first_token = command.split()[0] if command else ""
    ac = AppControl()

    # Domain block always wins
    domain_decision = ac.check_url(command)
    if domain_decision == AppDecision.BLOCK:
        return jsonify({
            "decision": "block",
            "score": 100,
            "reason": "domain_control: blocked domain in command",
            "sensitive_path": False,
            "rule_hits": [],
            "app_control": "domain_block",
        })

    ac_decision = ac.check(first_token)
    if ac_decision == AppDecision.BLOCK:
        return jsonify({
            "decision": "block",
            "score": 100,
            "reason": f"app_control: {first_token} is blocked",
            "sensitive_path": False,
            "rule_hits": [],
            "app_control": "block",
        })
    if ac_decision == AppDecision.ALLOW:
        return jsonify({
            "decision": "allow",
            "score": 0,
            "reason": f"app_control: {first_token} is allowed",
            "sensitive_path": False,
            "rule_hits": [],
            "app_control": "allow",
        })

    try:
        v = score_command(command)
        return jsonify({
            "decision": v.decision,
            "score": v.score,
            "reason": v.reason,
            "sensitive_path": v.sensitive_path,
            "rule_hits": [
                {"rule_id": h.rule_id, "name": h.name, "score_floor": h.score_floor, "evidence": h.evidence}
                for h in v.rule_hits[:10]
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pause", methods=["POST"])
def api_pause():
    sentinel = _pause_sentinel_path()
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.touch()
    return jsonify({"paused": True})


@app.route("/api/resume", methods=["POST"])
def api_resume():
    sentinel = _pause_sentinel_path()
    try:
        sentinel.unlink(missing_ok=True)
    except Exception:
        pass
    return jsonify({"paused": False})


@app.route("/api/rules")
def api_rules():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    search = request.args.get("q", "").strip().lower()
    try:
        from ralf.shared.rules import RuleEngine
        engine = RuleEngine()
        rules = engine._rules
        if search:
            def _rule_matches(r, q):
                if q in (r.name or "").lower(): return True
                if q in (r.id or "").lower(): return True
                if r.binary and any(q in b.lower() or b.lower() == q for b in r.binary): return True
                if r.contains and any(q in c.lower() or c.lower() in q for c in r.contains): return True
                if r.contains_any and any(q in c.lower() or c.lower() in q for c in r.contains_any): return True
                if r.regex_source and q in r.regex_source.lower(): return True
                return False
            rules = [r for r in rules if _rule_matches(r, search)]
        total = len(rules)
        start = (page - 1) * per_page
        page_rules = rules[start:start + per_page]
        return jsonify({
            "total": total,
            "page": page,
            "per_page": per_page,
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "score_floor": r.score_floor,
                    "binary": list(r.binary) if r.binary else [],
                    "contains": list(r.contains) if r.contains else [],
                    "contains_any": list(r.contains_any) if r.contains_any else [],
                    "regex": r.regex_source or "",
                }
                for r in page_rules
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rules/custom", methods=["POST"])
def api_rules_custom():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    binary = data.get("binary", "").strip()
    pattern = data.get("pattern", "").strip()
    score_floor = data.get("score_floor", 6)

    if not name:
        return jsonify({"error": "rule name required"}), 400
    if not binary and not pattern:
        return jsonify({"error": "binary or regex pattern required"}), 400

    if pattern:
        try:
            re.compile(pattern)
        except re.error as e:
            return jsonify({"error": f"invalid regex: {e}"}), 400

    try:
        from ralf.shared.rules import RuleEngine, DEFAULT_YAML_PATH
        import yaml
        yaml_path = Path(DEFAULT_YAML_PATH)
        with open(yaml_path) as f:
            data_yaml = yaml.safe_load(f) or {}
        rules_list = data_yaml.get("rules", [])
        new_rule = {
            "id": f"custom_{name.lower().replace(' ', '_')}_{int(time.time())}",
            "name": name,
            "score_floor": int(score_floor),
            "source": "dashboard_custom",
            "match": {},
        }
        if binary:
            new_rule["match"]["binary"] = [binary]
        if pattern:
            new_rule["match"]["regex"] = pattern
        rules_list.append(new_rule)
        data_yaml["rules"] = rules_list
        with open(yaml_path, "w") as f:
            yaml.safe_dump(data_yaml, f, default_flow_style=False)
        auto_compile = data.get("auto_compile", True)
        if auto_compile:
            _recompile_rules()
        return jsonify({"ok": True, "rule_id": new_rule["id"], "compiled": auto_compile})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rules/compile", methods=["POST"])
def api_rules_compile():
    try:
        _recompile_rules()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _recompile_rules():
    from ralf.shared.rules import RuleEngine
    from ralf.shared.verdict_engine import reset_cache
    engine = RuleEngine()
    cache_path = _rules_cache_path()
    engine.to_pickle(cache_path)
    reset_cache()


@app.route("/api/knowledge-counts")
def api_knowledge_counts():
    counts = {}
    try:
        from ralf.mitre.attack_linux import load_matrix as load_linux
        load_linux.cache_clear()
        counts["mitre-linux"] = len(load_linux().techniques)
    except Exception:
        counts["mitre-linux"] = 0
    try:
        from ralf.mitre.attack_macos import load_matrix as load_macos
        load_macos.cache_clear()
        counts["mitre-macos"] = len(load_macos().techniques)
    except Exception:
        counts["mitre-macos"] = 0
    try:
        from ralf.detection.cwe_registry import list_covered_cwes
        counts["cwe"] = len(list_covered_cwes())
    except Exception:
        counts["cwe"] = 0
    try:
        from ralf.detection.supply_chain import _DB_SEARCH_PATHS
        import sqlite3
        counts["cve"] = 0
        for p in _DB_SEARCH_PATHS:
            if p.exists():
                try:
                    conn = sqlite3.connect(str(p))
                    counts["cve"] = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
                    conn.close()
                    break
                except Exception:
                    continue
    except Exception:
        counts["cve"] = 0
    try:
        from ralf.discovery.loobins_map import load_catalog
        load_catalog.cache_clear()
        cat = load_catalog()
        counts["loobins"] = len(cat.binaries)
    except Exception:
        counts["loobins"] = 0
    try:
        data_dir = Path(__file__).parent.parent / "data"
        gtfo = data_dir / "gtfobins_capabilities.json"
        if gtfo.exists():
            counts["gtfobins"] = len(json.loads(gtfo.read_text()).get("binaries", []))
        else:
            counts["gtfobins"] = 0
    except Exception:
        counts["gtfobins"] = 0
    # Objective-See IOC count
    try:
        from ralf.threats.ioc_store import IocStore
        store = IocStore()
        try:
            counts["objective-see"] = store.count()
        finally:
            store.close()
    except Exception:
        counts["objective-see"] = 0
    # Bundled knowledge (not sync targets — ship with RALF)
    try:
        from ralf.detection.owasp_mapping import list_categories
        counts["owasp"] = len(list_categories())
    except Exception:
        counts["owasp"] = 0
    try:
        from ralf.detection.asvs_mapping import list_requirements
        counts["asvs"] = len(list_requirements())
    except Exception:
        counts["asvs"] = 0
    try:
        from ralf.detection.semgrep_rulesets import all_known_rulesets
        counts["semgrep"] = len(all_known_rulesets())
    except Exception:
        counts["semgrep"] = 0
    # SAST tools — count rules when available, False when not installed
    try:
        from ralf.detection.ruff_adapter import is_available as ruff_ok
        if ruff_ok():
            import subprocess as _sp
            out = _sp.check_output(["ruff", "rule", "--all", "--output-format", "json"],
                                   text=True, timeout=5)
            security = [r for r in json.loads(out) if r.get("code", "").startswith("S")]
            counts["ruff"] = len(security)
        else:
            counts["ruff"] = False
    except Exception:
        counts["ruff"] = False
    try:
        from ralf.detection.bandit_adapter import is_available as bandit_ok
        if bandit_ok():
            from bandit.core.extension_loader import MANAGER
            counts["bandit"] = len(MANAGER.plugins_by_id)
        else:
            counts["bandit"] = False
    except Exception:
        counts["bandit"] = False
    try:
        from ralf.detection.astgrep_adapter import is_available as astgrep_ok
        counts["astgrep"] = astgrep_ok()
    except Exception:
        counts["astgrep"] = False
    return jsonify(counts)


@app.route("/api/sync", methods=["POST"])
def api_sync():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "all")
    try:
        from ralf.sync import (
            sync_mitre_linux, sync_mitre_macos, sync_cwe,
            sync_loobins, sync_gtfobins, sync_cve,
        )
        from ralf.threats.objective_see import sync_objective_see
        runners = {
            "mitre-linux": lambda: sync_mitre_linux(timeout_sec=60),
            "mitre-macos": lambda: sync_mitre_macos(timeout_sec=60),
            "cwe": lambda: sync_cwe(timeout_sec=60),
            "loobins": lambda: sync_loobins(timeout_sec=60),
            "gtfobins": lambda: sync_gtfobins(timeout_sec=60),
            "cve": lambda: sync_cve(timeout_sec=180),
            "objective-see": lambda: sync_objective_see(timeout_sec=60),
        }
        results = []
        if target == "all":
            for name, fn in runners.items():
                try:
                    r = fn()
                    results.append({"source": name, "ok": r.success, "records": r.record_count})
                except Exception as e:
                    results.append({"source": name, "ok": False, "error": str(e)})
        else:
            fn = runners.get(target)
            if fn is None:
                return jsonify({"error": f"unknown target: {target}"}), 400
            r = fn()
            results.append({"source": target, "ok": r.success, "records": r.record_count})
        return jsonify({"ok": True, "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _scan_cache_path() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "ralf-free" / "last_scan.json"


def _save_scan_report(data: dict) -> None:
    p = _scan_cache_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))


def _load_scan_report() -> dict | None:
    p = _scan_cache_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


@app.route("/api/scan")
def api_scan_get():
    cached = _load_scan_report()
    if cached:
        return jsonify(cached)
    return jsonify({"score": None, "grade": None, "results": []})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        from ralf.scanner.runner import run_all_checks
        report = run_all_checks()
        data = {
            "score": report.score,
            "grade": report.grade,
            "ts": report.ts,
            "results": [r.to_dict() for r in report.results],
        }
        _save_scan_report(data)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def main():
    """Entry point for ``ralf-free dashboard``."""
    print(f"\n  RALF Free Dashboard → http://127.0.0.1:{DASHBOARD_PORT}\n")
    app.run(host="127.0.0.1", port=DASHBOARD_PORT, debug=False)


if __name__ == "__main__":
    main()
