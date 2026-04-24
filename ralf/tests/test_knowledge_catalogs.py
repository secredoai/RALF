"""Smoke tests for the public-knowledge catalog bundles.

Locks in the coverage claims surfaced by the CLI (`ralf-free loobins / mitre /
scan-cwe / scan-owasp / semgrep-status`). Run with ``pytest -q`` from the
repo root.

These tests do NOT assert exact counts — the catalogs will grow over time.
They assert lower bounds ("at least N") and structural invariants ("every
tactic present", "every OWASP category has ≥1 detector", "every CWE entry
has required fields").
"""
from __future__ import annotations

import pytest


# ── LOOBins ───────────────────────────────────────────────────────────────


def test_loobins_catalog_loads_with_minimum_coverage():
    from ralf.discovery import list_binaries, coverage_summary

    binaries = list_binaries()
    # Authoritative upstream (loobins.io / github.com/infosecB/LOOBins) has
    # ~59 binaries as of 2026-04. The lower bound is set conservatively so
    # the test survives small additions or removals upstream.
    assert len(binaries) >= 50, f"LOOBins catalog too small: {len(binaries)} < 50"

    cov = coverage_summary()
    assert cov["total_binaries"] == len(binaries)

    # Every entry must have a name; capability_tags and mitre_techniques may
    # be empty on newly-added entries that haven't been fully annotated yet.
    for b in binaries:
        assert b.name, "LOOBins entry missing name"


def test_loobins_has_flagship_binaries():
    from ralf.discovery import get_binary

    # These are the high-severity macOS offensive primitives we expect any
    # reasonable LOOBins snapshot to carry. Verified present in the
    # authoritative upstream (github.com/infosecB/LOOBins) at sync time.
    flagship = ["launchctl", "osascript", "security", "tmutil", "sqlite3",
                "plutil", "defaults", "spctl", "csrutil", "codesign",
                "dscl", "xattr"]
    for name in flagship:
        b = get_binary(name)
        assert b is not None, f"LOOBins missing flagship binary {name!r}"


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────


def test_mitre_linux_matrix():
    from ralf.mitre import attack_linux

    techs = attack_linux.list_techniques()
    # Full MITRE ATT&CK Linux matrix has ~350 techniques after the sync pulls
    # from the official STIX feed. Lower bound set at 250 to tolerate minor
    # upstream churn or deprecations between releases.
    assert len(techs) >= 250, f"Linux ATT&CK thin: {len(techs)} < 250 techniques"

    tactics = attack_linux.tactics()
    required = {"execution", "persistence", "privilege_escalation",
                "defense_evasion", "credential_access", "discovery",
                "collection", "command_and_control", "exfiltration", "impact"}
    missing = required - set(tactics)
    assert not missing, f"Linux matrix missing tactics: {missing}"


def test_mitre_macos_matrix():
    from ralf.mitre import attack_macos

    techs = attack_macos.list_techniques()
    # Full MITRE ATT&CK macOS matrix has ~350 techniques after the sync.
    assert len(techs) >= 250, f"macOS ATT&CK thin: {len(techs)} < 250 techniques"

    tactics = attack_macos.tactics()
    required = {"execution", "persistence", "privilege_escalation",
                "defense_evasion", "credential_access", "discovery",
                "collection", "command_and_control", "exfiltration", "impact"}
    missing = required - set(tactics)
    assert not missing, f"macOS matrix missing tactics: {missing}"


def test_mitre_flagship_techniques():
    from ralf.mitre import attack_linux, attack_macos

    # Linux flagships — high-severity techniques we expect to stay stable.
    for tid in ["T1059.004", "T1003.008", "T1055", "T1070.003", "T1021.004"]:
        assert attack_linux.get_technique(tid) is not None, (
            f"Linux matrix missing flagship technique {tid}"
        )

    # macOS flagships — T1547.011 was deprecated in ATT&CK v14 and replaced
    # by T1647 (Plist File Modification). T1556.001 was likewise restructured.
    # Use currently-present T-IDs.
    for tid in ["T1059.002", "T1555.001", "T1543.001", "T1553.001",
                "T1647", "T1543.004"]:
        assert attack_macos.get_technique(tid) is not None, (
            f"macOS matrix missing flagship technique {tid}"
        )


# ── CWE registry ──────────────────────────────────────────────────────────


def test_cwe_registry_coverage():
    from ralf.detection import cwe_registry

    cov = cwe_registry.coverage_summary()
    # Post-sync the CWE registry carries the full MITRE CWE dictionary subset
    # applicable to our languages — several hundred entries. Lower bound set
    # conservatively to tolerate upstream schema drift.
    assert cov["total_cwes_in_registry"] >= 500, (
        f"CWE registry thin after sync: {cov['total_cwes_in_registry']} entries"
    )
    assert cov["covered"] >= 25, (
        f"Not enough CWEs covered by detectors: {cov['covered']}"
    )

    # Every covered CWE must have ≥1 detector and ≥1 applicable language.
    # The OWASP mapping is best-effort (not every CWE maps to a Top-10 bucket),
    # so we don't gate on it.
    for e in cwe_registry.list_covered_cwes():
        assert e.detectors, f"{e.id} marked covered but has no detectors"
        assert e.applicable, f"{e.id} has detectors but no applicable languages"


def test_cwe_flagship_entries():
    from ralf.detection import cwe_registry

    for cwe_id in ["CWE-22", "CWE-78", "CWE-89", "CWE-94", "CWE-502",
                   "CWE-522", "CWE-611", "CWE-732", "CWE-798", "CWE-918"]:
        e = cwe_registry.get_cwe(cwe_id)
        assert e is not None, f"Missing flagship CWE {cwe_id}"
        assert e.is_covered, f"{cwe_id} present but not covered"


# ── OWASP Top 10 ──────────────────────────────────────────────────────────


def test_owasp_all_ten_categories_represented():
    from ralf.detection import owasp_mapping

    cats = owasp_mapping.list_categories()
    assert len(cats) == 10, f"OWASP Top 10 should have exactly 10: got {len(cats)}"

    ids = {c.id for c in cats}
    assert ids == {f"A{n:02d}" for n in range(1, 11)}, f"OWASP IDs mismatch: {ids}"

    # Every category must have ≥1 RALF detector + ≥1 cheat-sheet URL
    for c in cats:
        assert c.ralf_coverage, f"{c.id} has no RALF detector coverage"
        assert c.cheat_sheet_urls, f"{c.id} has no cheat-sheet URL references"
        assert c.related_cwes, f"{c.id} lists no related CWEs"


def test_owasp_cheatsheet_lookup_by_cwe():
    from ralf.detection import owasp_mapping

    urls = owasp_mapping.cheat_sheet_urls_for_cwe("CWE-78")
    assert urls, "CWE-78 → cheat sheet lookup empty"
    assert any("Injection_Prevention" in u for u in urls), (
        f"CWE-78 should cite the injection-prevention cheat sheet, got {urls}"
    )


# ── Semgrep adapter ───────────────────────────────────────────────────────


def test_semgrep_rulesets_always_on_complete():
    from ralf.detection.semgrep_rulesets import ALWAYS_ON_RULESETS

    # The claim is "OWASP Top 10 + CWE Top 25 + secrets coverage every scan"
    assert "p/owasp-top-ten" in ALWAYS_ON_RULESETS
    assert "p/cwe-top-25" in ALWAYS_ON_RULESETS
    assert "p/secrets" in ALWAYS_ON_RULESETS
    assert "p/security-audit" in ALWAYS_ON_RULESETS


def test_semgrep_language_autodetect():
    from ralf.detection.semgrep_rulesets import (
        language_for_path, rulesets_for_path,
    )

    # Known extensions resolve
    assert language_for_path("foo.py") == "python"
    assert language_for_path("bar.ts") == "typescript"
    assert language_for_path("baz.rb") == "ruby"
    assert language_for_path("Dockerfile") == "dockerfile"

    # Unknown → None
    assert language_for_path("something.xyz") is None

    # Python file gets Python-specific rulesets on top of always-on
    py_rules = rulesets_for_path("foo.py")
    assert "p/python" in py_rules
    assert "p/owasp-top-ten" in py_rules  # always-on included


def test_semgrep_graceful_fallback_when_absent():
    """If Semgrep isn't installed, the adapter returns a clean 'unavailable' result."""
    from ralf.detection import semgrep_adapter

    result = semgrep_adapter.run_semgrep("print('hi')", file_path="x.py")
    # Whether or not Semgrep is installed, the call must not raise.
    assert isinstance(result.available, bool)
    assert isinstance(result.findings, tuple)
    if not result.available:
        assert result.invoked is False
        assert not result.findings


# ── Sync module surface (no network) ──────────────────────────────────────


def test_sync_package_public_api():
    """Every public fetcher is exported and takes the expected signature."""
    import inspect

    from ralf import sync

    for name in ("sync_mitre_linux", "sync_mitre_macos", "sync_cwe",
                 "sync_loobins", "sync_gtfobins"):
        assert hasattr(sync, name), f"sync package missing {name}"
        fn = getattr(sync, name)
        assert callable(fn), f"{name} is not callable"
        sig = inspect.signature(fn)
        assert "output_path" in sig.parameters, (
            f"{name} missing output_path kwarg"
        )
        assert "timeout_sec" in sig.parameters, (
            f"{name} missing timeout_sec kwarg"
        )


def test_sync_rejects_non_https():
    """Per Rule 21 (adversarial thinking) — the base fetcher must reject HTTP."""
    from ralf.sync._base import fetch_bytes, SyncError

    try:
        fetch_bytes("http://example.com/")
    except SyncError as e:
        assert "HTTPS" in str(e), f"Wrong error message: {e}"
        return
    raise AssertionError("fetch_bytes accepted non-HTTPS URL")


def test_sync_user_agent_identifies_tool():
    """User-agent must identify ralf-free so upstreams can rate-limit politely."""
    from ralf.sync._base import default_user_agent

    ua = default_user_agent()
    assert "ralf-free" in ua, f"user-agent missing tool identifier: {ua}"
    assert "python" in ua.lower(), f"user-agent missing python version: {ua}"


# ── Semgrep hook integration (graceful no-op when Semgrep absent) ─────────


def test_cheat_sheet_urls_attached_to_findings():
    """The enrichment layer must attach OWASP Cheat Sheet URLs to any
    FileScanHit that carries a CWE tag.

    Tests the enrichment function directly rather than constructing a
    trigger pattern — the scanner's self-protecting Write-hook would
    block the fixture file otherwise.
    """
    from ralf.detection.code_scanner import FileScanHit, _enrich_with_remediation

    # Seed a synthetic hit with a CWE tag. _enrich_with_remediation does
    # the OWASP lookup we care about.
    bare = FileScanHit(
        blocked=True,
        reason="synthetic",
        cwe="CWE-89",
    )
    enriched = _enrich_with_remediation(bare)
    assert enriched.remediation, "CWE-89 must yield remediation URLs"
    assert any("Injection_Prevention" in url or "SQL_Injection" in url
               for url in enriched.remediation), (
        f"Expected OWASP injection cheat-sheet in remediation: "
        f"{enriched.remediation}"
    )

    # CWE-78 (OS command injection) should produce A03-injection cheat sheets
    bare78 = FileScanHit(blocked=True, reason="synthetic", cwe="CWE-78")
    enriched78 = _enrich_with_remediation(bare78)
    assert enriched78.remediation, "CWE-78 must yield remediation URLs"

    # Empty CWE → no enrichment, returns hit unchanged
    bareempty = FileScanHit(blocked=False, reason="x", cwe="")
    assert _enrich_with_remediation(bareempty) is bareempty


def test_sast_mix_adapters_importable():
    """ruff / bandit / ast-grep adapters load cleanly + expose the expected
    public API even when the binaries aren't installed. Graceful-fallback
    design — modules must be importable in minimal environments.
    """
    from ralf.detection import ruff_adapter, bandit_adapter, astgrep_adapter

    for mod, name in [
        (ruff_adapter,    "ruff"),
        (bandit_adapter,  "bandit"),
        (astgrep_adapter, "ast-grep"),
    ]:
        assert hasattr(mod, "is_available"), f"{name} adapter missing is_available()"
        assert hasattr(mod, "version"),      f"{name} adapter missing version()"
        avail = mod.is_available()
        # Whether installed or not, is_available must return a bool
        assert isinstance(avail, bool)

    # Each adapter's run function must return cleanly for trivial input —
    # even when the binary is absent.
    r = ruff_adapter.run_ruff("print('hi')", file_path="x.py")
    assert isinstance(r.findings, tuple)
    b = bandit_adapter.run_bandit("print('hi')", file_path="x.py")
    assert isinstance(b.findings, tuple)
    a = astgrep_adapter.run_astgrep("print('hi')", file_path="x.py")
    assert isinstance(a.findings, tuple)


def test_sast_dispatcher_graceful_when_no_tools():
    """The dispatcher must return cleanly whether or not the tools are
    installed. Returns ``("", 0)`` for trivial content with no triggers.
    """
    from ralf.adapters._base import _run_sast_adapters

    frag, bump = _run_sast_adapters("x = 1\n", "/tmp/example.py")
    assert isinstance(frag, str)
    assert isinstance(bump, int)
    assert bump >= 0


def test_semgrep_adapter_available_but_not_hook_wired():
    """The Semgrep adapter module is available as a shared primitive but
    the Write-hook path in ``handle_file_write`` no longer invokes Semgrep.
    The cold-start cost (~6 s per invocation) doesn't fit the 5 s Claude
    Code hook budget.
    """
    from ralf.adapters import _base
    from ralf.detection import semgrep_adapter

    # Adapter module still loads + CLI reports status
    assert hasattr(semgrep_adapter, "run_semgrep")
    assert hasattr(semgrep_adapter, "is_available")

    # Hook path no longer calls Semgrep — this helper should be gone
    assert not hasattr(_base, "_run_semgrep_on_content"), (
        "_run_semgrep_on_content should have been removed from Free's hook "
        "path; Semgrep integration is handled separately."
    )
