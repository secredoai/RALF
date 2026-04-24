"""CLI subcommands for public security-knowledge catalogs.

Exposes ``ralf-free`` subcommands that let users browse the catalogs shipped
with RALF Free:

- ``loobins list|show|coverage`` — macOS offensive-binary catalog
- ``mitre list|show|coverage --platform linux|macos`` — ATT&CK techniques
- ``scan-cwe list|show|coverage`` — CWE Top 25 registry
- ``scan-owasp list|show|coverage`` — OWASP Top 10 (2021)
- ``semgrep-status`` — Semgrep availability + which rulesets would run

Main ``cli.py`` imports :func:`add_subparsers` + :func:`handlers` and splices
them into the top-level parser. Keeping this module separate keeps the main
CLI from bloating as more knowledge catalogs land.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Callable


# ────────────────────────────────────────────────────────────────────────
# LOOBins
# ────────────────────────────────────────────────────────────────────────


def _cmd_loobins(args: argparse.Namespace) -> int:
    from ralf.discovery import list_binaries, get_binary, coverage_summary

    sub = args.loobins_cmd
    if sub == "list":
        rows = list_binaries()
        if args.json:
            print(json.dumps([b.to_dict() for b in rows], indent=2))
            return 0
        for b in rows:
            caps = ",".join(b.capability_tags[:3])
            print(f"{b.name:32} {b.intent:20} {caps}")
        print(f"\n{len(rows)} macOS binaries catalogued.")
        return 0

    if sub == "show":
        b = get_binary(args.name)
        if b is None:
            print(f"error: no LOOBins entry for {args.name!r}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(b.to_dict(), indent=2))
            return 0
        print(f"Binary:        {b.name}")
        print(f"Path:          {b.path}")
        print(f"Description:   {b.short_description}")
        print(f"Capabilities:  {', '.join(b.capability_tags) or '(none)'}")
        print(f"MITRE:         {', '.join(b.mitre_techniques) or '(none)'}")
        print(f"Intent:        {b.intent}")
        print(f"Example use:   {b.example_use}")
        return 0

    if sub == "coverage":
        cov = coverage_summary()
        if args.json:
            print(json.dumps(cov, indent=2))
            return 0
        print(f"LOOBins catalog  ({cov['source']})")
        print(f"  last updated:          {cov['last_updated']}")
        print(f"  binaries:              {cov['total_binaries']}")
        print(f"  unique MITRE IDs:      {cov['unique_mitre_techniques']}")
        print(f"  unique intent tags:    {cov['unique_intents']}")
        print(f"  by capability:")
        for tag, n in cov["by_capability"].items():
            print(f"    {tag:22} {n}")
        return 0

    print("usage: ralf-free loobins {list|show|coverage}", file=sys.stderr)
    return 2


# ────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK
# ────────────────────────────────────────────────────────────────────────


def _mitre_module(platform: str):
    if platform == "macos":
        from ralf.mitre import attack_macos as mod
        return mod
    from ralf.mitre import attack_linux as mod
    return mod


def _cmd_mitre(args: argparse.Namespace) -> int:
    platform = (args.platform or "").lower()
    if platform not in ("linux", "macos"):
        import platform as _plat
        platform = "macos" if _plat.system() == "Darwin" else "linux"

    mod = _mitre_module(platform)
    sub = args.mitre_cmd

    if sub == "list":
        techs = mod.list_techniques(tactic=args.tactic)
        if args.json:
            print(json.dumps(
                [{"id": t.id, "name": t.name, "tactic": t.tactic} for t in techs],
                indent=2,
            ))
            return 0
        for t in techs:
            print(f"{t.id:14} {t.tactic:22} {t.name}")
        print(f"\n{len(techs)} techniques on platform={platform}"
              + (f" (tactic={args.tactic})" if args.tactic else ""))
        return 0

    if sub == "show":
        t = mod.get_technique(args.technique_id)
        if t is None:
            print(f"error: no ATT&CK entry for {args.technique_id!r} on {platform}",
                  file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(
                {"id": t.id, "name": t.name, "tactic": t.tactic,
                 "description": t.description, "platform": platform},
                indent=2,
            ))
            return 0
        print(f"Technique:     {t.id}")
        print(f"Name:          {t.name}")
        print(f"Tactic:        {t.tactic}")
        print(f"Platform:      {platform}")
        print(f"Description:   {t.description}")
        return 0

    if sub == "coverage":
        cov = mod.coverage_summary()
        if args.json:
            print(json.dumps(cov, indent=2))
            return 0
        print(f"MITRE ATT&CK {platform.upper()}  ({cov['source']})")
        print(f"  last updated:    {cov['last_updated']}")
        print(f"  total techniques: {cov['total_techniques']}")
        print(f"  tactics:")
        for tac, n in cov["techniques_per_tactic"].items():
            print(f"    {tac:24} {n}")
        return 0

    print("usage: ralf-free mitre --platform {linux|macos} {list|show|coverage}",
          file=sys.stderr)
    return 2


# ────────────────────────────────────────────────────────────────────────
# CWE registry
# ────────────────────────────────────────────────────────────────────────


def _cmd_scan_cwe(args: argparse.Namespace) -> int:
    from ralf.detection import cwe_registry

    sub = args.cwe_cmd

    if sub == "list":
        entries = (cwe_registry.list_covered_cwes() if args.covered_only
                   else cwe_registry.list_all_cwes())
        if args.json:
            print(json.dumps(
                [{"id": e.id, "name": e.name, "owasp": e.owasp,
                  "applicable": list(e.applicable),
                  "detectors": list(e.detectors)} for e in entries],
                indent=2,
            ))
            return 0
        for e in entries:
            status = "●" if e.is_covered else "○"
            rank = f"#{e.rank_2024}" if e.rank_2024 else "  "
            print(f"{status} {e.id:12} {rank:>4}  {e.owasp:5}  {e.name}")
        print(f"\n{len(entries)} CWE entries "
              f"({sum(1 for e in entries if e.is_covered)} covered, "
              f"{sum(1 for e in entries if not e.is_covered)} not applicable/covered).")
        return 0

    if sub == "show":
        e = cwe_registry.get_cwe(args.cwe_id)
        if e is None:
            print(f"error: no registry entry for {args.cwe_id!r}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(
                {"id": e.id, "name": e.name, "owasp": e.owasp,
                 "applicable": list(e.applicable),
                 "detectors": list(e.detectors),
                 "note": e.note,
                 "rank_2024": e.rank_2024,
                 "is_covered": e.is_covered},
                indent=2,
            ))
            return 0
        print(f"CWE ID:        {e.id}")
        print(f"Name:          {e.name}")
        print(f"OWASP:         {e.owasp or '(none)'}")
        print(f"Applicable:    {', '.join(e.applicable) or '(N/A)'}")
        print(f"Detectors:     {', '.join(e.detectors) or '(not yet wired)'}")
        print(f"Top 25 rank:   {e.rank_2024 or '(outside 2024 Top 25)'}")
        if e.note:
            print(f"Note:          {e.note}")
        return 0

    if sub == "coverage":
        cov = cwe_registry.coverage_summary()
        if args.json:
            print(json.dumps(cov, indent=2))
            return 0
        print("CWE registry")
        print(f"  total in registry:  {cov['total_cwes_in_registry']}")
        print(f"  covered:            {cov['covered']}")
        print(f"  uncovered:          {cov['uncovered']}")
        print(f"  by language:")
        for lang, n in cov["by_language"].items():
            print(f"    {lang:10} {n}")
        print(f"  by OWASP category:")
        for owasp, n in cov["by_owasp_category"].items():
            print(f"    {owasp}   {n}")
        return 0

    print("usage: ralf-free scan-cwe {list|show|coverage}", file=sys.stderr)
    return 2


# ────────────────────────────────────────────────────────────────────────
# OWASP Top 10
# ────────────────────────────────────────────────────────────────────────


def _cmd_scan_owasp(args: argparse.Namespace) -> int:
    from ralf.detection import owasp_mapping

    sub = args.owasp_cmd

    if sub == "list":
        cats = owasp_mapping.list_categories()
        if args.json:
            print(json.dumps(
                [{"id": c.id, "name": c.name,
                  "ralf_coverage": list(c.ralf_coverage),
                  "cheat_sheets": list(c.cheat_sheet_urls)} for c in cats],
                indent=2,
            ))
            return 0
        for c in cats:
            n_det = len(c.ralf_coverage)
            print(f"{c.id}  {c.name:44}  {n_det:2} detectors")
        print(f"\nAll {len(cats)} OWASP Top 10 (2021) categories represented.")
        return 0

    if sub == "show":
        c = owasp_mapping.get_category(args.category_id)
        if c is None:
            print(f"error: no OWASP entry for {args.category_id!r}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(
                {"id": c.id, "name": c.name, "description": c.description,
                 "related_cwes": list(c.related_cwes),
                 "ralf_coverage": list(c.ralf_coverage),
                 "cheat_sheets": list(c.cheat_sheet_urls)},
                indent=2,
            ))
            return 0
        print(f"OWASP:         {c.id} — {c.name}")
        print(f"Description:")
        print(f"  {c.description}")
        print(f"Related CWEs ({len(c.related_cwes)}):  {', '.join(c.related_cwes[:12])}"
              f"{'...' if len(c.related_cwes) > 12 else ''}")
        print(f"RALF coverage ({len(c.ralf_coverage)}):")
        for d in c.ralf_coverage:
            print(f"  • {d}")
        print(f"Cheat sheets ({len(c.cheat_sheet_urls)}):")
        for u in c.cheat_sheet_urls:
            print(f"  • {u}")
        return 0

    if sub == "coverage":
        cov = owasp_mapping.coverage_summary()
        if args.json:
            print(json.dumps(cov, indent=2))
            return 0
        print("OWASP Top 10 (2021) — RALF detector coverage")
        for cat_id, n in cov["category_detector_counts"].items():
            print(f"  {cat_id}  {n} detectors")
        return 0

    print("usage: ralf-free scan-owasp {list|show|coverage}", file=sys.stderr)
    return 2


# ────────────────────────────────────────────────────────────────────────
# OWASP ASVS
# ────────────────────────────────────────────────────────────────────────


def _cmd_scan_asvs(args: argparse.Namespace) -> int:
    from ralf.detection import asvs_mapping

    sub = args.asvs_cmd

    if sub == "list":
        reqs = asvs_mapping.list_requirements()
        if args.json:
            print(json.dumps(
                [{"id": r.id, "chapter": r.chapter, "text": r.text,
                  "level": r.level,
                  "related_cwes": list(r.related_cwes),
                  "detectors": list(r.detectors)} for r in reqs],
                indent=2,
            ))
            return 0
        for r in reqs:
            marker = "*" if r.detectors else " "
            print(f"{marker} {r.id:10} L{r.level}  {r.chapter[:32]:32}  "
                  f"{r.text[:60]}")
        print(f"\n{len(reqs)} ASVS requirements; "
              f"{sum(1 for r in reqs if r.detectors)} with detector coverage.")
        return 0

    if sub == "show":
        r = asvs_mapping.get_requirement(args.req_id)
        if r is None:
            print(f"error: no ASVS entry for {args.req_id!r}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps({
                "id": r.id, "chapter": r.chapter, "text": r.text,
                "level": r.level,
                "related_cwes": list(r.related_cwes),
                "detectors": list(r.detectors),
            }, indent=2))
            return 0
        print(f"ASVS:       {r.id}")
        print(f"Chapter:    {r.chapter}")
        print(f"Level:      {r.level}")
        print(f"Text:       {r.text}")
        print(f"Related CWEs:  {', '.join(r.related_cwes) or '(none)'}")
        print(f"Detectors:     {', '.join(r.detectors) or '(manual-review only)'}")
        return 0

    if sub == "coverage":
        cov = asvs_mapping.coverage_summary()
        if args.json:
            print(json.dumps(cov, indent=2))
            return 0
        print("OWASP ASVS v5 (curated subset)")
        print(f"  total requirements:  {cov['total_requirements']}")
        print(f"  with detectors:      {cov['with_detectors']}")
        print(f"  level 1:             {cov['level_1_count']}")
        print(f"  level 2:             {cov['level_2_count']}")
        print(f"  by chapter:")
        for ch, n in cov["by_chapter"].items():
            print(f"    {ch[:36]:36} {n}")
        return 0

    print("usage: ralf-free scan-asvs {list|show|coverage}", file=sys.stderr)
    return 2


# ────────────────────────────────────────────────────────────────────────
# mSCP (NIST macOS Security Compliance Project)
# ────────────────────────────────────────────────────────────────────────


def _cmd_mscp(args: argparse.Namespace) -> int:
    from ralf.scanner import mscp_macos

    sub = args.mscp_cmd

    if sub == "list":
        rules = mscp_macos.list_rules(category=args.category)
        if args.json:
            print(json.dumps(
                [{"id": r.id, "title": r.title, "category": r.category,
                  "severity": r.severity,
                  "nist_800_53": list(r.nist_800_53),
                  "disa_stig": list(r.disa_stig),
                  "cis": list(r.cis)} for r in rules],
                indent=2,
            ))
            return 0
        for r in rules:
            nist = ",".join(r.nist_800_53[:2]) if r.nist_800_53 else "-"
            print(f"{r.id:50}  {r.severity:7}  {r.category:10}  {nist}")
        print(f"\n{len(rules)} mSCP rules"
              + (f" in category '{args.category}'" if args.category else ""))
        return 0

    if sub == "show":
        r = mscp_macos.get_rule(args.rule_id)
        if r is None:
            print(f"error: no mSCP rule named {args.rule_id!r}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps({
                "id": r.id, "title": r.title, "category": r.category,
                "severity": r.severity,
                "nist_800_53": list(r.nist_800_53),
                "disa_stig": list(r.disa_stig),
                "cis": list(r.cis),
            }, indent=2))
            return 0
        print(f"Rule:       {r.id}")
        print(f"Title:      {r.title}")
        print(f"Category:   {r.category}")
        print(f"Severity:   {r.severity}")
        print(f"NIST 800-53:  {', '.join(r.nist_800_53) or '(none)'}")
        print(f"DISA STIG:    {', '.join(r.disa_stig) or '(none)'}")
        print(f"CIS macOS:    {', '.join(r.cis) or '(none)'}")
        return 0

    if sub == "coverage":
        cov = mscp_macos.coverage_summary()
        if args.json:
            print(json.dumps(cov, indent=2))
            return 0
        print("NIST macOS Security Compliance Project (mSCP) — RALF bundle")
        print(f"  total rules:         {cov['total_rules']}")
        print(f"  with NIST 800-53:    {cov['with_nist_refs']}")
        print(f"  with DISA STIG:      {cov['with_stig_refs']}")
        print(f"  with CIS cross-ref:  {cov['with_cis_refs']}")
        print(f"  unique NIST controls: {cov['unique_nist_controls']}")
        print(f"  by category:")
        for cat, n in cov["by_category"].items():
            print(f"    {cat:12} {n}")
        print(f"  by severity:")
        for sev, n in cov["by_severity"].items():
            print(f"    {sev:12} {n}")
        return 0

    print("usage: ralf-free mscp {list|show|coverage}", file=sys.stderr)
    return 2


# ────────────────────────────────────────────────────────────────────────
# Semgrep status
# ────────────────────────────────────────────────────────────────────────


def _cmd_semgrep_status(args: argparse.Namespace) -> int:
    from ralf.detection import semgrep_adapter, semgrep_rulesets

    available = semgrep_adapter.is_available()
    binary = semgrep_adapter.semgrep_binary()
    ver = semgrep_adapter.version() if available else None
    rulesets = semgrep_rulesets.all_known_rulesets()

    if args.json:
        print(json.dumps({
            "available": available,
            "binary": binary,
            "version": ver,
            "total_rulesets": len(rulesets),
            "always_on": list(semgrep_rulesets.ALWAYS_ON_RULESETS),
            "language_rulesets": {k: list(v) for k, v in semgrep_rulesets.LANGUAGE_RULESETS.items()},
        }, indent=2))
        return 0

    print("Semgrep status")
    print(f"  available: {'yes' if available else 'no'}")
    print(f"  binary:    {binary or '(not found on PATH)'}")
    print(f"  version:   {ver or '(n/a)'}")
    print(f"  rulesets:  {len(rulesets)} total "
          f"({len(semgrep_rulesets.ALWAYS_ON_RULESETS)} always-on "
          f"+ {sum(len(v) for v in semgrep_rulesets.LANGUAGE_RULESETS.values())} language-specific)")
    print()
    print("  Always-on rulesets:")
    for r in semgrep_rulesets.ALWAYS_ON_RULESETS:
        print(f"    {r}")
    if not available:
        print()
        print("  Semgrep is not installed. To enable expanded SAST coverage:")
        print("      pip install semgrep")
    return 0


# ────────────────────────────────────────────────────────────────────────
# Parser + dispatch registration
# ────────────────────────────────────────────────────────────────────────


def add_subparsers(sub: argparse._SubParsersAction) -> None:
    """Add knowledge-catalog subparsers to the main CLI parser."""

    # loobins
    p = sub.add_parser("loobins", help="macOS offensive-binary catalog (LOOBins)")
    lsub = p.add_subparsers(dest="loobins_cmd", metavar="<sub>")
    p_list = lsub.add_parser("list", help="List all catalogued binaries")
    p_list.add_argument("--json", action="store_true")
    p_show = lsub.add_parser("show", help="Show detail for one binary")
    p_show.add_argument("name")
    p_show.add_argument("--json", action="store_true")
    p_cov = lsub.add_parser("coverage", help="Show catalog coverage summary")
    p_cov.add_argument("--json", action="store_true")

    # mitre
    p = sub.add_parser("mitre", help="MITRE ATT&CK technique catalog (Linux / macOS)")
    p.add_argument("--platform", choices=["linux", "macos"], default=None,
                   help="ATT&CK platform (defaults to the current host OS)")
    msub = p.add_subparsers(dest="mitre_cmd", metavar="<sub>")
    p_list = msub.add_parser("list", help="List techniques")
    p_list.add_argument("--tactic", default=None,
                        help="Filter by tactic (e.g. persistence, defense_evasion)")
    p_list.add_argument("--json", action="store_true")
    p_show = msub.add_parser("show", help="Show one technique")
    p_show.add_argument("technique_id", help="e.g. T1059.004")
    p_show.add_argument("--json", action="store_true")
    p_cov = msub.add_parser("coverage", help="Show ATT&CK coverage summary")
    p_cov.add_argument("--json", action="store_true")

    # scan-cwe
    p = sub.add_parser("scan-cwe", help="CWE Top 25 registry (RALF's covered classes)")
    csub = p.add_subparsers(dest="cwe_cmd", metavar="<sub>")
    p_list = csub.add_parser("list", help="List CWEs in the registry")
    p_list.add_argument("--covered-only", action="store_true",
                        help="Show only CWEs with at least one RALF detector")
    p_list.add_argument("--json", action="store_true")
    p_show = csub.add_parser("show", help="Show detail for one CWE")
    p_show.add_argument("cwe_id", help="e.g. CWE-78")
    p_show.add_argument("--json", action="store_true")
    p_cov = csub.add_parser("coverage", help="Show registry coverage summary")
    p_cov.add_argument("--json", action="store_true")

    # scan-owasp
    p = sub.add_parser("scan-owasp", help="OWASP Top 10 (2021) — RALF coverage map")
    osub = p.add_subparsers(dest="owasp_cmd", metavar="<sub>")
    p_list = osub.add_parser("list", help="List categories A01..A10")
    p_list.add_argument("--json", action="store_true")
    p_show = osub.add_parser("show", help="Show detail for one category")
    p_show.add_argument("category_id", help="e.g. A01")
    p_show.add_argument("--json", action="store_true")
    p_cov = osub.add_parser("coverage", help="Show OWASP coverage summary")
    p_cov.add_argument("--json", action="store_true")

    # scan-asvs
    p = sub.add_parser("scan-asvs", help="OWASP ASVS v5 — requirement registry")
    asub = p.add_subparsers(dest="asvs_cmd", metavar="<sub>")
    p_list = asub.add_parser("list", help="List ASVS requirements")
    p_list.add_argument("--json", action="store_true")
    p_show = asub.add_parser("show", help="Show detail for one requirement")
    p_show.add_argument("req_id", help="e.g. V5.3.4")
    p_show.add_argument("--json", action="store_true")
    p_cov = asub.add_parser("coverage", help="Show ASVS coverage summary")
    p_cov.add_argument("--json", action="store_true")

    # mscp
    p = sub.add_parser("mscp", help="NIST macOS Security Compliance Project (mSCP)")
    msub = p.add_subparsers(dest="mscp_cmd", metavar="<sub>")
    p_list = msub.add_parser("list", help="List mSCP rules")
    p_list.add_argument("--category", default=None,
                        help="Filter by category (audit/auth/os/pwpolicy/sysprefs/icloud)")
    p_list.add_argument("--json", action="store_true")
    p_show = msub.add_parser("show", help="Show one rule")
    p_show.add_argument("rule_id")
    p_show.add_argument("--json", action="store_true")
    p_cov = msub.add_parser("coverage", help="Show mSCP bundle coverage summary")
    p_cov.add_argument("--json", action="store_true")

    # semgrep-status
    p = sub.add_parser("semgrep-status",
                       help="Show Semgrep availability and ruleset selection")
    p.add_argument("--json", action="store_true")


handlers: dict[str, Callable[[argparse.Namespace], int]] = {
    "loobins": _cmd_loobins,
    "mitre": _cmd_mitre,
    "scan-cwe": _cmd_scan_cwe,
    "scan-owasp": _cmd_scan_owasp,
    "scan-asvs": _cmd_scan_asvs,
    "mscp": _cmd_mscp,
    "semgrep-status": _cmd_semgrep_status,
}


__all__ = ["add_subparsers", "handlers"]
