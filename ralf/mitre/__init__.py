"""MITRE ATT&CK technique catalogs for Linux and macOS.

Each platform gets a curated technique bundle under ``ralf/data/`` plus a
typed loader here. The catalogs are sourced from the official MITRE ATT&CK
STIX feed and filtered to the subset most relevant to agentic-AI defense.

Usage::

    from ralf.mitre import attack_linux, attack_macos

    for t in attack_linux.list_techniques(tactic="persistence"):
        print(t.id, t.name)

    t = attack_macos.get_technique("T1555.001")
    if t:
        print(t.description)
"""
from ralf.mitre import attack_linux, attack_macos

__all__ = ["attack_linux", "attack_macos"]
