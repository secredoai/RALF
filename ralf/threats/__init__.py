"""Objective-See macOS IOC threat feed.

Provides:

- :class:`IocStore` — SQLite-backed IOC database (sha256 + bundle-ID).
- :func:`sync_objective_see` — fetch the Objective-See community malware feed.

CLI surface: ``ralf-free threats sync | status | scan PATH``.
"""
from ralf.threats.ioc_store import IocStore
from ralf.threats.objective_see import sync_objective_see

__all__ = ["IocStore", "sync_objective_see"]
