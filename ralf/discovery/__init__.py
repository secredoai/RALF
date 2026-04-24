"""Discovery primitives — LOOBins catalog for macOS and (later) GTFOBins for Linux.

The discovery package hosts public-knowledge binary-capability catalogs. Each
catalog maps a native system binary to its known offensive / dual-use
capabilities, MITRE ATT&CK technique IDs, and an intent tag used by the
verdict engine.

Currently shipping:

- :mod:`ralf.discovery.loobins_map` — macOS binaries (loobins.io, MIT-licensed
  public catalog curated by the LOOBins community).

The companion Linux catalog (GTFOBins) is sourced from the learned-rules YAML
via ``source: gtfobins_*`` rule tags. A dedicated ``gtfobins_map`` module may
be added in a later round to parallel this macOS module.
"""
from ralf.discovery.loobins_map import (
    LoobinsBinary,
    load_catalog,
    list_binaries,
    get_binary,
    coverage_summary,
)

__all__ = [
    "LoobinsBinary",
    "load_catalog",
    "list_binaries",
    "get_binary",
    "coverage_summary",
]
