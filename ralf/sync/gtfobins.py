"""GTFOBins fetcher — Linux offensive-binary catalog.

Pulls the GTFOBins GitHub archive (``GTFOBins/GTFOBins.github.io``), parses
every binary markdown page (YAML front-matter), and emits a learned-rules
YAML snippet that can be merged into ``ralf/data/learned_rules.yaml``.

Unlike LOOBins, GTFOBins data feeds *rule generation* not a standalone data
file — GTFOBins has been the source of ``gtfobins_*`` tagged rules in the
learned-rules corpus since round 1. This fetcher expands the coverage from
the current ~213 binaries to the full upstream set (~380+ binaries, up to
~490 function-binary pairs when LOLBAS-style capability expansion is applied).

Two output modes:

- ``emit_rules=True`` (default) → writes YAML to the configured path that
  can be appended to ``learned_rules.yaml`` with the ``gtfobins_round_7``
  source tag.
- ``emit_rules=False`` → writes a JSON summary to
  ``ralf/data/gtfobins_capabilities.json`` (mirror of LOOBins schema) for
  CLI browsing only.
"""
from __future__ import annotations

import io
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ralf.sync._base import (
    SyncError,
    SyncResult,
    fetch_bytes,
    timer,
    write_json_atomic,
)

log = logging.getLogger(__name__)

_GTFOBINS_URL = (
    "https://codeload.github.com/GTFOBins/GTFOBins.github.io/zip/refs/heads/master"
)
_GTFOBINS_SIZE_CAP = 50 * 1024 * 1024  # 50 MB (repo ~4 MB today)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_OUTPUT = _DATA_DIR / "gtfobins_capabilities.json"

# Characters permitted in a GTFOBins binary filename. Filters out accidental
# non-data files like README.md, .DS_Store, etc. Binary names on disk are
# plain (no extension, occasionally with `.so`) — allow both.
_VALID_BIN_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-._")

# Map GTFOBins function categories → capability + intent
# Score floors deliberately capped for binary-only matching. The rules in
# this file trigger on presence of a binary in a command (no argument context),
# so they must not block legitimate daily usage of common dev tooling. High
# scores require richer context-aware rules that live in the hand-curated
# corpus. Round-7 rules produce "informational" hits — they contribute to
# review-threshold decisions but don't block on their own.
_FUNCTION_TO_CAPABILITY: dict[str, tuple[str, str, int]] = {
    # Each row: (capability_tag, intent, score_floor)
    "shell": ("execution", "spawn_shell", 4),
    "command": ("execution", "spawn_shell", 3),
    "reverse-shell": ("command_and_control", "exfiltrate", 6),
    "non-interactive-reverse-shell": ("command_and_control", "exfiltrate", 5),
    "bind-shell": ("command_and_control", "spawn_shell", 5),
    "non-interactive-bind-shell": ("command_and_control", "spawn_shell", 4),
    "file-upload": ("exfiltration", "exfiltrate", 4),
    "file-download": ("execution", "fetch", 4),
    "file-write": ("persistence", "modify", 4),
    "file-read": ("collection", "read", 3),
    "library-load": ("execution", "spawn_shell", 5),
    "sudo": ("privilege_escalation", "escalate", 6),
    "suid": ("privilege_escalation", "escalate", 6),
    "capabilities": ("privilege_escalation", "escalate", 6),
    "limited-suid": ("privilege_escalation", "escalate", 5),
}

# Binaries that are so commonly used for legitimate daily work that generating
# any binary-only GTFOBins rule for them creates unacceptable false-positive
# rates. These are legitimate everyday developer tools — if they're abused,
# the abuse lives in argument patterns, not binary presence. Rules for these
# binaries must be context-aware (hand-curated), not auto-generated.
_EXCLUDE_FROM_RULE_GEN: set[str] = {
    # Interpreters + package managers that developers run all day
    "python", "python2", "python3", "pip", "pip2", "pip3", "pipx", "poetry",
    "node", "npm", "npx", "pnpm", "yarn", "bun",
    "ruby", "gem", "bundle", "bundler", "rake", "rails",
    "perl", "cpan", "cpanm",
    "go", "gofmt",
    "cargo", "rustc", "rustup",
    "mvn", "maven", "gradle", "ant",
    "dotnet", "nuget",
    "composer", "php",
    "lua", "luarocks",
    # Shells themselves
    "bash", "sh", "zsh", "dash", "ksh", "fish", "tcsh", "csh",
    # Universal CLIs on every developer machine
    "git", "make", "cmake", "ninja", "meson", "ctest",
    # Editors (often appear in shell banners or man references)
    "vi", "vim", "nano", "emacs", "ed", "nvim",
    # Build/test runners
    "docker", "podman", "kubectl", "helm", "terraform",
    # Text processing used constantly
    "awk", "gawk", "sed", "grep", "egrep", "fgrep", "head", "tail",
    "sort", "uniq", "cut", "tr", "wc", "cat", "less", "more",
    "find", "locate", "xargs", "env", "echo", "printf",
}


@dataclass
class _ParsedBin:
    name: str
    functions: set[str] = field(default_factory=set)
    description: str = ""


def _parse_one_entry(raw: bytes, binary_name: str) -> _ParsedBin | None:
    """One GTFOBins entry → ParsedBin.

    Entries are pure YAML (no Jekyll front-matter delimiters). Top-level
    schema: ``{functions: {<function-name>: [use-case, ...], ...},
    description?: str}``.
    """
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None

    # Some very old entries did use ``---`` delimiters. Strip if present.
    stripped = text.lstrip()
    if stripped.startswith("---"):
        # Remove the opening and closing --- lines
        body = stripped.split("\n", 1)[1] if "\n" in stripped else ""
        if "\n---" in body:
            body = body.split("\n---", 1)[0]
        payload = body
    else:
        payload = text

    try:
        doc = yaml.safe_load(payload)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None

    functions = doc.get("functions") or {}
    if not isinstance(functions, dict):
        return None

    parsed = _ParsedBin(name=binary_name)
    for fn_name in functions.keys():
        fn_str = str(fn_name).strip().lower()
        if fn_str in _FUNCTION_TO_CAPABILITY:
            parsed.functions.add(fn_str)

    # Description: GTFOBins rarely carries a text description field; fall
    # back to a generic string.
    desc = doc.get("description")
    parsed.description = str(desc).strip()[:200] if desc else ""

    if not parsed.functions:
        return None

    return parsed


def _is_valid_binary_filename(stem: str) -> bool:
    """Reject README.md, .DS_Store, template artifacts, etc."""
    if not stem:
        return False
    if stem.startswith("."):
        return False
    if stem.lower() in {"readme", "index", "contributing", "license", "scope"}:
        return False
    low = stem.lower()
    return all(ch in _VALID_BIN_CHARS for ch in low)


def _parse_archive(archive_bytes: bytes) -> list[_ParsedBin]:
    """Pull every ``_gtfobins/<name>`` entry out of the GitHub archive.

    GTFOBins files have no consistent extension — entries are just the binary
    name (e.g. ``cat``, ``7z``, ``aa-exec``) containing pure YAML.
    """
    out: dict[str, _ParsedBin] = {}

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            parts = name.split("/")
            # Entry must live under an _gtfobins/ directory within the archive
            if "_gtfobins" not in parts:
                continue
            # Index into parts to ensure _gtfobins is a PATH COMPONENT, not a
            # substring of some other path
            try:
                idx = parts.index("_gtfobins")
            except ValueError:
                continue
            # The entry file must sit directly inside _gtfobins/
            if idx + 1 != len(parts) - 1:
                continue
            filename = parts[-1]
            # Filename is just the binary name, optionally with .so suffix
            stem = filename
            if stem.endswith(".so"):
                stem = stem[:-3]
            if not _is_valid_binary_filename(stem):
                continue
            try:
                raw = zf.read(info)
            except (KeyError, RuntimeError):
                continue
            parsed = _parse_one_entry(raw, stem)
            if parsed is None:
                continue
            if parsed.name in out:
                out[parsed.name].functions.update(parsed.functions)
            else:
                out[parsed.name] = parsed

    return sorted(out.values(), key=lambda p: p.name.lower())


def _to_output_dict(parsed: _ParsedBin) -> dict:
    """Emit GTFOBins schema (mirrors LOOBins for consistency)."""
    # Derive capability tags + dominant intent from all applicable functions
    capabilities: set[str] = set()
    intents: list[tuple[str, int]] = []
    techniques: set[str] = set()
    for fn in parsed.functions:
        if fn in _FUNCTION_TO_CAPABILITY:
            cap, intent, score = _FUNCTION_TO_CAPABILITY[fn]
            capabilities.add(cap)
            intents.append((intent, score))

    # Pick dominant intent = highest score
    intents.sort(key=lambda pair: -pair[1])
    intent = intents[0][0] if intents else "unknown"

    return {
        "name": parsed.name,
        "path": "",  # GTFOBins doesn't declare a canonical path
        "short_description": parsed.description or f"{parsed.name} — see gtfobins.github.io",
        "capability_tags": sorted(capabilities),
        "mitre_techniques": sorted(techniques),
        "functions": sorted(parsed.functions),
        "intent": intent,
    }


def _to_learned_rules(bins: list[_ParsedBin]) -> list[dict]:
    """Emit learned-rule entries compatible with ralf/data/learned_rules.yaml.

    One rule per (binary, function) pair. Rule ID is synthesized so that re-runs
    are idempotent (same input → same rule IDs).

    Skips the binaries in ``_EXCLUDE_FROM_RULE_GEN`` — common developer tooling
    where binary-only matching produces unacceptable false-positive rates on
    legitimate daily work. Those binaries still appear in the JSON catalog
    (and can be context-match'd by hand-curated rules) but don't get
    auto-generated rules.
    """
    rules: list[dict] = []
    seen_ids: set[str] = set()
    skipped_binaries: set[str] = set()
    for parsed in bins:
        lname = parsed.name.lower()
        if lname in _EXCLUDE_FROM_RULE_GEN:
            skipped_binaries.add(parsed.name)
            continue
        for fn in sorted(parsed.functions):
            cap_entry = _FUNCTION_TO_CAPABILITY.get(fn)
            if cap_entry is None:
                continue
            cap, intent, score = cap_entry
            rid = f"lr-gtfo-r7-{parsed.name}-{fn}"
            if rid in seen_ids:
                continue
            seen_ids.add(rid)
            rules.append({
                "id": rid,
                "name": f"GTFOBins {parsed.name} — {fn}",
                "match": {"binary": [parsed.name]},
                "score_floor": score,
                "source": "gtfobins_round_7",
            })
    if skipped_binaries:
        log.info(
            "Skipped %d common dev binaries from GTFOBins rule generation "
            "(exclude list): %s",
            len(skipped_binaries), ", ".join(sorted(skipped_binaries)),
        )
    return rules


def sync_gtfobins(
    *,
    output_path: Path | None = None,
    emit_rules: bool = True,
    rules_output_path: Path | None = None,
    timeout_sec: float = 60.0,
) -> SyncResult:
    """Fetch GTFOBins archive, parse, write JSON (and optionally a learned-rules snippet)."""
    url = _GTFOBINS_URL
    outpath = output_path or _DEFAULT_OUTPUT
    rules_outpath = rules_output_path or (_DATA_DIR / "gtfobins_round_7.rules.yaml")

    with timer() as t:
        try:
            body, _headers = fetch_bytes(
                url, timeout_sec=timeout_sec, size_cap_bytes=_GTFOBINS_SIZE_CAP,
            )
            bytes_fetched = len(body)
            try:
                bins = _parse_archive(body)
            except zipfile.BadZipFile as e:
                raise SyncError(f"GTFOBins archive not a valid zip: {e}") from e

            if len(bins) < 100:
                raise SyncError(
                    f"GTFOBins parse produced only {len(bins)} binaries — schema drift?"
                )

            import datetime as _dt
            binaries_out = [_to_output_dict(b) for b in bins]
            payload = {
                "version": 2,
                "source": "gtfobins.github.io",
                "license_note": (
                    "GTFOBins is CC-BY-3.0 public security knowledge, sourced from "
                    "github.com/GTFOBins/GTFOBins.github.io and refreshed via "
                    "ralf-free sync gtfobins."
                ),
                "upstream_url": url,
                "last_updated": _dt.date.today().isoformat(),
                "description": (
                    "Complete Linux offensive-binary catalog synced from the "
                    "GTFOBins community repository. Each binary lists its "
                    "abuse-function set (shell, file-read, library-load, sudo, "
                    "suid, etc.) and the RALF capability tags + intent + score "
                    "floors derived from those functions."
                ),
                "binaries": binaries_out,
            }
            write_json_atomic(outpath, payload)

            record_count = len(binaries_out)
            warnings: list[str] = []

            if emit_rules:
                rules = _to_learned_rules(bins)
                rules_payload = {
                    "version": 2,
                    "source": "gtfobins_round_7",
                    "generated_from": url,
                    "last_updated": _dt.date.today().isoformat(),
                    "note": (
                        "Generated rules. Merge into ralf/data/learned_rules.yaml "
                        "under the 'rules:' list (dedup by 'id'). Each rule carries "
                        "source: gtfobins_round_7."
                    ),
                    "rules": rules,
                }
                # Write a YAML snippet for review / selective merge
                rules_outpath.parent.mkdir(parents=True, exist_ok=True)
                with rules_outpath.open("w", encoding="utf-8") as f:
                    yaml.safe_dump(
                        rules_payload, f, sort_keys=False, allow_unicode=True,
                    )
                warnings.append(
                    f"Generated {len(rules)} learned-rule entries to {rules_outpath} "
                    "— review then merge into learned_rules.yaml under 'rules:'."
                )

        except SyncError as e:
            return SyncResult(
                source="gtfobins", url=url, success=False, record_count=0,
                output_path=None, bytes_fetched=0, elapsed_sec=t.elapsed,
                error=str(e),
            )

    return SyncResult(
        source="gtfobins", url=url, success=True, record_count=record_count,
        output_path=outpath, bytes_fetched=bytes_fetched, elapsed_sec=t.elapsed,
        warnings=warnings,
    )


__all__ = ["sync_gtfobins"]
