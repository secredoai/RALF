"""Install/uninstall RALF hooks for an agent's settings.json.

Per agent we install MULTIPLE hooks (PreToolUse + PostToolUse for Claude).
Each hook entry is a ``HookEntry(event_key, matcher, command)`` tuple; the
agent profile carries a tuple of them. Older single-hook attributes
(``hook_command`` / ``hook_matcher`` / ``hook_event_key``) are preserved as
properties pointing at the first entry for backwards compatibility.

Public API:
    - :func:`install_for_agent` — wire all configured hooks.
    - :func:`uninstall_for_agent` — remove them.

Both interactive by default (prompt + backup). Pass ``yes=True`` to skip
the prompt — used by tests and by ``setup.sh`` when ``RALF_AUTO_YES=1``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HookEntry:
    """One (event, matcher, command) hook tuple."""
    event_key: str
    matcher: str
    command: str


@dataclass(frozen=True)
class AgentProfile:
    """A single agent and the hooks we install for it."""
    name: str
    settings_path: Path
    description: str
    hooks: tuple[HookEntry, ...]

    # Backwards-compat: callers that read .hook_command etc. get the first.
    @property
    def hook_command(self) -> str:
        return self.hooks[0].command if self.hooks else ""

    @property
    def hook_matcher(self) -> str:
        return self.hooks[0].matcher if self.hooks else ""

    @property
    def hook_event_key(self) -> str:
        return self.hooks[0].event_key if self.hooks else ""


_AGENTS: dict[str, AgentProfile] = {
    "claude": AgentProfile(
        name="claude",
        settings_path=Path(os.path.expanduser("~/.claude/settings.json")),
        description="Claude Code (~/.claude/settings.json)",
        hooks=(
            HookEntry(
                event_key="PreToolUse",
                matcher="Bash|Write|Edit|NotebookEdit|Read|WebFetch|mcp__.*",
                command="python3 -m ralf.adapters.claude_code",
            ),
            HookEntry(
                event_key="PostToolUse",
                matcher="Read|WebFetch|mcp__.*",
                command="python3 -m ralf.adapters.claude_code_posttooluse",
            ),
        ),
    ),
    "gemini": AgentProfile(
        name="gemini",
        settings_path=Path(os.path.expanduser("~/.gemini/settings.json")),
        description="Gemini CLI (~/.gemini/settings.json)",
        hooks=(
            HookEntry(
                event_key="BeforeTool",
                matcher="run_shell|write_file|replace|edit",
                command="python3 -m ralf.adapters.gemini_cli",
            ),
        ),
    ),
    "codex": AgentProfile(
        name="codex",
        settings_path=Path(os.path.expanduser("~/.codex/settings.json")),
        description="Codex CLI (~/.codex/settings.json)",
        hooks=(
            HookEntry(
                event_key="PreToolUse",
                matcher="shell|write|patch",
                command="python3 -m ralf.adapters.codex_cli",
            ),
        ),
    ),
}


def get_profile(agent: str) -> AgentProfile:
    profile = _AGENTS.get(agent.lower())
    if profile is None:
        raise ValueError(
            f"unknown agent {agent!r}; supported: {sorted(_AGENTS)}"
        )
    return profile


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{ts}")
    backup.write_bytes(path.read_bytes())
    return backup


def _confirm(prompt: str) -> bool:
    if os.environ.get("RALF_AUTO_YES") == "1":
        return True
    try:
        reply = input(prompt).strip().lower()
    except EOFError:
        return False
    return reply in ("y", "yes")


def _entry_present(settings: dict, hook: HookEntry) -> bool:
    """True if a single HookEntry is already wired in."""
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get(hook.event_key) or []
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("matcher") != hook.matcher:
            continue
        for h in entry.get("hooks") or []:
            if isinstance(h, dict) and h.get("command") == hook.command:
                return True
    return False


def _hook_present(settings: dict, profile: AgentProfile) -> bool:
    """True if ALL of ``profile``'s hooks are wired in."""
    return all(_entry_present(settings, h) for h in profile.hooks)


def _install_entry(settings: dict, hook: HookEntry) -> dict:
    settings = dict(settings)
    hooks_root = dict(settings.get("hooks", {}) or {})
    entries = list(hooks_root.get(hook.event_key) or [])
    entries.append({
        "matcher": hook.matcher,
        "hooks": [{"type": "command", "command": hook.command}],
    })
    hooks_root[hook.event_key] = entries
    settings["hooks"] = hooks_root
    return settings


def _install_into(settings: dict, profile: AgentProfile) -> dict:
    """Install ALL of ``profile``'s hooks. Idempotent."""
    for hook in profile.hooks:
        if not _entry_present(settings, hook):
            settings = _install_entry(settings, hook)
    return settings


def _remove_entry(settings: dict, hook: HookEntry) -> tuple[dict, int]:
    settings = dict(settings)
    hooks_root = dict(settings.get("hooks", {}) or {})
    entries = hooks_root.get(hook.event_key) or []
    new_entries: list = []
    removed = 0
    for entry in entries:
        if not isinstance(entry, dict):
            new_entries.append(entry)
            continue
        kept = [
            h for h in entry.get("hooks", [])
            if not (isinstance(h, dict) and h.get("command") == hook.command)
        ]
        if not kept:
            removed += 1
            continue
        if len(kept) != len(entry.get("hooks", [])):
            removed += 1
        new_entry = dict(entry)
        new_entry["hooks"] = kept
        new_entries.append(new_entry)

    if new_entries:
        hooks_root[hook.event_key] = new_entries
    else:
        hooks_root.pop(hook.event_key, None)

    if hooks_root:
        settings["hooks"] = hooks_root
    else:
        settings.pop("hooks", None)
    return settings, removed


def _remove_from(settings: dict, profile: AgentProfile) -> tuple[dict, int]:
    total = 0
    for hook in profile.hooks:
        settings, n = _remove_entry(settings, hook)
        total += n
    return settings, total


def install_for_agent(
    agent: str,
    *,
    settings_path: Path | None = None,
    yes: bool = False,
) -> int:
    profile = get_profile(agent)
    target = settings_path or profile.settings_path

    print(f"ralf-free install-agent: {profile.description}")
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        try:
            settings = json.loads(target.read_text() or "{}")
        except json.JSONDecodeError as exc:
            print(f"error: {target} is not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(settings, dict):
            print(f"error: {target} is not a JSON object", file=sys.stderr)
            return 2
    else:
        settings = {}

    already = [h for h in profile.hooks if _entry_present(settings, h)]
    to_install = [h for h in profile.hooks if not _entry_present(settings, h)]

    for hook in already:
        print(f"  [skip] {hook.event_key}/{hook.matcher} already wired")

    if not to_install:
        print(f"  all hooks already present in {target} — no change needed")
        return 0

    backup = _backup(target)
    if backup:
        print(f"  backup: {backup}")

    for hook in to_install:
        print(f"  [add]  {hook.event_key}/{hook.matcher} → {hook.command}")

    if not (yes or _confirm("Apply these edits? [y/N] ")):
        print("aborted; no changes written")
        return 1

    new_settings = _install_into(settings, profile)
    target.write_text(json.dumps(new_settings, indent=2) + "\n")
    print(f"  wrote: {target}")
    return 0


def uninstall_for_agent(
    agent: str,
    *,
    settings_path: Path | None = None,
) -> int:
    profile = get_profile(agent)
    target = settings_path or profile.settings_path
    if not target.exists():
        print(f"  no {target} — nothing to remove")
        return 0
    try:
        settings = json.loads(target.read_text() or "{}")
    except json.JSONDecodeError as exc:
        print(f"error: {target} is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(settings, dict):
        return 0
    new_settings, removed = _remove_from(settings, profile)
    if removed == 0:
        print(f"  no hooks present in {target}")
        return 0
    target.write_text(json.dumps(new_settings, indent=2) + "\n")
    print(f"  removed {removed} entry/entries from {target}")
    return 0
