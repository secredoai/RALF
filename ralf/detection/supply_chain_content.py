"""Supply chain detection for file-write content.

Complements :mod:`ralf.detection.supply_chain` (which handles Bash
commands) by inspecting the content of files being written for
pinned-vulnerable dependencies and embedded install commands.

Two layers, highest-signal first:

1. **Manifest parser** (by filename) — requirements.txt, Pipfile,
   pyproject.toml, package.json. Extracts ``(package, version)``
   pairs via format-aware parsing and queries the advisory DB
   directly via :meth:`_AdvisoryDB.check_package`.

2. **Embedded command scan** (by content) — line-walks the file
   looking for ``pip install X==Y`` / ``npm install X@Y`` style
   invocations and hands each match to
   :func:`ralf.detection.supply_chain.score_install_command`.
   Applied to Dockerfiles, shell scripts, CI YAML, and any
   unrecognized text file.

Bounded: 128 KiB content cap, max 256 matches per scan, manifest
parsers run at most once per file. Falls back to the embedded
scan if manifest parsing raises.

Returns a :class:`SupplyChainResult` reusing the existing dataclass
from :mod:`ralf.detection.supply_chain`, so the verdict engine can
treat Bash-path and Write-path hits uniformly.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Iterable

try:
    import tomllib  # stdlib, Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # PyPI backport for Python <3.11
    except ImportError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

from ralf.detection.supply_chain import (
    AdvisoryHit,
    SupplyChainResult,
    _SEVERITY_SCORES,
    _get_db,
    score_install_command,
)

log = logging.getLogger(__name__)

_MAX_CONTENT_LEN = 128 * 1024  # 128 KiB
_MAX_EMBEDDED_MATCHES = 256

# ── Filename classification ─────────────────────────────────────────────

# Matches ``requirements.txt``, ``requirements-dev.txt``, ``dev-requirements.txt``,
# ``requirements_prod.txt``, ``test-requirements.txt``, etc. Both prefix and
# suffix variants are common in the wild.
_REQUIREMENTS_PATTERNS = (
    re.compile(r"^(?:[\w-]+[-_.])?requirements(?:[-_.][\w-]+)?\.txt$", re.IGNORECASE),
    re.compile(r"^(?:[\w-]+[-_.])?constraints(?:[-_.][\w-]+)?\.txt$", re.IGNORECASE),
)
_DOCKERFILE_PATTERNS = (
    re.compile(r"^Dockerfile(?:\.[\w.-]+)?$"),
    re.compile(r"^Containerfile(?:\.[\w.-]+)?$"),
    re.compile(r".*\.dockerfile$", re.IGNORECASE),
)
_SHELL_SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
_CI_YAML_HINTS = (".yml", ".yaml")


def _is_requirements(basename: str) -> bool:
    return any(p.match(basename) for p in _REQUIREMENTS_PATTERNS)


def _is_dockerfile(basename: str) -> bool:
    return any(p.match(basename) for p in _DOCKERFILE_PATTERNS)


def _is_shell_script(basename: str) -> bool:
    lower = basename.lower()
    return any(lower.endswith(s) for s in _SHELL_SCRIPT_SUFFIXES)


def _is_package_json(basename: str) -> bool:
    return basename == "package.json"


def _is_pyproject(basename: str) -> bool:
    return basename == "pyproject.toml"


def _is_pipfile(basename: str) -> bool:
    return basename == "Pipfile"


def _is_ci_yaml(basename: str, path: str | None) -> bool:
    lower = basename.lower()
    if not any(lower.endswith(s) for s in _CI_YAML_HINTS):
        return False
    if basename in ("ci.yml", "ci.yaml") or basename.endswith((".gitlab-ci.yml", ".gitlab-ci.yaml")):
        return True
    if path and (".github/workflows" in path.replace("\\", "/") or ".circleci" in path):
        return True
    # Plain YAML with install commands falls through to embedded scan anyway.
    return False


# ── Manifest parsers ────────────────────────────────────────────────────

# One line of requirements.txt: `pkg==1.2.3`, `pkg~=1.2`, `pkg[extras]==1.2.3`,
# optionally with `; python_version>='3.8'` environment markers and comments.
_REQ_LINE_RE = re.compile(
    r"""^\s*
    (?P<pkg>[A-Za-z0-9_][A-Za-z0-9_.\-]*)
    (?:\[[^\]]*\])?           # optional extras
    \s*
    (?P<op>==|===)            # only exact pins are version-matchable
    \s*
    (?P<ver>[0-9][\w.\-+]*)
    """,
    re.VERBOSE,
)


def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Extract exact-pinned packages from a requirements.txt / constraints file.

    Only ``==`` / ``===`` pins are returned — range specifiers (``~=``,
    ``>=``) don't identify a specific vulnerable version, so matching
    them against the CVE DB would produce false positives. Lines with
    only loose specifiers are skipped (same policy as
    ``score_install_command`` unpinned handling).
    """
    out: list[tuple[str, str]] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()  # strip comments
        if not line or line.startswith(("-", "--", "./")):
            continue  # flags, --index-url, editable installs, etc.
        m = _REQ_LINE_RE.match(line)
        if m:
            out.append((m.group("pkg"), m.group("ver")))
    return out


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    """Extract exact-pinned deps from a package.json ``dependencies`` /
    ``devDependencies`` / ``peerDependencies`` / ``optionalDependencies``.

    Only pins that are a bare version (``"1.2.3"``) or ``"=1.2.3"`` are
    returned. Range specifiers (``^1.2.3``, ``~1.2.3``, ``>=1.2``) are
    skipped for the same reason as requirements.txt.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[tuple[str, str]] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for pkg, spec in section.items():
            if not isinstance(pkg, str) or not isinstance(spec, str):
                continue
            stripped = spec.strip()
            if stripped.startswith("="):
                stripped = stripped[1:].strip()
            if re.match(r"^\d[\w.\-+]*$", stripped):
                out.append((pkg, stripped))
    return out


def _parse_pyproject_toml(content: str) -> list[tuple[str, str]]:
    """Extract exact-pinned deps from a pyproject.toml.

    Handles PEP 621 ``[project].dependencies`` (list of PEP 508 strings)
    and Poetry's ``[tool.poetry.dependencies]`` (table of name → spec).
    """
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []

    out: list[tuple[str, str]] = []

    # PEP 621: [project] dependencies = ["flask==0.12.2", ...]
    project = data.get("project", {})
    if isinstance(project, dict):
        deps = project.get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:
                if isinstance(dep, str):
                    m = _REQ_LINE_RE.match(dep)
                    if m:
                        out.append((m.group("pkg"), m.group("ver")))

    # Poetry: [tool.poetry.dependencies]
    tool = data.get("tool", {})
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    if isinstance(poetry_deps, dict):
        for pkg, spec in poetry_deps.items():
            if pkg == "python":
                continue
            ver = ""
            if isinstance(spec, str):
                ver = spec.strip()
            elif isinstance(spec, dict):
                v = spec.get("version")
                if isinstance(v, str):
                    ver = v.strip()
            if ver.startswith("="):
                ver = ver[1:].strip()
            if re.match(r"^\d[\w.\-+]*$", ver):
                out.append((str(pkg), ver))

    return out


def _parse_pipfile(content: str) -> list[tuple[str, str]]:
    """Extract exact-pinned deps from a Pipfile (TOML)."""
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []

    out: list[tuple[str, str]] = []
    for section_name in ("packages", "dev-packages"):
        section = data.get(section_name, {})
        if not isinstance(section, dict):
            continue
        for pkg, spec in section.items():
            ver = ""
            if isinstance(spec, str):
                ver = spec.strip()
            elif isinstance(spec, dict):
                v = spec.get("version")
                if isinstance(v, str):
                    ver = v.strip()
            if ver.startswith(("==", "===")):
                ver = ver.lstrip("=").strip()
            elif ver.startswith("="):
                ver = ver[1:].strip()
            if re.match(r"^\d[\w.\-+]*$", ver):
                out.append((str(pkg), ver))
    return out


# ── Embedded command scanner ────────────────────────────────────────────

# Matches common install invocations anywhere in a line. The capture
# starts at the binary (optionally path-prefixed like
# ``/tmp/venv/bin/pip`` or ``./node_modules/.bin/npm``) and extends to
# end-of-line or the next shell operator. ``score_install_command``
# does the real tokenization on the captured slice.
_EMBEDDED_INSTALL_RE = re.compile(
    r"""
    (?:^|[\s;&|`$(])                              # boundary before binary/path
    (?P<cmd>
        (?:[\w./~+-]*/)?                          # optional absolute/relative path prefix
        (?:pip3?|npm|yarn|pnpm|cargo|gem|composer|go|apk|apt-get|apt|dnf|yum|brew)
        \s+(?:install|add|get|i)\b
        [^\r\n;&|`]*                              # rest of the command slice
    )
    """,
    re.VERBOSE,
)


def _scan_embedded_commands(content: str) -> Iterable[str]:
    """Yield install-command slices found embedded in arbitrary text.

    Each yielded string is a single-line slice starting at the binary
    and ending before the next shell separator or end-of-line. The
    slicer is intentionally loose — ``score_install_command`` re-parses
    the slice with its own tokenizer and will reject anything that
    isn't a valid install.
    """
    if len(content) > _MAX_CONTENT_LEN:
        return
    count = 0
    for m in _EMBEDDED_INSTALL_RE.finditer(content):
        if count >= _MAX_EMBEDDED_MATCHES:
            return
        yield m.group("cmd").strip()
        count += 1


# ── Manifest → advisory lookup ──────────────────────────────────────────


def _score_packages(
    packages: list[tuple[str, str]],
    ecosystem: str,
    source: str,
) -> SupplyChainResult:
    """Query the advisory DB for each (pkg, version) and build a result."""
    result = SupplyChainResult(packages=list(packages), ecosystem=ecosystem)
    db = _get_db()
    result.db_available = db.available

    for pkg_name, version in packages:
        hits = db.check_package(pkg_name, ecosystem, version)
        if not hits:
            continue
        result.advisory_hits.extend(hits)
        top_severity = hits[0].severity.upper()
        # Manifest entries are always pinned (we only parse exact pins),
        # so use the full severity score — no "unpinned → 2" downgrade.
        sev_score = _SEVERITY_SCORES.get(top_severity, 3)
        if sev_score > result.advisory_score:
            result.advisory_score = sev_score
        cve_ids = [h.cve_id for h in hits[:3] if h.cve_id]
        result.notes.append(
            f"{source}: {pkg_name}=={version} has {len(hits)} known "
            f"advisory/ies (max: {top_severity})"
            + (f" — {', '.join(cve_ids)}" if cve_ids else "")
        )
        if hits[0].patched_versions:
            result.notes.append(f"  Patched in: {hits[0].patched_versions}")

    return result


# ── Public entry point ──────────────────────────────────────────────────


def score_file_content_supply_chain(
    content: str,
    file_path: str | None = None,
) -> SupplyChainResult | None:
    """Scan file-write content for supply chain threats.

    Returns ``None`` when the file is neither a recognized manifest
    nor contains any embedded install command — keeps the hot path
    cheap for the common case (source files being edited).

    Returns a :class:`SupplyChainResult` with ``total_score > 0`` when
    at least one advisory, typosquat, or dangerous flag was detected.
    """
    if not content or len(content) > _MAX_CONTENT_LEN:
        return None

    basename = os.path.basename(file_path) if file_path else ""

    # ── Layer 1: manifest parsers ─────────────────────────────────
    packages: list[tuple[str, str]] = []
    ecosystem = ""
    source = ""
    try:
        if _is_requirements(basename):
            packages = _parse_requirements_txt(content)
            ecosystem = "pip"
            source = "requirements"
        elif _is_package_json(basename):
            packages = _parse_package_json(content)
            ecosystem = "npm"
            source = "package.json"
        elif _is_pyproject(basename):
            packages = _parse_pyproject_toml(content)
            ecosystem = "pip"
            source = "pyproject"
        elif _is_pipfile(basename):
            packages = _parse_pipfile(content)
            ecosystem = "pip"
            source = "Pipfile"
    except Exception as e:
        log.debug("manifest parser failed for %s: %s", basename, e)
        packages = []

    manifest_result: SupplyChainResult | None = None
    if packages:
        manifest_result = _score_packages(packages, ecosystem, source)

    # ── Layer 2: embedded command scan ────────────────────────────
    # Always run on Dockerfiles, shell scripts, CI YAML, and any file
    # that didn't match a manifest. This catches RUN pip install in
    # Dockerfiles, install steps in workflow YAML, and ad-hoc scripts.
    run_embedded = (
        manifest_result is None
        or _is_dockerfile(basename)
        or _is_shell_script(basename)
        or _is_ci_yaml(basename, file_path)
    )

    embedded_result: SupplyChainResult | None = None
    if run_embedded:
        best_score = 0
        best_notes: list[str] = []
        best_packages: list[tuple[str, str]] = []
        best_ecosystem = ""
        for slice_ in _scan_embedded_commands(content):
            sc = score_install_command(slice_)
            if sc is None:
                continue
            if sc.total_score > best_score:
                best_score = sc.total_score
                best_notes = list(sc.notes)
                best_packages = list(sc.packages)
                best_ecosystem = sc.ecosystem
        if best_score > 0:
            embedded_result = SupplyChainResult(
                packages=best_packages,
                ecosystem=best_ecosystem,
                advisory_score=best_score,
                notes=[f"embedded: {n}" for n in best_notes],
            )

    # ── Merge: worst-score-wins, union the notes ──────────────────
    if manifest_result is None and embedded_result is None:
        return None
    if manifest_result is None:
        return embedded_result
    if embedded_result is None:
        return manifest_result

    # Both present — build a merged result with the higher score.
    merged = SupplyChainResult(
        packages=manifest_result.packages + embedded_result.packages,
        ecosystem=manifest_result.ecosystem or embedded_result.ecosystem,
        advisory_hits=manifest_result.advisory_hits,
        advisory_score=max(manifest_result.advisory_score, embedded_result.advisory_score),
        notes=manifest_result.notes + embedded_result.notes,
        db_available=manifest_result.db_available,
    )
    return merged
