"""Supply chain protection — CVE advisory lookup, typosquatting, downgrade detection.

Three layers of package install protection:

1. **CVE advisory lookup** — queries local SQLite advisory DB (25K+ advisories
   from GitHub Advisory Database) for known-vulnerable packages + versions.
2. **Typosquatting detection** — Levenshtein distance against top packages per
   ecosystem. Catches ``reqeusts``, ``colorsama``, etc.
3. **Downgrade / dangerous flag detection** — ``--force-reinstall``,
   ``--no-deps``, ``--ignore-requires-python``, version pinning to old versions.

Based on advisory.py and package_scorer.py, with additions for typosquatting
and downgrade detection. Self-contained.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Advisory DB paths ─────────────────────────────────────────────────

_DB_SEARCH_PATHS = [
    # Preferred: OSV-federated DB produced by ``ralf-free sync cve``.
    # Our schema, 5-year rolling window, ~100K+ advisories post-dedup.
    Path(os.environ.get("RALF_CONFIG_DIR", "")) / "advisories_osv.db",
    Path.home() / ".config" / "ralf" / "advisories_osv.db",
    # Fallbacks: GHSA snapshot DBs from other tools. Schema-compatible
    # enough for the supply-chain lookup to work; smaller coverage.
    Path(os.environ.get("RALF_CONFIG_DIR", "")) / "advisories.db",
    Path.home() / ".config" / "ralf" / "advisories.db",
]

# Ecosystem normalization: binary → canonical ecosystem
_ECOSYSTEM_MAP = {
    "pip": "pip", "pip3": "pip",
    "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "cargo": "cargo",
    "gem": "rubygems",
    "go": "go",
    "composer": "composer",
    "nuget": "nuget",
}

# DB ecosystem aliases (advisory DBs use varying names)
_ECOSYSTEM_ALIASES = {
    "pip": ("pip", "PyPI", "pypi"),
    "npm": ("npm",),
    "cargo": ("cargo", "crates.io"),
    "rubygems": ("rubygems", "RubyGems"),
    "go": ("go", "Go"),
    "composer": ("composer", "Packagist"),
    "nuget": ("nuget", "NuGet"),
}

# CVE severity → score contribution (additive to rule engine score)
_SEVERITY_SCORES = {
    "CRITICAL": 12,
    "HIGH": 10,
    "MODERATE": 7,
    "MEDIUM": 7,
    "LOW": 3,
}

# Install verbs recognized across package managers
_INSTALL_VERBS = frozenset({"install", "add", "i"})

# Dangerous flags that weaken install safety
_DANGEROUS_FLAGS = {
    "pip": {
        "--force-reinstall": ("high", 8, "Forces reinstall, may downgrade patched packages"),
        "--no-deps": ("medium", 5, "Skips dependency resolution safety checks"),
        "--ignore-requires-python": ("medium", 3, "Bypasses Python version guard"),
        "--break-system-packages": ("high", 6, "Bypasses PEP 668 externally-managed environment protection"),
        "--pre": ("low", 2, "Allows pre-release versions which may be untested"),
    },
    "pip3": None,  # same as pip — resolved at runtime
    "npm": {
        "--force": ("medium", 5, "Forces install despite conflicts"),
        "--legacy-peer-deps": ("low", 2, "Bypasses peer dependency checks"),
        "--ignore-scripts": ("low", 0, "Actually safer — skips postinstall scripts"),
    },
    "cargo": {
        "--force": ("medium", 5, "Forces reinstall"),
    },
    "gem": {
        "--force": ("medium", 5, "Forces reinstall"),
        "--no-ri": ("low", 0, "Skips docs — benign"),
    },
}
# pip3 shares pip's flags
_DANGEROUS_FLAGS["pip3"] = _DANGEROUS_FLAGS["pip"]

# ── Version parsing (lightweight — no packaging dependency) ────────────


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints."""
    parts = []
    for p in re.split(r'[.\-_]', v.strip()):
        m = re.match(r'(\d+)', p)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _version_in_range(version: str, vulnerable: str, patched: str) -> bool:
    """Check if a version falls in the vulnerable range."""
    if not version:
        return False
    ver = _parse_version(version)

    # Parse vulnerable lower bound
    vuln_lower = (0,)
    if vulnerable:
        m = re.search(r'[\d][\d.]*', vulnerable)
        if m:
            vuln_lower = _parse_version(m.group())

    if ver < vuln_lower:
        return False

    # If patched, version must be < patched
    if patched and patched.strip():
        patched_ver = _parse_version(patched)
        if ver >= patched_ver:
            return False  # fixed in this version

    return True


# ── Command parsing ────────────────────────────────────────────────────

# Regex for version-pinned installs
_VERSION_PIN_RE = re.compile(
    r'([a-zA-Z0-9_-]+)\s*(?:==|@)\s*([0-9][0-9a-zA-Z._-]*)'
)


@dataclass
class ParsedInstall:
    """Parsed package install command."""
    binary: str
    ecosystem: str
    packages: list[tuple[str, str]]  # [(name, version), ...] — version="" if unpinned
    flags: list[str]                 # raw flags present
    raw_command: str


def parse_install_command(command: str) -> ParsedInstall | None:
    """Extract package names, versions, and flags from an install command.

    Returns None if the command isn't a package install.
    """
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    if len(tokens) < 2:
        return None

    binary = os.path.basename(tokens[0])
    # Handle `sudo pip install` and `python -m pip install`
    if binary in ("sudo", "env"):
        tokens = tokens[1:]
        if not tokens:
            return None
        binary = os.path.basename(tokens[0])
    if binary in ("python", "python3") and len(tokens) >= 3 and tokens[1] == "-m":
        binary = tokens[2]
        tokens = tokens[2:]

    ecosystem = _ECOSYSTEM_MAP.get(binary)
    if not ecosystem:
        return None

    # Find install verb
    found_install = False
    packages: list[tuple[str, str]] = []
    flags: list[str] = []
    skip_next = False

    for i, tok in enumerate(tokens[1:], 1):
        if skip_next:
            skip_next = False
            continue
        if not found_install:
            if tok.lower() in _INSTALL_VERBS:
                found_install = True
            continue
        # Collect flags
        if tok.startswith("-"):
            flags.append(tok)
            # Skip value of flags that take an argument
            if tok in ("--index-url", "--extra-index-url", "-i", "--registry",
                       "--source", "--target", "-t", "--prefix",
                       "--root", "--constraint", "-c", "-r"):
                skip_next = True
            continue
        # Parse package name + optional version
        # Handle ==, @, >=, <=, ~=, != version specifiers
        pkg = tok
        version = ""
        for sep in ("==", "@", ">=", "<=", "~=", "!="):
            if sep in tok:
                parts = tok.split(sep, 1)
                pkg = parts[0]
                version = parts[1] if len(parts) > 1 else ""
                break
        if pkg and not pkg.startswith("-") and not pkg.startswith("/"):
            packages.append((pkg, version))

    if not found_install:
        return None

    return ParsedInstall(
        binary=binary,
        ecosystem=ecosystem,
        packages=packages,
        flags=flags,
        raw_command=command,
    )


# ── Advisory DB ────────────────────────────────────────────────────────


@dataclass
class AdvisoryHit:
    """A known vulnerability matching a package."""
    cve_id: str
    package: str
    ecosystem: str
    severity: str
    summary: str
    vulnerable_versions: str
    patched_versions: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id, "package": self.package,
            "ecosystem": self.ecosystem, "severity": self.severity,
            "summary": self.summary,
            "vulnerable_versions": self.vulnerable_versions,
            "patched_versions": self.patched_versions,
        }


@dataclass
class SupplyChainResult:
    """Complete supply chain analysis result for an install command."""
    packages: list[tuple[str, str]] = field(default_factory=list)
    ecosystem: str = ""
    advisory_hits: list[AdvisoryHit] = field(default_factory=list)
    advisory_score: int = 0
    typosquat_warnings: list[str] = field(default_factory=list)
    typosquat_score: int = 0
    dangerous_flags: list[str] = field(default_factory=list)
    flag_score: int = 0
    notes: list[str] = field(default_factory=list)
    db_available: bool = False

    @property
    def total_score(self) -> int:
        return self.advisory_score + self.typosquat_score + self.flag_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "packages": self.packages,
            "ecosystem": self.ecosystem,
            "total_score": self.total_score,
            "advisory_score": self.advisory_score,
            "advisory_hits": [h.to_dict() for h in self.advisory_hits],
            "typosquat_score": self.typosquat_score,
            "typosquat_warnings": self.typosquat_warnings,
            "flag_score": self.flag_score,
            "dangerous_flags": self.dangerous_flags,
            "notes": self.notes,
            "db_available": self.db_available,
        }


class _AdvisoryDB:
    """Read-only SQLite advisory database (lazy singleton)."""

    def __init__(self) -> None:
        self._conn: sqlite3.Connection | None = None
        self._path: Path | None = None
        self._tried = False

    def _ensure(self) -> None:
        if self._tried:
            return
        self._tried = True
        for p in _DB_SEARCH_PATHS:
            if not str(p) and p.name == "advisories.db":
                continue  # skip empty RALF_CONFIG_DIR
            try:
                if p.is_file():
                    self._path = p
                    self._conn = sqlite3.connect(
                        str(p), check_same_thread=False,
                    )
                    self._conn.row_factory = sqlite3.Row
                    # Verify table exists
                    cur = self._conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name='advisories'"
                    )
                    if cur.fetchone() is None:
                        self._conn.close()
                        self._conn = None
                        continue
                    log.debug("Advisory DB loaded: %s", p)
                    return
            except Exception as e:
                log.debug("Failed to open %s: %s", p, e)
        log.debug("No advisory DB found")

    @property
    def available(self) -> bool:
        self._ensure()
        return self._conn is not None

    def check_package(self, package: str, ecosystem: str, version: str = "") -> list[AdvisoryHit]:
        """Look up a package. Returns matching advisories sorted by severity."""
        self._ensure()
        if not self._conn:
            return []

        aliases = _ECOSYSTEM_ALIASES.get(ecosystem, (ecosystem,))
        placeholders = ",".join("?" for _ in aliases)
        # Normalize package name (PyPI uses - and _ interchangeably)
        pkg_normalized = package.lower().replace("-", "_")
        pkg_hyphen = package.lower().replace("_", "-")

        try:
            rows = self._conn.execute(
                f"""SELECT cve_id, package_name, ecosystem, severity,
                           summary, vulnerable_versions, patched_versions
                    FROM advisories
                    WHERE (LOWER(REPLACE(package_name, '-', '_')) = ?
                           OR LOWER(REPLACE(package_name, '_', '-')) = ?)
                      AND ecosystem IN ({placeholders})
                    ORDER BY
                        CASE severity
                            WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                            WHEN 'MODERATE' THEN 2 WHEN 'MEDIUM' THEN 2
                            WHEN 'LOW' THEN 3 ELSE 4
                        END
                    LIMIT 20""",
                (pkg_normalized, pkg_hyphen, *aliases),
            ).fetchall()
        except Exception as e:
            log.debug("Advisory query failed: %s", e)
            return []

        hits: list[AdvisoryHit] = []
        for row in rows:
            # If version is specified, check if it falls in the vulnerable range
            if version:
                vuln = row["vulnerable_versions"] or ""
                patched = row["patched_versions"] or ""
                if not _version_in_range(version, vuln, patched):
                    continue
            hits.append(AdvisoryHit(
                cve_id=row["cve_id"] or "",
                package=row["package_name"],
                ecosystem=row["ecosystem"],
                severity=row["severity"] or "UNKNOWN",
                summary=(row["summary"] or "")[:150],
                vulnerable_versions=row["vulnerable_versions"] or "",
                patched_versions=row["patched_versions"] or "",
            ))

        return hits


# Module singleton
_advisory_db: _AdvisoryDB | None = None


def _get_db() -> _AdvisoryDB:
    global _advisory_db
    if _advisory_db is None:
        _advisory_db = _AdvisoryDB()
    return _advisory_db


# ── Typosquatting detection ────────────────────────────────────────────

# Top packages per ecosystem. Curated from download stats.
# Only need the top ~200 per ecosystem to catch common typosquats.
_TOP_PACKAGES: dict[str, frozenset[str]] = {
    "pip": frozenset({
        "requests", "boto3", "urllib3", "setuptools", "certifi", "typing-extensions",
        "idna", "charset-normalizer", "python-dateutil", "packaging", "botocore",
        "pyyaml", "numpy", "six", "s3transfer", "pip", "jmespath", "cryptography",
        "cffi", "pycparser", "colorama", "wheel", "attrs", "platformdirs",
        "pyasn1", "tomli", "rsa", "click", "jinja2", "markupsafe", "pyparsing",
        "importlib-metadata", "zipp", "pytz", "filelock", "decorator", "jsonschema",
        "pillow", "pandas", "scipy", "flask", "django", "sqlalchemy", "psycopg2",
        "redis", "celery", "gunicorn", "uvicorn", "fastapi", "pydantic",
        "httpx", "aiohttp", "grpcio", "protobuf", "google-auth", "google-api-core",
        "matplotlib", "scikit-learn", "tensorflow", "torch", "transformers",
        "lxml", "beautifulsoup4", "scrapy", "selenium", "pytest", "tox",
        "black", "flake8", "mypy", "ruff", "isort", "coverage", "sphinx",
        "paramiko", "fabric", "ansible", "docker", "kubernetes", "boto",
        "pygments", "rich", "textual", "typer", "httptools", "websockets",
        "aiofiles", "ujson", "orjson", "msgpack", "wrapt", "cachetools",
        "pyopenssl", "bcrypt", "passlib", "itsdangerous", "werkzeug",
        "marshmallow", "wtforms", "alembic", "sqlmodel", "motor", "pymongo",
        "psutil", "watchdog", "apscheduler", "arrow", "pendulum", "dateparser",
        "openpyxl", "xlrd", "tabulate", "colorama", "tqdm", "alive-progress",
        "python-dotenv", "python-decouple", "environs", "dynaconf",
        "sentry-sdk", "datadog", "newrelic", "prometheus-client", "opentelemetry-api",
        "anthropic", "openai", "google-generativeai", "langchain", "llama-index",
        "tiktoken", "tokenizers", "sentence-transformers", "chromadb", "pinecone",
    }),
    "npm": frozenset({
        "lodash", "chalk", "react", "express", "axios", "commander", "debug",
        "minimist", "semver", "glob", "uuid", "moment", "yargs", "inquirer",
        "typescript", "webpack", "jest", "eslint", "prettier", "babel",
        "underscore", "async", "bluebird", "request", "mkdirp", "rimraf",
        "fs-extra", "cross-env", "dotenv", "cors", "body-parser", "mongoose",
        "socket.io", "passport", "jsonwebtoken", "bcrypt", "nodemailer",
        "winston", "morgan", "helmet", "compression", "multer", "ejs",
        "handlebars", "pug", "next", "nuxt", "vue", "angular", "svelte",
        "tailwindcss", "postcss", "autoprefixer", "sass", "less", "styled-components",
        "emotion", "redux", "mobx", "zustand", "swr", "react-query",
        "prisma", "sequelize", "typeorm", "knex", "pg", "mysql2", "redis",
        "graphql", "apollo-server", "fastify", "koa", "hapi", "nest",
        "electron", "puppeteer", "playwright", "cypress", "mocha", "chai",
        "vitest", "esbuild", "vite", "rollup", "parcel", "turbo",
        "zod", "yup", "joi", "ajv", "class-validator",
        "dayjs", "date-fns", "luxon", "nanoid", "cuid",
    }),
    "cargo": frozenset({
        "serde", "tokio", "rand", "clap", "log", "regex", "chrono", "anyhow",
        "thiserror", "reqwest", "hyper", "actix-web", "axum", "warp",
        "serde_json", "toml", "config", "env_logger", "tracing", "rayon",
        "crossbeam", "parking_lot", "once_cell", "lazy_static", "itertools",
        "futures", "async-trait", "tower", "tonic", "prost", "diesel",
        "sqlx", "rusqlite", "redis", "uuid", "url", "bytes", "base64",
        "sha2", "hmac", "aes", "rsa", "ring", "rustls",
    }),
    "rubygems": frozenset({
        "rails", "rake", "bundler", "rspec", "sinatra", "puma", "unicorn",
        "sidekiq", "devise", "nokogiri", "json", "pg", "mysql2", "redis",
        "activesupport", "actionpack", "activerecord", "sprockets",
        "rubocop", "minitest", "capybara", "factory_bot", "faker",
    }),
}


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def check_typosquat(package: str, ecosystem: str) -> tuple[str, int] | None:
    """Check if a package name is a likely typosquat of a popular package.

    Returns (real_package_name, distance) or None if no match.
    Only flags distance 1-2 edits for packages >= 4 chars.
    """
    top = _TOP_PACKAGES.get(ecosystem)
    if not top:
        return None

    pkg_lower = package.lower().replace("_", "-")
    # Exact match = not a typosquat
    if pkg_lower in {p.lower().replace("_", "-") for p in top}:
        return None

    # Skip short names (high false positive rate)
    if len(pkg_lower) < 4:
        return None

    best_match: str | None = None
    best_dist = 999
    max_dist = 2 if len(pkg_lower) >= 6 else 1

    for real_pkg in top:
        real_lower = real_pkg.lower().replace("_", "-")
        # Quick length filter
        if abs(len(real_lower) - len(pkg_lower)) > max_dist:
            continue
        dist = _levenshtein(pkg_lower, real_lower)
        if 0 < dist <= max_dist and dist < best_dist:
            best_dist = dist
            best_match = real_pkg

    if best_match is not None:
        return (best_match, best_dist)
    return None


# ── Main scoring function ──────────────────────────────────────────────


def score_install_command(command: str) -> SupplyChainResult | None:
    """Full supply chain analysis of a package install command.

    Returns None if the command isn't a package install.
    Returns SupplyChainResult with score breakdown otherwise.

    This is designed to be called from score_command() in the verdict engine.
    """
    parsed = parse_install_command(command)
    if parsed is None:
        return None

    result = SupplyChainResult(
        packages=parsed.packages,
        ecosystem=parsed.ecosystem,
    )

    db = _get_db()
    result.db_available = db.available

    # ── Layer 1: CVE advisory lookup ──────────────────────────────
    for pkg_name, version in parsed.packages:
        hits = db.check_package(pkg_name, parsed.ecosystem, version)
        if hits:
            result.advisory_hits.extend(hits)
            top_severity = hits[0].severity.upper()

            if version:
                # Pinned to a specific version that matched vulnerable range → full score
                score = _SEVERITY_SCORES.get(top_severity, 3)
            else:
                # Unpinned install — pip/npm will install latest (probably patched).
                # Informational only: score 2 (not enough to block by itself).
                score = 2

            if score > result.advisory_score:
                result.advisory_score = score

            cve_ids = [h.cve_id for h in hits[:3] if h.cve_id]
            ver_str = f"=={version}" if version else " (latest — likely patched)"
            result.notes.append(
                f"CVE: {pkg_name}{ver_str} has {len(hits)} known advisory/ies "
                f"(max: {top_severity})"
                + (f" — {', '.join(cve_ids)}" if cve_ids else "")
            )
            if hits[0].patched_versions:
                result.notes.append(
                    f"  Patched in: {hits[0].patched_versions}"
                )

    # ── Layer 2: Typosquatting detection ──────────────────────────
    for pkg_name, _version in parsed.packages:
        typo = check_typosquat(pkg_name, parsed.ecosystem)
        if typo:
            real_name, dist = typo
            result.typosquat_warnings.append(
                f"'{pkg_name}' looks like a typosquat of '{real_name}' "
                f"(edit distance: {dist})"
            )
            # Typosquat score: 10 for distance 1, 7 for distance 2
            typo_score = 10 if dist == 1 else 7
            if typo_score > result.typosquat_score:
                result.typosquat_score = typo_score
            result.notes.append(
                f"TYPOSQUAT: '{pkg_name}' is {dist} edit(s) from "
                f"popular package '{real_name}'"
            )

    # ── Layer 3: Dangerous flags / downgrade ──────────────────────
    flag_table = _DANGEROUS_FLAGS.get(parsed.binary, {})
    if flag_table:
        for flag in parsed.flags:
            if flag in flag_table:
                severity, score, reason = flag_table[flag]
                result.dangerous_flags.append(f"{flag}: {reason}")
                if score > result.flag_score:
                    result.flag_score = score
                result.notes.append(f"FLAG: {flag} — {reason}")

    return result
