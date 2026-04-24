"""Platform-agnostic modules: rules, sensitive paths, verdict, audit, hook, CLI."""

from ralf.shared.rules import (
    RuleEngine,
    RuleHit,
    CompiledRule,
    DEFAULT_YAML_PATH,
    DEFAULT_CACHE_FILE,
    DEFAULT_CACHE_DIR,
)
from ralf.detection.sensitive_paths import has_sensitive, get_matches
from ralf.shared.platform_detect import (
    get_platform_name,
    UnsupportedPlatformError,
)

__all__ = [
    "RuleEngine",
    "RuleHit",
    "CompiledRule",
    "DEFAULT_YAML_PATH",
    "DEFAULT_CACHE_FILE",
    "DEFAULT_CACHE_DIR",
    "has_sensitive",
    "get_matches",
    "get_platform_name",
    "UnsupportedPlatformError",
]
