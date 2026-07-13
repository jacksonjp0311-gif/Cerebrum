"""Phoenix adapter: explicit allowlist boundary for Cortex integration.

This module enforces the integration boundary between Phoenix private surfaces
and Cortex repository memory. It never reads, returns, or passes through any
file matching the deny list. The deny list is hardcoded and cannot be weakened
by configuration — only strengthened.

ALLOW (by extension + location):
    - source code (.py, .rs, .ts, .js, .go, .kt, .java, .c, .h, .cpp)
    - schemas (.json schema files, .proto, .graphql)
    - public docs (docs/**, README*, CHANGELOG*, LICENSE*)
    - selected operational logs (explicitly opted-in only)

DENY (hardcoded, non-overridable):
    - SOUL.md, JOURNAL.md, MEMORY.md
    - private memory directories (memory/**, phone_sessions/**, sessions/**)
    - pre-compression notes
    - API credentials, secrets, tokens (.env*, *key*, *secret*, *credential*)
    - raw conversation archives (*conversation*, *chat*, *transcript*)
    - personal relationship data (*relationship*, *personal*)
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator


# ── Hardcoded deny list ───────────────────────────────────────────────
# Two tiers:
#   DENY_BASENAMES — matched against the file's basename (e.g. "SOUL.md")
#   DENY_PATH_GLOBS — matched against the full relative path (e.g. "memory/**")
#
# The deny list is hardcoded and cannot be weakened by configuration.

# Files that are ALWAYS denied regardless of where they appear
DENY_BASENAMES: frozenset[str] = frozenset({
    "SOUL.md",
    "JOURNAL.md",
    "MEMORY.md",
    "IDENTITY.md",
    "AGENTS.md",
    "ACTIVE_TASKS.md",
})

# Substrings that mark a file as sensitive if they appear in the basename
DENY_BASENAME_SUBSTRINGS: frozenset[str] = frozenset({
    ".env",
    "credential",
    "api_key",
    "secret",
    "token",
    "password",
    "conversation",
    "chat",
    "transcript",
    "session_log",
    "relationship",
    "personal",
    "private_journal",
    "PRE_COMPRESSION",
})

# Path patterns — matched against the full relative path using fnmatch
# These catch files inside sensitive directories
DENY_PATH_GLOBS: frozenset[str] = frozenset({
    "memory/*",
    "memory/**",
    "*/memory/*",
    "*/memory/**",
    "**/memory/*",
    "**/memory/**",
    "phone_sessions/*",
    "phone_sessions/**",
    "*/phone_sessions/*",
    "*/phone_sessions/**",
    "**/phone_sessions/*",
    "**/phone_sessions/**",
    "sessions/*",
    "sessions/**",
    "*/sessions/*",
    "*/sessions/**",
    "**/sessions/*",
    "**/sessions/**",
    "private/*",
    "private/**",
    "*/private/*",
    "*/private/**",
    "**/private/*",
    "**/private/**",
    ".ssh/*",
    ".ssh/**",
    "*/.ssh/*",
    "*/.ssh/**",
    "**/.ssh/*",
    "**/.ssh/**",
    "**/PRE_COMPRESSION*",
})

# ── Allow list (by extension) ─────────────────────────────────────────
# A file must match an allow extension AND not match any deny pattern.

ALLOW_EXTENSIONS: frozenset[str] = frozenset({
    # Source code
    ".py", ".rs", ".ts", ".tsx", ".js", ".jsx",
    ".go", ".kt", ".kts", ".java", ".c", ".h", ".cpp", ".hpp", ".cc",
    ".rb", ".swift", ".scala", ".clj",
    # Schemas & config
    ".json", ".proto", ".graphql", ".yaml", ".yml", ".toml", ".ini",
    # Structured docs
    ".md", ".rst", ".txt",
})

# ── Public document paths ─────────────────────────────────────────────
# .md/.rst/.txt files are ONLY allowed if they live under these paths.
# This prevents journal or memory markdown from leaking through.

PUBLIC_DOC_PATHS: frozenset[str] = frozenset({
    "docs", "doc", "documentation",
    "examples",
    "benchmarks",
    "tests", "test",
    "scripts",
    "config",
})

# Extensions that bypass the public-doc-path restriction
# (source code and schemas are allowed anywhere they aren't denied)
STRUCTURAL_EXTENSIONS: frozenset[str] = ALLOW_EXTENSIONS - {".md", ".rst", ".txt"}

# Max file size to read (256 KB — prevents huge logs or binaries)
MAX_FILE_BYTES: int = 262_144


@dataclass(frozen=True)
class PhoenixPolicy:
    """Configuration for the Phoenix adapter boundary."""
    phoenix_root: Path
    allow_log_files: bool = False  # operational logs require explicit opt-in
    log_glob: str = "**/*.log"
    max_files: int = 200
    max_total_bytes: int = 2_097_152  # 2 MB total context packet


@dataclass(frozen=True)
class ClassifiedFile:
    path: Path
    relative_path: str
    reason: str  # why it was allowed or denied
    allowed: bool


def _match_any(path_str: str, patterns: frozenset[str]) -> bool:
    """Check if a path matches any glob pattern."""
    return any(fnmatch.fnmatch(path_str, pat) for pat in patterns)


def is_denied(relative_path: str) -> str | None:
    """Return the deny reason if a path is denied, else None."""
    normalized = relative_path.replace("\\", "/")
    basename = Path(normalized).name
    lower_base = basename.lower()
    lower_path = normalized.lower()

    # Tier 1: Exact basename match (SOUL.md, JOURNAL.md, etc.)
    if basename in DENY_BASENAMES:
        return f"denied basename: {basename}"

    # Tier 2: Substring in basename OR full path (credential, .env, conversation, etc.)
    for substr in DENY_BASENAME_SUBSTRINGS:
        if substr.lower() in lower_base or substr.lower() in lower_path:
            return f"denied substring: {substr}"

    # Tier 3: Path glob match (memory/**, phone_sessions/**, etc.)
    for pattern in DENY_PATH_GLOBS:
        if fnmatch.fnmatch(normalized, pattern):
            return f"matched deny path pattern: {pattern}"

    return None


def is_allowed(relative_path: str, policy: PhoenixPolicy) -> tuple[bool, str]:
    """Check if a file is allowed under the policy.
    
    Returns (allowed, reason).
    """
    normalized = relative_path.replace("\\", "/")
    suffix = Path(normalized).suffix.lower()

    # Step 1: Hard deny check — non-overridable
    deny_reason = is_denied(normalized)
    if deny_reason:
        return False, deny_reason

    # Step 2: Source code & schemas — allowed anywhere not denied
    if suffix in STRUCTURAL_EXTENSIONS:
        return True, f"allowed extension: {suffix}"

    # Step 3: Markdown/text docs — only under public doc paths
    if suffix in {".md", ".rst", ".txt"}:
        parts = Path(normalized).parts
        for public_dir in PUBLIC_DOC_PATHS:
            if public_dir in parts:
                return True, f"public doc path: {public_dir}"
        # README/CHANGELOG/LICENSE at any level
        basename = Path(normalized).name.upper()
        if basename.startswith(("README", "CHANGELOG", "LICENSE", "CONTRIBUTING")):
            return True, f"public root document: {basename}"
        return False, "markdown outside public doc paths"

    # Step 4: Log files — only if explicitly opted in
    if suffix == ".log" and policy.allow_log_files:
        if fnmatch.fnmatch(normalized, policy.log_glob) or fnmatch.fnmatch(normalized, Path(normalized).name):
            return True, "opt-in operational log"

    # Step 5: Everything else — denied by default
    return False, f"extension {suffix} not in allow list"


def classify(
    relative_path: str,
    policy: PhoenixPolicy,
) -> ClassifiedFile:
    """Classify a single file path."""
    denied = is_denied(relative_path)
    if denied:
        return ClassifiedFile(
            path=policy.phoenix_root / relative_path,
            relative_path=relative_path,
            reason=denied,
            allowed=False,
        )
    allowed, reason = is_allowed(relative_path, policy)
    return ClassifiedFile(
        path=policy.phoenix_root / relative_path,
        relative_path=relative_path,
        reason=reason,
        allowed=allowed,
    )


def walk_phoenix(policy: PhoenixPolicy) -> Generator[ClassifiedFile, None, None]:
    """Walk the Phoenix root and yield ClassifiedFile for every file found.
    
    Both allowed and denied files are yielded so callers can audit the boundary.
    """
    root = policy.phoenix_root
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip hidden directories (.git, .venv, __pycache__, etc.)
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "__pycache__"]
        for filename in filenames:
            full = Path(dirpath) / filename
            rel = str(full.relative_to(root))
            yield classify(rel, policy)


def collect_allowed(policy: PhoenixPolicy) -> list[ClassifiedFile]:
    """Return only allowed files, bounded by policy limits."""
    allowed: list[ClassifiedFile] = []
    total_bytes = 0
    for cf in walk_phoenix(policy):
        if not cf.allowed:
            continue
        try:
            size = cf.path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            continue
        if total_bytes + size > policy.max_total_bytes:
            break
        if len(allowed) >= policy.max_files:
            break
        total_bytes += size
        allowed.append(cf)
    return allowed


def build_context_packet(policy: PhoenixPolicy) -> dict:
    """Build a context packet of allowed files for Cortex ingestion.
    
    Returns a dict with:
        root: the Phoenix root path
        files: list of {path, content_preview} for allowed files
        denied_count: number of files blocked by the boundary
        denied_samples: up to 5 sample denied paths (without content)
    """
    allowed_files = collect_allowed(policy)
    denied: list[str] = []
    for cf in walk_phoenix(policy):
        if not cf.allowed:
            denied.append(cf.relative_path)

    packet = {
        "root": str(policy.phoenix_root),
        "files": [],
        "denied_count": len(denied),
        "denied_samples": denied[:5],
        "policy": {
            "allow_log_files": policy.allow_log_files,
            "max_files": policy.max_files,
            "max_total_bytes": policy.max_total_bytes,
        },
    }

    for cf in allowed_files:
        try:
            content = cf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        preview = content[:4096]
        if len(content) > 4096:
            preview += "\n... [truncated]"
        packet["files"].append({
            "path": cf.relative_path,
            "reason": cf.reason,
            "content": preview,
        })

    return packet


def audit_boundary(policy: PhoenixPolicy) -> dict:
    """Return an audit report of what would be allowed/denied.
    
    Does NOT read file contents — just classifies paths.
    Useful for verifying the boundary before enabling ingestion.
    """
    allowed_paths: list[dict] = []
    denied_paths: list[dict] = []
    for cf in walk_phoenix(policy):
        entry = {"path": cf.relative_path, "reason": cf.reason}
        if cf.allowed:
            allowed_paths.append(entry)
        else:
            denied_paths.append(entry)
    return {
        "root": str(policy.phoenix_root),
        "allowed_count": len(allowed_paths),
        "denied_count": len(denied_paths),
        "allowed": allowed_paths,
        "denied": denied_paths,
    }
