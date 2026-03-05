#!/usr/bin/env python3
"""
Claude Session Anonymizer — 100% local, zero external API calls.

Scans Claude Code session files (.jsonl) for sensitive data and replaces
all occurrences consistently (same input → same replacement) so the
anonymized session remains coherent and analyzable.

Usage:
    python anonymize.py                          # interactive mode
    python anonymize.py <session_id>,<session_id> # direct mode
    python anonymize.py --project <project_dir>   # specify project
    python anonymize.py --list                    # list all sessions
"""

import json
import os
import re
import sys
import argparse
import hashlib
from pathlib import Path
from collections import defaultdict
from datetime import datetime


# ─── Pattern definitions ─────────────────────────────────────────────────────

PATTERNS = {
    # CRITICAL — definitely secret
    "api_key": {
        "priority": 1,
        "label": "API Key / Secret",
        "patterns": [
            # Generic API keys (long alphanumeric strings preceded by key-like context)
            r'(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer|password|passwd|pwd)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?',
            # AWS keys
            r'(AKIA[0-9A-Z]{16})',
            r'(?:aws.{0,20}secret.{0,20})["\']?([A-Za-z0-9/+=]{40})["\']?',
            # OpenAI
            r'(sk-[A-Za-z0-9]{20,})',
            # Anthropic
            r'(sk-ant-[A-Za-z0-9\-]{20,})',
            # GitHub tokens
            r'(ghp_[A-Za-z0-9]{36})',
            r'(gho_[A-Za-z0-9]{36})',
            r'(github_pat_[A-Za-z0-9_]{22,})',
            # Google API keys
            r'(AIza[A-Za-z0-9_\-]{35})',
            # Stripe
            r'(sk_live_[A-Za-z0-9]{24,})',
            r'(pk_live_[A-Za-z0-9]{24,})',
            # Slack tokens
            r'(xoxb-[0-9]{10,}-[A-Za-z0-9]{24,})',
            r'(xoxp-[0-9]{10,}-[A-Za-z0-9]{24,})',
            # Generic long hex secrets (32+ chars)
            r'(?:token|secret|key|credential)\s*[=:]\s*["\']?([0-9a-f]{32,})["\']?',
            # Private keys
            r'(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)',
            # .env values
            r'^[A-Z_]{3,}=(.{16,})$',
        ],
    },

    # HIGH — personal data
    "email": {
        "priority": 2,
        "label": "Email Address",
        "patterns": [
            r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
        ],
    },
    "phone": {
        "priority": 2,
        "label": "Phone Number",
        "patterns": [
            # International format: +7 999 123-45-67, +1 (555) 123-4567
            r'(\+[1-9]\d{0,2}[\s\-\.]?\(?\d{2,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{2,4})',
            # US format: (555) 123-4567
            r'(\(\d{3}\)\s?\d{3}[\-\.]\d{4})',
        ],
    },
    "ip_address": {
        "priority": 2,
        "label": "IP Address",
        "patterns": [
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        ],
    },

    # MEDIUM — file system / URLs
    "file_path": {
        "priority": 3,
        "label": "File Path (with username)",
        "patterns": [
            r'(/(?:Users|home)/[a-zA-Z0-9._\-]+(?:/[^\s"\'`,\]\)}{]{1,})*)',
            r'(C:\\Users\\[a-zA-Z0-9._\-]+(?:\\[^\s"\'`,\]\)}{]{1,})*)',
        ],
    },
    "url": {
        "priority": 3,
        "label": "URL",
        "patterns": [
            r'(https?://[^\s"\'<>\]\)}{,]{5,})',
        ],
    },

    # LOW — proper nouns / identifiers (extra safety)
    "domain": {
        "priority": 4,
        "label": "Domain Name",
        "patterns": [
            r'(?<![/@\w])([a-zA-Z0-9\-]+\.(?:com|org|net|io|dev|app|co|ai|ae|xyz|me|pro|tech|cloud|space|site|online))\b',
        ],
    },
    "uuid": {
        "priority": 4,
        "label": "UUID",
        "patterns": [
            r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        ],
    },
}

# Common false-positive domains to skip
SKIP_DOMAINS = {
    "github.com", "google.com", "googleapis.com", "anthropic.com",
    "openai.com", "npmjs.com", "pypi.org", "stackoverflow.com",
    "json-schema.org", "mozilla.org", "w3.org", "schema.org",
    "example.com", "localhost", "127.0.0.1",
}

# Skip patterns that are clearly not sensitive
SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


# ─── Replacement generators ──────────────────────────────────────────────────

class ReplacementMap:
    """Maintains consistent 1:1 mapping of original → anonymized values."""

    def __init__(self):
        self.map = {}           # original → replacement
        self.reverse = {}       # replacement → original
        self.counters = defaultdict(int)
        self.categories = defaultdict(list)  # category → [(original, replacement)]

    def get_replacement(self, original: str, category: str) -> str:
        if original in self.map:
            return self.map[original]

        self.counters[category] += 1
        n = self.counters[category]

        if category == "email":
            replacement = f"user{n}@example-{n}.com"
        elif category == "phone":
            replacement = f"+1-555-000-{n:04d}"
        elif category == "ip_address":
            replacement = f"10.0.{n // 256}.{n % 256}"
        elif category == "api_key":
            replacement = f"REDACTED_KEY_{n:03d}"
        elif category == "file_path":
            # Replace username in path but keep structure
            replacement = re.sub(
                r'(/(?:Users|home)/)[a-zA-Z0-9._\-]+',
                r'\1ANONYMIZED_USER',
                original,
            )
            # Also anonymize project-specific directory names if they look custom
            if replacement == original:
                replacement = f"/home/ANONYMIZED_USER/project_{n}"
        elif category == "url":
            replacement = f"https://example-{n}.com/path"
        elif category == "domain":
            replacement = f"example-{n}.com"
        elif category == "uuid":
            # Generate a deterministic but anonymized UUID
            h = hashlib.md5(original.encode()).hexdigest()
            replacement = f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"
        elif category == "proper_noun":
            replacement = f"NAME_{n}"
        else:
            replacement = f"REDACTED_{category.upper()}_{n}"

        self.map[original] = replacement
        self.reverse[replacement] = original
        self.categories[category].append((original, replacement))
        return replacement


# ─── Proper noun detection ────────────────────────────────────────────────────

# Common English words that look like proper nouns but aren't
COMMON_WORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "as", "is", "was", "are", "were", "been",
    "be", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "shall", "can", "need", "must",
    "i", "you", "he", "she", "it", "we", "they", "me", "him", "her",
    "us", "them", "my", "your", "his", "its", "our", "their",
    "this", "that", "these", "those", "here", "there", "where", "when",
    "how", "what", "which", "who", "whom", "if", "then", "else", "so",
    "not", "no", "yes", "all", "each", "every", "both", "few", "more",
    "most", "other", "some", "such", "than", "too", "very", "just",
    "about", "above", "after", "again", "also", "always", "any",
    "because", "before", "between", "down", "during", "even", "ever",
    "first", "get", "give", "go", "got", "great", "into", "know",
    "last", "let", "like", "long", "look", "make", "many", "much",
    "new", "next", "now", "old", "only", "open", "out", "over",
    "own", "part", "put", "right", "same", "see", "set", "still",
    "take", "tell", "think", "try", "turn", "under", "up", "use",
    "want", "way", "well", "work", "write", "year",
    # Programming-related capitalized words (not proper nouns)
    "api", "url", "html", "css", "json", "xml", "http", "https",
    "get", "post", "put", "delete", "patch", "head", "options",
    "true", "false", "null", "none", "undefined", "nan", "inf",
    "string", "number", "boolean", "object", "array", "function",
    "class", "interface", "type", "enum", "const", "let", "var",
    "import", "export", "default", "return", "async", "await",
    "error", "warning", "info", "debug", "success", "failed",
    "file", "directory", "path", "name", "value", "key", "data",
    "list", "map", "set", "table", "index", "node", "element",
    "create", "read", "update", "delete", "find", "search", "filter",
    "start", "stop", "run", "build", "test", "deploy", "install",
    "user", "admin", "root", "system", "server", "client", "host",
    "input", "output", "result", "response", "request", "query",
    "command", "option", "config", "setting", "param", "arg",
    "message", "text", "content", "body", "title", "description",
    "status", "state", "mode", "level", "step", "phase", "stage",
    "source", "target", "origin", "destination",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    # Tool names / Claude-related
    "claude", "anthropic", "bash", "read", "write", "edit", "glob", "grep",
    "agent", "tool", "skill", "task", "plan", "memory",
    "assistant", "human", "model", "session", "project", "workspace",
    # Common tech brand names that are OK to keep
    "github", "google", "npm", "python", "node", "docker", "linux",
    "macos", "windows", "chrome", "firefox", "safari", "vscode",
    "typescript", "javascript", "react", "vue", "angular", "next",
    "vercel", "netlify", "aws", "azure", "gcp",
    # Common words that start sentences or appear capitalized in markdown/docs
    "note", "important", "example", "usage", "returns", "summary",
    "overview", "details", "changes", "added", "removed", "fixed",
    "version", "release", "feature", "breaking", "deprecated",
    "available", "required", "optional", "supported", "defined",
    "called", "passed", "provided", "returned", "expected",
    "running", "starting", "loading", "processing", "generating",
    "checking", "reading", "writing", "creating", "updating",
    "deleting", "finding", "searching", "filtering", "sorting",
    "working", "using", "setting", "getting", "making", "taking",
    "looking", "trying", "keeping", "adding", "removing",
    "method", "property", "parameter", "argument", "variable",
    "module", "package", "library", "framework", "component",
    "service", "handler", "controller", "middleware", "plugin",
    "schema", "migration", "template", "layout", "widget",
    "instance", "constructor", "factory", "builder", "adapter",
    "listener", "observer", "subscriber", "publisher", "emitter",
    "parser", "compiler", "interpreter", "resolver", "validator",
    "formatter", "serializer", "deserializer", "encoder", "decoder",
    "wrapper", "helper", "utility", "manager", "provider",
    "context", "scope", "namespace", "registry", "container",
    "entry", "record", "field", "column", "row", "cell",
    "page", "section", "header", "footer", "sidebar", "panel",
    "button", "link", "image", "icon", "label", "badge",
    "dialog", "modal", "popup", "tooltip", "dropdown", "menu",
    "form", "checkbox", "radio", "select", "textarea",
    "color", "font", "size", "width", "height", "margin", "padding",
    "border", "background", "display", "position", "overflow",
    "primary", "secondary", "success", "danger", "info",
    "small", "medium", "large", "hidden", "visible", "disabled",
    "active", "selected", "focused", "checked", "expanded",
    "loading", "empty", "ready", "pending", "done", "cancelled",
    # Common sentence-starters
    "here", "this", "that", "these", "those", "there", "where",
    "when", "what", "how", "why", "which", "each", "every",
    "some", "any", "many", "much", "most", "other", "another",
    "such", "same", "different", "similar", "specific", "general",
    "also", "however", "therefore", "instead", "although",
    "since", "while", "until", "unless", "whether", "either",
    "neither", "both", "only", "just", "already", "still",
    # CSS/HTML/tech terms
    "consolas", "monospace", "serif", "sans", "roboto", "segoe",
    "helvetica", "arial", "verdana", "courier", "georgia",
    "inline", "block", "flex", "grid", "absolute", "relative",
    "static", "fixed", "sticky", "inherit", "initial", "auto",
    "transparent", "solid", "dashed", "dotted", "none",
    "hover", "focus", "visited", "after", "before", "placeholder",
    # Common verbs/adjectives/nouns that appear capitalized in headers/markdown
    "implement", "replace", "replaces", "check", "extract", "generate",
    "resolve", "skip", "serialize", "validate", "escape", "match",
    "anonymize", "anonymized", "anonymizer", "scan", "scans",
    "report", "detect", "detects", "output", "outputs", "sort",
    "batch", "call", "say", "replace", "dry", "total", "visual",
    "secret", "secrets", "email", "emails", "phone", "domain",
    "privacy", "private", "public", "guarantee", "license",
    "copyright", "permission", "software", "original", "personal",
    "proper", "common", "generic", "local", "high", "low", "medium",
    "critical", "extra", "top", "middle", "bottom", "main",
    "quick", "international", "extension", "portal", "collector",
    "storage", "address", "identifier", "identifiers", "path", "paths",
    "findings", "finding", "pattern", "category", "priority",
    "examples", "names", "nouns", "keys", "misc",
    "zero", "single", "double", "triple", "multiple",
    "login", "logout", "signup", "signin", "register",
    "users", "code", "view", "views",
    "english", "russian", "french", "german", "spanish", "chinese",
    "programming", "interactive", "regenerate", "argument",
    # Tech names that are not personal
    "linkedin", "stripe", "slack", "notion", "figma", "jira",
    "confluence", "trello", "asana", "monday", "webflow",
    "supabase", "postgres", "mysql", "redis", "mongodb", "sqlite",
    "nginx", "apache", "kubernetes", "terraform", "ansible",
    "grafana", "datadog", "sentry", "cloudflare", "heroku",
    "github", "gitlab", "bitbucket",
    # CSS/font names
    "blinkmac", "blinkmacsy", "blinkmacsy stemfont",
    # Misc tech
    "markdown", "yaml", "toml", "regex", "shell", "terminal",
    "cursor", "prompt", "stdin", "stdout", "stderr",
    "async", "sync", "callback", "promise", "future", "stream",
    "buffer", "cache", "queue", "stack", "heap", "pool",
    "mutex", "lock", "thread", "process", "worker", "daemon",
    "socket", "port", "proxy", "gateway", "tunnel", "bridge",
    "token", "hash", "salt", "cipher", "digest", "signature",
    "encode", "decode", "encrypt", "decrypt", "compress",
    "upload", "download", "fetch", "push", "pull", "merge",
    "branch", "commit", "rebase", "cherry", "stash", "diff",
    "patch", "release", "deploy", "publish", "rollback",
    "monitor", "trace", "profile", "benchmark", "audit", "scan",
    # Common proper-looking words in programming contexts
    "written", "based", "given", "known", "shown", "stored",
    "found", "received", "sent", "passed", "included", "excluded",
    "enabled", "configured", "initialized", "registered",
    "extracted", "generated", "processed", "computed", "resolved",
    "mapped", "matched", "parsed", "validated", "formatted",
    "allow", "deny", "accept", "reject", "approve", "grant",
    "revoke", "block", "permit", "restrict", "limit",
}


def find_proper_nouns(text: str) -> list[str]:
    """Find capitalized words that might be proper nouns (names, companies, etc.)."""
    # Match capitalized words not at sentence start, not in code/technical context
    # Focus on words that appear in natural language context (after lowercase words)
    words = re.findall(r'(?<=[a-z] )\b([A-Z][a-z]{2,15})\b', text)

    result = set()
    for w in words:
        wl = w.lower()
        if wl in COMMON_WORDS:
            continue
        if len(w) < 3:
            continue
        # Skip words ending in common suffixes that indicate programming terms
        if any(w.endswith(s) for s in ("Map", "Set", "List", "Error", "Type",
               "Node", "Handler", "Parser", "Builder", "Factory", "Manager",
               "Provider", "Resolver", "Validator", "Formatter", "Wrapper",
               "Helper", "Config", "Context", "Event", "Result", "Option")):
            continue
        result.add(w)
    return list(result)


# ─── Session reader ──────────────────────────────────────────────────────────

def get_claude_dir() -> Path:
    return Path.home() / ".claude"


def list_projects() -> list[tuple[str, Path]]:
    """List all projects with sessions."""
    claude_dir = get_claude_dir()
    projects_dir = claude_dir / "projects"
    if not projects_dir.exists():
        return []

    results = []
    for p in sorted(projects_dir.iterdir()):
        if p.is_dir():
            sessions = list(p.glob("*.jsonl"))
            if sessions:
                # Decode project name
                name = p.name.replace("-", "/")
                results.append((name, p))
    return results


def list_sessions(project_dir: Path) -> list[dict]:
    """List sessions in a project directory with metadata."""
    sessions = []
    for f in sorted(project_dir.glob("*.jsonl")):
        session_id = f.stem
        # Read first user message for preview
        preview = ""
        timestamp = ""
        msg_count = 0
        try:
            with open(f) as fh:
                for line in fh:
                    try:
                        obj = json.loads(line)
                        if obj.get("type") == "user" and not preview:
                            msg = obj.get("message", {})
                            content = msg.get("content", "")
                            if isinstance(content, str):
                                preview = content[:100]
                            timestamp = obj.get("timestamp", "")
                        if obj.get("type") in ("user", "assistant"):
                            msg_count += 1
                    except json.JSONDecodeError:
                        continue
        except Exception:
            continue

        sessions.append({
            "id": session_id,
            "path": f,
            "preview": preview,
            "timestamp": timestamp,
            "message_count": msg_count,
        })
    return sessions


def read_session(session_path: Path) -> list[dict]:
    """Read all messages from a session file."""
    messages = []
    with open(session_path) as f:
        for line in f:
            try:
                obj = json.loads(line)
                messages.append(obj)
            except json.JSONDecodeError:
                continue
    return messages


def extract_text_from_session(session_path: Path) -> str:
    """Extract all text from a session file by reading the raw JSONL.

    We scan the raw file content rather than parsing JSON structure,
    because sensitive data can appear anywhere — deeply nested tool results,
    metadata fields, etc. Raw scanning ensures nothing is missed.
    """
    return session_path.read_text(encoding="utf-8", errors="replace")


# ─── Scanner ─────────────────────────────────────────────────────────────────

def scan_text(text: str) -> list[tuple[str, str, int]]:
    """
    Scan text for sensitive patterns.
    Returns list of (category, matched_value, priority).
    """
    findings = []
    seen = set()

    for category, config in PATTERNS.items():
        priority = config["priority"]
        for pattern in config["patterns"]:
            try:
                for match in re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE):
                    value = match.group(1) if match.lastindex else match.group(0)
                    value = value.strip().rstrip("/\\")

                    # Skip trivially short matches
                    if len(value) < 4:
                        continue

                    # Skip known false positives
                    if category == "domain" and value.lower() in SKIP_DOMAINS:
                        continue
                    if category == "ip_address" and value in SKIP_IPS:
                        continue
                    if category == "ip_address":
                        # Validate IP
                        parts = value.split(".")
                        if not all(0 <= int(p) <= 255 for p in parts):
                            continue
                    if category == "phone":
                        # Must have at least 10 digits and start with +
                        digits = re.sub(r'\D', '', value)
                        if len(digits) < 10 or len(digits) > 15:
                            continue
                        # Skip if it looks like a version number or ID
                        if re.match(r'^\d+[\-\.]\d+[\-\.]\d+[\-\.]\d+$', value):
                            continue
                    if category == "api_key" and category == "api_key":
                        # Skip if it's just a common word
                        if value.lower() in COMMON_WORDS:
                            continue

                    if value not in seen:
                        seen.add(value)
                        findings.append((category, value, priority))
            except re.error:
                continue

    # Proper nouns (priority 5 — lowest / extra safety)
    for noun in find_proper_nouns(text):
        if noun not in seen and len(noun) >= 3:
            seen.add(noun)
            findings.append(("proper_noun", noun, 5))

    # Sort by priority
    findings.sort(key=lambda x: x[2])
    return findings


# ─── Anonymizer ──────────────────────────────────────────────────────────────

def anonymize_session_lines(session_path: Path, replacement_map: ReplacementMap,
                             findings: list[tuple[str, str, int]]) -> str:
    """Apply anonymization to a raw session file and return anonymized text.

    Works on raw JSONL text to avoid JSON escape/unescape issues.
    Replaces both plain and JSON-escaped versions of each value.
    """
    # Build replacement map first
    for category, value, _priority in findings:
        replacement_map.get_replacement(value, category)

    raw = session_path.read_text(encoding="utf-8", errors="replace")

    # Sort replacements by length (longest first) to avoid partial replacements
    sorted_replacements = sorted(
        replacement_map.map.items(),
        key=lambda x: len(x[0]),
        reverse=True,
    )

    for original, replacement in sorted_replacements:
        # Replace plain text
        raw = raw.replace(original, replacement)
        # Also replace JSON-escaped version (e.g. paths with \/ or \\)
        esc_orig = json.dumps(original)[1:-1]  # strip surrounding quotes
        esc_repl = json.dumps(replacement)[1:-1]
        if esc_orig != original:
            raw = raw.replace(esc_orig, esc_repl)

    return raw


# ─── Output generation ────────────────────────────────────────────────────────

PRIORITY_LABELS = {
    1: "CRITICAL — Secrets & Keys",
    2: "HIGH — Personal Data",
    3: "MEDIUM — Paths & URLs",
    4: "LOW — Identifiers",
    5: "EXTRA — Proper Nouns (safety margin)",
}


def make_file_prefix(project_name: str, session_meta: dict) -> str:
    """Generate a readable file name prefix from project and session metadata."""
    # Extract short project name from path
    parts = project_name.strip("/").split("/")
    # Take last 1-2 meaningful parts
    meaningful = [p for p in parts if p and p not in ("Users", "home", "Documents", "GitHub")]
    short_name = "-".join(meaningful[-2:]) if meaningful else "session"
    # Sanitize
    short_name = re.sub(r'[^\w\-]', '-', short_name).strip('-').lower()

    # Date from session
    ts = session_meta.get("timestamp", "")
    date_str = ts[:10] if ts else datetime.now().strftime("%Y-%m-%d")

    return f"{short_name}_{date_str}"


def generate_transcript(session_path: Path, replacement_map: ReplacementMap) -> str:
    """Generate a human-readable .txt transcript from a session file."""
    lines = []
    lines.append("=" * 70)
    lines.append("ANONYMIZED SESSION TRANSCRIPT")
    lines.append("Generated by Claude Session Anonymizer (100% local)")
    lines.append("=" * 70)
    lines.append("")

    with open(session_path) as f:
        for raw_line in f:
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            msg_type = obj.get("type")
            if msg_type not in ("user", "assistant"):
                continue

            message = obj.get("message", {})
            role = message.get("role", msg_type)
            content = message.get("content", "")

            # Extract text
            text_parts = []
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        if item.get("type") == "text":
                            text_parts.append(item.get("text", ""))
                        elif item.get("type") == "tool_use":
                            tool_name = item.get("name", "?")
                            inp = item.get("input", {})
                            # Show tool call compactly
                            if isinstance(inp, dict):
                                summary_parts = []
                                for k, v in inp.items():
                                    vs = str(v)
                                    if len(vs) > 80:
                                        vs = vs[:80] + "..."
                                    summary_parts.append(f"{k}={vs}")
                                text_parts.append(f"[Tool: {tool_name}({', '.join(summary_parts)})]")
                            else:
                                text_parts.append(f"[Tool: {tool_name}]")
                        elif item.get("type") == "tool_result":
                            res = item.get("content", "")
                            if isinstance(res, str) and res:
                                if len(res) > 200:
                                    res = res[:200] + "..."
                                text_parts.append(f"[Result: {res}]")

            text = "\n".join(text_parts).strip()
            if not text:
                continue

            # Apply replacements
            sorted_replacements = sorted(
                replacement_map.map.items(),
                key=lambda x: len(x[0]),
                reverse=True,
            )
            for original, replacement in sorted_replacements:
                text = text.replace(original, replacement)

            # Format
            ts = obj.get("timestamp", "")
            ts_short = ts[:19].replace("T", " ") if ts else ""

            speaker = "USER" if role == "user" else "ASSISTANT"
            lines.append(f"--- {speaker} {ts_short} ---")
            lines.append(text)
            lines.append("")

    return "\n".join(lines)


def count_occurrences(text: str, value: str) -> int:
    """Count how many times a value appears in text."""
    return text.count(value)


def generate_report_txt(replacement_map: ReplacementMap,
                         findings: list[tuple[str, str, int]],
                         raw_text: str,
                         session_ids: list[str],
                         output_path: Path) -> None:
    """Generate a plain text report of all findings and replacements."""

    lines = []
    lines.append("=" * 70)
    lines.append("ANONYMIZATION REPORT")
    lines.append("Generated by Claude Session Anonymizer (100% local)")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Sessions: {', '.join(s[:8] + '...' for s in session_ids)}")
    lines.append(f"Date:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total findings:     {len(findings)}")
    lines.append(f"Unique replacements: {len(replacement_map.map)}")
    lines.append(f"Critical + High:    {sum(1 for _, _, p in findings if p <= 2)}")
    lines.append("")

    grouped = defaultdict(list)
    for category, value, priority in findings:
        replacement = replacement_map.map.get(value, "???")
        hits = count_occurrences(raw_text, value)
        grouped[priority].append((category, value, replacement, hits))

    for priority in sorted(grouped.keys()):
        label = PRIORITY_LABELS.get(priority, f"Priority {priority}")
        items = grouped[priority]

        lines.append("-" * 70)
        lines.append(f"{label}  ({len(items)} found)")
        lines.append("-" * 70)
        lines.append("")

        # Column widths
        for category, value, replacement, hits in items:
            cat_label = PATTERNS.get(category, {}).get("label", category)
            lines.append(f"  [{cat_label}]  x{hits}")
            lines.append(f"    {value}")
            lines.append(f"    -> {replacement}")
            lines.append("")

    lines.append("=" * 70)
    lines.append("To verify: open the anonymized .jsonl or .txt in any editor,")
    lines.append("Ctrl+F for any original value above — none should be found.")
    lines.append("=" * 70)

    output_path.write_text("\n".join(lines), encoding="utf-8")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Anonymize Claude Code sessions — 100% local, no external APIs.",
    )
    parser.add_argument("sessions", nargs="?", default=None,
                        help="Comma-separated session IDs to anonymize")
    parser.add_argument("--list", action="store_true",
                        help="List all projects and sessions")
    parser.add_argument("--project", "-p", default=None,
                        help="Project directory name (from --list output)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output directory for anonymized files (default: ./output)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Only scan and report, don't write anonymized files")
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     Claude Session Anonymizer — 100% Local Processing   ║")
    print("║     No data is sent to any external service.            ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    projects = list_projects()
    if not projects:
        print("No Claude Code projects found in ~/.claude/projects/")
        sys.exit(1)

    # ── List mode ──
    if args.list:
        print("Available projects:\n")
        for i, (name, path) in enumerate(projects, 1):
            sessions = list_sessions(path)
            print(f"  [{i}] {name}  ({len(sessions)} sessions)")
            for s in sessions[:5]:
                ts = s['timestamp'][:10] if s['timestamp'] else '?'
                preview = s['preview'][:60] + '...' if len(s['preview']) > 60 else s['preview']
                print(f"      {s['id'][:8]}...  {ts}  msgs:{s['message_count']:3d}  {preview}")
            if len(sessions) > 5:
                print(f"      ... and {len(sessions) - 5} more")
            print()
        print("Usage: python anonymize.py <session_id1>,<session_id2> --project <dir_name>")
        print("       Use full session ID or first 8 chars.")
        sys.exit(0)

    # ── Select project ──
    if args.project:
        # Find matching project
        matching = [(n, p) for n, p in projects if args.project in n or args.project in p.name]
        if not matching:
            print(f"Project not found: {args.project}")
            print("Use --list to see available projects.")
            sys.exit(1)
        project_name, project_dir = matching[0]
    else:
        # Interactive project selection
        print("Select project:\n")
        for i, (name, _) in enumerate(projects, 1):
            print(f"  [{i}] {name}")
        print()
        try:
            choice = int(input("Enter number: ")) - 1
            if 0 <= choice < len(projects):
                project_name, project_dir = projects[choice]
            else:
                print("Invalid choice.")
                sys.exit(1)
        except (ValueError, EOFError):
            print("Invalid input.")
            sys.exit(1)

    print(f"\nProject: {project_name}")

    # ── Select sessions ──
    all_sessions = list_sessions(project_dir)
    if not all_sessions:
        print("No sessions found in this project.")
        sys.exit(1)

    if args.sessions:
        session_ids = [s.strip() for s in args.sessions.split(",")]
    else:
        print(f"\nAvailable sessions ({len(all_sessions)}):\n")
        for i, s in enumerate(all_sessions, 1):
            ts = s['timestamp'][:10] if s['timestamp'] else '?'
            preview = s['preview'][:60] + '...' if len(s['preview']) > 60 else s['preview']
            print(f"  [{i}] {s['id'][:8]}...  {ts}  msgs:{s['message_count']:3d}  {preview}")
        print()
        print("Enter session numbers (comma-separated) or 'all':")
        try:
            choice = input("> ").strip()
            if choice.lower() == "all":
                session_ids = [s["id"] for s in all_sessions]
            else:
                indices = [int(x.strip()) - 1 for x in choice.split(",")]
                session_ids = [all_sessions[i]["id"] for i in indices if 0 <= i < len(all_sessions)]
        except (ValueError, EOFError):
            print("Invalid input.")
            sys.exit(1)

    # Resolve partial IDs
    selected_sessions = []
    for sid in session_ids:
        for s in all_sessions:
            if s["id"].startswith(sid):
                selected_sessions.append(s)
                break
        else:
            print(f"Warning: session not found: {sid}")

    if not selected_sessions:
        print("No valid sessions selected.")
        sys.exit(1)

    print(f"\nProcessing {len(selected_sessions)} session(s)...\n")

    # ── Scan ──
    all_text = ""
    for s in selected_sessions:
        all_text += extract_text_from_session(s["path"]) + "\n"

    print(f"Extracted {len(all_text):,} characters of text.")

    findings = scan_text(all_text)
    print(f"Found {len(findings)} sensitive items.\n")

    # ── Display summary ──
    by_priority = defaultdict(list)
    for cat, val, pri in findings:
        by_priority[pri].append((cat, val))

    for pri in sorted(by_priority.keys()):
        label = PRIORITY_LABELS.get(pri, f"Priority {pri}")
        items = by_priority[pri]
        print(f"  {label}: {len(items)} items")
        for cat, val in items[:3]:
            display = val[:50] + "..." if len(val) > 50 else val
            print(f"    - [{cat}] {display}")
        if len(items) > 3:
            print(f"    ... and {len(items) - 3} more")
    print()

    # ── Anonymize ──
    replacement_map = ReplacementMap()

    # Build replacement map for all findings (needed for report even in dry-run)
    for category, value, _priority in findings:
        replacement_map.get_replacement(value, category)

    output_dir = Path(args.output) if args.output else Path.cwd() / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.dry_run:
        for s in selected_sessions:
            prefix = make_file_prefix(project_name, s)

            # 1. Anonymized session (.jsonl) — for sharing
            anonymized_text = anonymize_session_lines(
                s["path"], replacement_map, findings
            )
            session_file = output_dir / f"{prefix}_session.jsonl"
            session_file.write_text(anonymized_text, encoding="utf-8")

            # 2. Readable transcript (.txt)
            transcript = generate_transcript(s["path"], replacement_map)
            transcript_file = output_dir / f"{prefix}_transcript.txt"
            transcript_file.write_text(transcript, encoding="utf-8")

            print(f"  Session:    {session_file.name}")
            print(f"  Transcript: {transcript_file.name}")

    # 3. Report (.txt) — always, even in dry-run
    report_path = output_dir / "report.txt"
    generate_report_txt(replacement_map, findings, all_text,
                         [s["id"] for s in selected_sessions], report_path)
    print(f"  Report:     {report_path.name}")

    print(f"\n  Output dir: {output_dir}/")
    print(f"  Total replacements: {len(replacement_map.map)}")

    # ── Verification hint ──
    if replacement_map.map and not args.dry_run:
        print()
        print("─── Verify ─────────────────────────────────────────")
        print("Open any output file in an editor and Ctrl+F for")
        print("any value from report.txt — none should be found.")

    print()
    print("Done!")
    print()


if __name__ == "__main__":
    main()
