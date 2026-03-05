# Claude Session Anonymizer

**100% local. Zero external API calls. No data leaves your machine.**

A CLI tool to anonymize [Claude Code](https://docs.anthropic.com/en/docs/claude-code) session transcripts before sharing them publicly (e.g., for research, debugging, or training data).

## Why?

Claude Code sessions stored in `~/.claude/projects/` contain everything: your file paths, API keys, emails, client names, internal URLs, and more. If you want to share session data — for research, bug reports, or open-source contributions — you need to scrub it first.

This tool:
- **Scans** sessions for sensitive patterns (keys, emails, phones, paths, URLs, proper nouns)
- **Replaces** all findings consistently (same value → same replacement everywhere)
- **Reports** what was found, categorized by severity
- **Outputs** clean anonymized session files ready to share

## Privacy Guarantee

- Written in pure Python — **zero dependencies**
- **No network calls** — no AI APIs, no cloud services, no telemetry
- All detection is via **local regex patterns**
- You can audit the entire source: it's one file (`anonymize.py`)

## Quick Start

```bash
git clone https://github.com/Chill-AI-Space/claude-session-anonymizer.git
cd claude-session-anonymizer

# List all projects and sessions
python anonymize.py --list

# Anonymize specific sessions
python anonymize.py <session_id1>,<session_id2> --project <project_name>

# Interactive mode
python anonymize.py

# Dry run — only scan and report, don't write files
python anonymize.py --dry-run
```

## What It Detects

Findings are categorized by severity:

| Priority | Category | Examples |
|----------|----------|----------|
| **CRITICAL** | API Keys & Secrets | `sk-ant-...`, `AKIA...`, `ghp_...`, `.env` values |
| **HIGH** | Personal Data | Emails, phone numbers, IP addresses |
| **MEDIUM** | Paths & URLs | `/Users/john/projects/...`, `https://internal.company.com/...` |
| **LOW** | Identifiers | Domain names, UUIDs |
| **EXTRA** | Proper Nouns | Names, company names, project names (safety margin) |

## How Replacement Works

Every unique sensitive value gets a **deterministic replacement**:

| Type | Original | Replacement |
|------|----------|-------------|
| Email | `john@acme.com` | `user1@example-1.com` |
| Phone | `+1-555-123-4567` | `+1-555-000-0001` |
| API Key | `sk-ant-abc123...` | `REDACTED_KEY_001` |
| File Path | `/Users/john/project/` | `/Users/ANONYMIZED_USER/project/` |
| URL | `https://acme.internal.io/api` | `https://example-1.com/path` |
| Name | `Vladimir` | `NAME_1` |

**Consistency**: If `john@acme.com` appears 47 times across the session, all 47 occurrences become `user1@example-1.com`. This preserves the logical flow of the conversation.

## Output

```
output/
├── anonymization-report.html    # Visual report of all findings
└── <session_id>.anonymized.jsonl # Anonymized session file(s)
```

The HTML report groups findings by severity so you can quickly review what was detected.

## Session Storage

Claude Code stores sessions at:
```
~/.claude/projects/<encoded-project-path>/<session-id>.jsonl
```

Each file is JSONL (one JSON object per line) containing user messages, assistant responses, tool calls, and metadata.

## License

MIT
