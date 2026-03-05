# Claude Session Anonymizer

**100% local. Zero external API calls. No data leaves your machine.**

Anonymize [Claude Code](https://docs.anthropic.com/en/docs/claude-code) sessions before sharing them — for research, debugging, or open-source contributions.

## Why?

Sessions in `~/.claude/projects/` contain everything: API keys, emails, file paths, client names, internal URLs. This tool scrubs it all with consistent 1:1 replacements so the conversation still makes sense.

## Quick Start

```bash
git clone https://github.com/Chill-AI-Space/claude-session-anonymizer.git
cd claude-session-anonymizer

# 1. Browse your sessions
python3 anonymize.py --list

# 2. Anonymize (first 8 chars of ID is enough)
python3 anonymize.py a1b2c3d4 --project my-project
```

### Use with Claude Code

Paste this prompt into Claude Code and it will walk you through everything:

```
I want to share some of my Claude Code sessions publicly. Help me find and anonymize them.

Step 1: Show me my sessions — run this and show the output:
  python3 ~/Documents/GitHub/claude-session-anonymizer/anonymize.py --list

Step 2: I'll pick which sessions to anonymize by telling you the IDs.

Step 3: For each session I pick, run:
  python3 ~/Documents/GitHub/claude-session-anonymizer/anonymize.py <session_ids> --project <project> -o ~/Desktop/anonymized

Step 4: After anonymization, verify nothing leaked:
  - Open the report.txt and pick 5-10 original values (emails, keys, paths)
  - grep for each one in the transcript and session files
  - Report back: how many values checked, how many found (should be 0)

Step 5: Show me the first 30 lines of the transcript so I can confirm it looks good.
```

## Output

Three files per session:

```
output/
├── my-project_2026-03-01_session.jsonl    # anonymized raw session (for sharing/import)
├── my-project_2026-03-01_transcript.txt   # human-readable conversation
└── report.txt                             # what was found, replaced, match counts
```

See [`examples/`](examples/) for sample output.

## What It Detects

| Priority | Category | Examples |
|----------|----------|----------|
| **CRITICAL** | API Keys & Secrets | `sk-ant-...`, `AKIA...`, `ghp_...`, `.env` values |
| **HIGH** | Personal Data | Emails, phone numbers, IP addresses |
| **MEDIUM** | Paths & URLs | `/Users/john/projects/...`, `https://internal.company.com/...` |
| **LOW** | Identifiers | Domain names, UUIDs |
| **EXTRA** | Proper Nouns | Names, company names, project names (safety margin) |

## How Replacement Works

Every unique value gets a **consistent replacement** across the entire session:

```
john@acme.com          → user1@example-1.com     (all 47 occurrences)
/Users/john/project    → /Users/ANONYMIZED_USER/project
sk-ant-api03-xKj8...  → REDACTED_KEY_001
Vladimir               → NAME_1
```

The report shows each replacement and how many times it was applied:

```
[Email Address]  x12
  john@acme.com
  -> user1@example-1.com
```

## Privacy Guarantee

- Pure Python — **zero dependencies**
- **No network calls** — no AI APIs, no cloud services, no telemetry
- All detection via **local regex patterns**
- One file to audit: `anonymize.py`

## License

MIT
