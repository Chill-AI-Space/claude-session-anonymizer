# Claude Session Anonymizer

**Anonymize and contribute your Claude Code sessions to a public research collection.**

100% local anonymization. Nothing leaves your machine until you explicitly submit.

## Why contribute?

Every session you share helps the community understand how people actually use Claude Code — what works, what doesn't, what patterns emerge. The more sessions we collect, the better the analysis. Your data is fully anonymized before it goes anywhere.

**Public collection:** [chillai.space/anonymised-claude-sessions/sessions](https://chillai.space/anonymised-claude-sessions/sessions)

## Quick Start (with Claude Code)

Paste this into Claude Code — it handles everything:

```
I want to contribute my Claude Code sessions to a public research collection. They'll be anonymized locally before sending.

1. Clone the anonymizer if I don't have it yet:
   ls ~/Documents/GitHub/claude-session-anonymizer/anonymize.py 2>/dev/null || git clone https://github.com/Chill-AI-Space/claude-session-anonymizer.git ~/Documents/GitHub/claude-session-anonymizer

2. Show my sessions sorted by size (biggest first — they're the most valuable for research):
   python3 ~/Documents/GitHub/claude-session-anonymizer/anonymize.py --list

3. From the list, suggest the top 5 biggest sessions and ask me: "These 5 sessions have the most activity. OK to anonymize and contribute all of them? Or pick different ones."

4. For the sessions I approve, anonymize and submit them in one go:
   python3 ~/Documents/GitHub/claude-session-anonymizer/anonymize.py <session_ids> --project <project> -o ~/Desktop/anonymized --submit

5. After each submission, verify nothing leaked:
   - Read report.txt, pick 5 original values (emails, paths, keys)
   - grep for them in the output files
   - Confirm: "Checked N values, 0 found in output. Clean."

6. Show me the summary: how many sessions submitted, total size, and the link to browse the public collection.
```

## Manual Usage

```bash
git clone https://github.com/Chill-AI-Space/claude-session-anonymizer.git
cd claude-session-anonymizer

# Browse sessions (sorted by size, biggest first)
python3 anonymize.py --list

# Anonymize specific sessions
python3 anonymize.py a1b2c3d4,e5f6g7h8 --project my-project

# Anonymize and submit to the public collection
python3 anonymize.py a1b2c3d4,e5f6g7h8 --project my-project --submit
```

## Output

Three files per session:

```
output/
├── my-project_2026-03-01_session.jsonl    # anonymized raw session
├── my-project_2026-03-01_transcript.txt   # human-readable conversation
└── report.txt                             # what was found and replaced
```

## What Gets Anonymized

| Priority | Category | Examples |
|----------|----------|----------|
| **CRITICAL** | API Keys & Secrets | `sk-ant-...`, `AKIA...`, `ghp_...`, `.env` values |
| **HIGH** | Personal Data | Emails, phone numbers, IP addresses |
| **MEDIUM** | Paths & URLs | `/Users/john/projects/...`, `https://internal.company.com/...` |
| **LOW** | Identifiers | Domain names, UUIDs |
| **EXTRA** | Proper Nouns | Names, company names, project names |

Every unique value gets a **consistent replacement** so the conversation still makes sense:

```
john@acme.com          → user1@example-1.com     (all 47 occurrences)
/Users/john/project    → /Users/ANONYMIZED_USER/project
sk-ant-api03-xKj8...  → REDACTED_KEY_001
Vladimir               → NAME_1
```

## Public Collection API

Anyone can browse the submitted sessions:

| Endpoint | Description |
|----------|-------------|
| `GET /sessions` | List all submitted sessions |
| `GET /sessions/:hash` | Download a specific session |
| `GET /stats` | Collection statistics |
| `POST /submit` | Submit an anonymized session |

Base URL: `https://chillai.space/anonymised-claude-sessions`

Rate limit: 10 submissions per hour per IP. Max file size: 5MB.

## Privacy Guarantee

- Pure Python — **zero dependencies**
- All detection via **local regex patterns**
- **Nothing is sent anywhere** until you add `--submit`
- One file to audit: [`anonymize.py`](anonymize.py)
- Submissions go to a public Cloudflare R2 bucket — no tracking, no accounts, no cookies

## License

MIT
