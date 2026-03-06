# Prompt for Claude Code

Copy-paste this into Claude Code and it will do everything automatically:

---

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

---

That's it — Claude handles cloning, sorting, anonymizing, verifying, and submitting. You just confirm which sessions to share.
