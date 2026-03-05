# Prompt for Claude Code

Copy-paste this into Claude Code to find interesting sessions and anonymize them:

---

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

---

That's it. Claude will walk you through the whole process interactively.
