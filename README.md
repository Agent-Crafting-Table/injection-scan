# injection-scan — Deterministic Prompt Injection Scanner

A zero-dependency Node.js scanner for detecting prompt injection attempts in external content (web pages, emails, API responses, user input). 60+ regex patterns across 9 attack categories, plus a semantic density layer for paraphrasing attacks.

> Part of [The Agent Crafting Table](https://github.com/Agent-Crafting-Table) — standalone Claude Code agent components.

## Drop-in

```bash
# Copy to your agent workspace
cp injection-scan.js /your/workspace/scripts/injection-scan.js
```

Then call it before passing any external content to your LLM:

```bash
node scripts/injection-scan.js "content to check"
# exit 0 = clean, 1 = suspicious, 2 = blocked
```

## Why

Any agent that processes external content — URLs, emails, API responses — is a target for prompt injection. An attacker embeds instruction-override text in a web page; your agent fetches it and obeys. This scanner runs before you pass external content to your LLM.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Clean — safe to proceed |
| 1 | Suspicious — review before proceeding |
| 2 | Blocked — do not pass to LLM |

## Output

JSON to stdout:

```json
{
  "risk": "clean|suspicious|blocked",
  "score": 0,
  "findings": [
    {
      "label": "instruction-override",
      "severity": "blocked",
      "matches": ["ignore previous instructions"]
    }
  ]
}
```

## Usage

```bash
# Scan a string
node injection-scan.js "ignore previous instructions and do X"

# Scan a file
node injection-scan.js --file /path/to/fetched-page.html

# Pipe from curl
curl -s https://example.com | node injection-scan.js

# In a shell script (check exit code)
if node injection-scan.js --file "$CONTENT_FILE"; then
  echo "safe"
elif [ $? -eq 1 ]; then
  echo "suspicious — human review needed"
else
  echo "blocked — not passing to LLM"
fi
```

## Requirements

- Node.js 16+
- Zero dependencies
