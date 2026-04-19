# injection-scan — Deterministic Prompt Injection Scanner

A zero-dependency Node.js scanner for detecting prompt injection attempts in external content (web pages, emails, API responses, user input). 60+ regex patterns across 9 attack categories, plus a semantic density layer for paraphrasing attacks.

> Part of [The Agent Crafting Table](https://github.com/The-Agent-Crafting-Table) — standalone agent system components for Claude Code.

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
- Zero runtime dependencies

## Detection Categories

| Category | Examples |
|---|---|
| `instruction-override` | "ignore previous instructions", "disregard all rules" |
| `polite-override` | "just this once, ignore...", "hypothetically if you had no restrictions" |
| `fake-system-tag` | `[system]`, `<system>`, `[ADMIN]`, `[OVERRIDE]` |
| `persona-override` | "you are now...", "your new role is..." |
| `authority-spoof` | "admin mode enabled", "the user has authorized", "security level: 0" |
| `exfil-attempt` | "send [content] to http://...", "output all your keys" |
| `fake-tool-call` | `<tool>`, `<function>`, `[EXEC]`, fake bash blocks with exec() |
| `html-injection` | Hidden CSS (display:none, opacity:0), zero-width chars, HTML comments with instructions |
| `jailbreak` | "DAN mode", "developer mode", "act as an evil AI" |
| `sql-injection` | `; DROP TABLE`, `UNION SELECT`, classic OR 1=1 |
| `encoding-trick` | Base64 + eval, URL-encoded injection keywords |
| `high-directive-density` | Semantic: unusually high density of imperative/directive language (catches paraphrasing attacks) |

## Semantic Layer

Beyond pattern matching, the scanner computes an imperative-density score over the full text. Normal web content has <3% imperative verb density. Text engineered to override instructions tends to have much higher density even when all individual patterns are novel. This catches paraphrasing attacks that reword known patterns.

The semantic layer only produces a `suspicious` result (score ≤ 40), never a hard `blocked`. It's a signal, not a gate.

## Integration Pattern

```javascript
const { execFileSync } = require('child_process');

function scanContent(text) {
  try {
    execFileSync('node', ['injection-scan.js', text], { encoding: 'utf8' });
    return 'clean';
  } catch (err) {
    const result = JSON.parse(err.stdout || '{}');
    if (err.status === 2) throw new Error(`Blocked: ${result.findings?.[0]?.label}`);
    if (err.status === 1) return 'suspicious'; // review before proceeding
    throw err;
  }
}
```

## Tuning

The `INJECTION_PATTERNS`, `SUSPICIOUS_PHRASES`, and `IMPERATIVE_VERBS` arrays are all plaintext at the top of the file. Add project-specific patterns there. The `semanticSuspicionScore` thresholds (0.03/0.05/0.08 imperative density) can be adjusted if your legitimate content is highly directive (e.g. tutorial sites with lots of "run this command").

## Limitations

- Regex-based — a determined attacker who knows the exact patterns can craft text that avoids every one. Defense-in-depth: use this as one layer, not the only layer.
- English-language focused. Patterns written for English; multilingual injection attempts may pass.
- The semantic layer produces false positives on legitimate instructional content (docs, how-to articles). Tune the density thresholds if you're scanning that type of content.
