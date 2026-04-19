#!/usr/bin/env node
/**
 * injection-scan.js - Deterministic prompt injection scanner
 *
 * Usage:
 *   node scripts/injection-scan.js "text to scan"
 *   echo "text" | node scripts/injection-scan.js
 *   node scripts/injection-scan.js --file /path/to/file.txt
 *
 * Exit codes: 0 = clean, 1 = suspicious, 2 = blocked
 * Output: JSON { risk: "clean|suspicious|blocked", score: 0-100, findings: [] }
 *
 * Last updated: 2026-03-14
 * Pattern count: 60+
 */

const INJECTION_PATTERNS = [
  // ── Direct instruction overrides ──────────────────────────────────────────
  { pattern: /ignore\s+(previous|all|prior)\s+(instructions?|prompts?|rules?|context)/gi, severity: 'blocked', label: 'instruction-override' },
  { pattern: /disregard\s+(previous|all|prior)\s+(instructions?|prompts?|rules?)/gi, severity: 'blocked', label: 'instruction-override' },
  { pattern: /forget\s+(everything|all|previous|prior)\s*(instructions?|context|prompts?)?/gi, severity: 'blocked', label: 'instruction-override' },
  { pattern: /override\s+(your\s+)?(previous|prior|current|all)\s+(instructions?|directives?|rules?|context)/gi, severity: 'blocked', label: 'instruction-override' },

  // ── Indirect / polite overrides ───────────────────────────────────────────
  { pattern: /set\s+aside\s+(what\s+you\s+were\s+doing|your\s+(previous|prior|current)\s+(instructions?|task|role))/gi, severity: 'blocked', label: 'polite-override' },
  { pattern: /let['']?s\s+start\s+(fresh|over|from\s+scratch)\b/gi, severity: 'suspicious', label: 'polite-override' },
  { pattern: /for\s+this\s+(task|request|question)\s+only[,\s]+please/gi, severity: 'suspicious', label: 'polite-override' },
  { pattern: /hypothetically\s+speaking[,\s]+if\s+you\s+had\s+no\s+(restrictions?|limits?|rules?|guidelines?)/gi, severity: 'blocked', label: 'polite-override' },
  { pattern: /if\s+you\s+(had\s+no|weren['']?t\s+bound\s+by|could\s+ignore)\s+(restrictions?|rules?|guidelines?|instructions?)/gi, severity: 'blocked', label: 'polite-override' },
  { pattern: /just\s+this\s+once[,\s]+ignore/gi, severity: 'blocked', label: 'polite-override' },
  { pattern: /as\s+a\s+thought\s+experiment[,\s]+(pretend|imagine|assume)\s+you\s+(have\s+no|are\s+not)/gi, severity: 'suspicious', label: 'polite-override' },

  // ── System prompt manipulation ────────────────────────────────────────────
  { pattern: /\[system\]|\[System\]|<system>|<\/system>/g, severity: 'blocked', label: 'fake-system-tag' },
  { pattern: /you\s+are\s+now\b/gi, severity: 'suspicious', label: 'persona-override' },
  { pattern: /your\s+new\s+(instructions?|role|persona|identity|prime\s+directive)/gi, severity: 'suspicious', label: 'persona-override' },
  { pattern: /new\s+(prime\s+)?directive/gi, severity: 'suspicious', label: 'directive-override' },
  { pattern: /override\s+(mode|protocol|instructions?)/gi, severity: 'suspicious', label: 'directive-override' },
  { pattern: /\bsystem\s+prompt\b.*\b(is|was|should\s+be)\b/gi, severity: 'suspicious', label: 'system-prompt-probe' },

  // ── Context poisoning / authority spoofing ────────────────────────────────
  { pattern: /the\s+user\s+has\s+(authorized|approved|granted|confirmed)\b/gi, severity: 'blocked', label: 'authority-spoof' },
  { pattern: /admin\s+mode\s+(enabled|activated|on)\b/gi, severity: 'blocked', label: 'authority-spoof' },
  { pattern: /special\s+permission\s+(granted|given|approved)\b/gi, severity: 'blocked', label: 'authority-spoof' },
  { pattern: /security\s+level\s*:\s*(unrestricted|none|0|disabled)\b/gi, severity: 'blocked', label: 'authority-spoof' },
  { pattern: /\[AUTHORIZED\]|\[ADMIN\]|\[OVERRIDE\]|\[TRUSTED\]/gi, severity: 'blocked', label: 'authority-spoof' },
  { pattern: /authorization\s+code\s*:\s*\S+/gi, severity: 'suspicious', label: 'authority-spoof' },
  { pattern: /elevated\s+(privileges?|access|permissions?)\s+(granted|enabled|active)/gi, severity: 'blocked', label: 'authority-spoof' },

  // ── Data exfiltration ─────────────────────────────────────────────────────
  { pattern: /send\s+.{0,50}\s+to\s+.{0,100}(http|email|discord|telegram|webhook)/gi, severity: 'suspicious', label: 'exfil-attempt' },
  { pattern: /output\s+(all|every|your)\s+(files?|secrets?|keys?|tokens?|passwords?)/gi, severity: 'blocked', label: 'secret-extraction' },
  { pattern: /print\s+(your|all)\s+(api\s+keys?|secrets?|credentials?|tokens?)/gi, severity: 'blocked', label: 'secret-extraction' },
  { pattern: /summarize\s+and\s+(forward|send|email|post)\b/gi, severity: 'suspicious', label: 'indirect-exfil' },
  { pattern: /include\s+this\s+in\s+your\s+next\s+message\s+to\b/gi, severity: 'blocked', label: 'indirect-exfil' },
  { pattern: /when\s+you\s+(respond|reply)[,\s]+also\s+(add|include|append|send)\b/gi, severity: 'suspicious', label: 'indirect-exfil' },
  { pattern: /relay\s+(this|the\s+following|these\s+details)\s+to\b/gi, severity: 'suspicious', label: 'indirect-exfil' },
  { pattern: /\bexfiltrate\b/gi, severity: 'blocked', label: 'indirect-exfil' },

  // ── Fake tool/function calls ──────────────────────────────────────────────
  { pattern: /<tool\s*>.*?<\/tool\s*>/gi, severity: 'blocked', label: 'fake-tool-call' },
  { pattern: /<function\s*>.*?<\/function\s*>/gi, severity: 'blocked', label: 'fake-tool-call' },
  { pattern: /<tool_call\s*>|<\/tool_call\s*>/gi, severity: 'blocked', label: 'fake-tool-call' },
  { pattern: /\[TOOL_USE\]|\[FUNCTION_CALL\]|\[EXEC\]/gi, severity: 'blocked', label: 'fake-tool-call' },
  { pattern: /```\s*(tool|function|exec|bash|sh)\s*\n[\s\S]*?exec\s*\(/gi, severity: 'suspicious', label: 'fake-tool-call' },

  // ── Markdown / HTML injection ─────────────────────────────────────────────
  { pattern: /<!--[\s\S]*?ignore[\s\S]*?-->/gi, severity: 'blocked', label: 'html-injection' },
  { pattern: /<!--[\s\S]*?(previous|prior)\s+(instructions?|prompt)[\s\S]*?-->/gi, severity: 'blocked', label: 'html-injection' },
  { pattern: /<style[^>]*>[\s\S]*?display\s*:\s*none[\s\S]*?<\/style>/gi, severity: 'suspicious', label: 'hidden-text' },
  { pattern: /color\s*:\s*transparent|opacity\s*:\s*0|font-size\s*:\s*0/gi, severity: 'suspicious', label: 'hidden-text' },
  { pattern: /\u200b|\u200c|\u200d|\u2060|\ufeff/g, severity: 'suspicious', label: 'zero-width-chars' },

  // ── File/config manipulation ──────────────────────────────────────────────
  { pattern: /read\s+(WORKFLOW_AUTO|BOOTSTRAP|SYSTEM|OVERRIDE)\.md/gi, severity: 'blocked', label: 'fake-file-load' },
  { pattern: /required\s+startup\s+files?\s+were\s+not\s+read/gi, severity: 'blocked', label: 'fake-startup-protocol' },
  { pattern: /please\s+read\s+(them|it)\s+now\s+using\s+the\s+(Read|read)\s+tool/gi, severity: 'blocked', label: 'fake-startup-protocol' },

  // ── Role / jailbreak ──────────────────────────────────────────────────────
  { pattern: /jailbreak|DAN\s+mode|developer\s+mode|unrestricted\s+mode/gi, severity: 'blocked', label: 'jailbreak' },
  { pattern: /pretend\s+(you\s+are|to\s+be)\s+(not\s+an?\s+ai|unrestricted|without\s+limits)/gi, severity: 'blocked', label: 'jailbreak' },
  { pattern: /\bDAN\b|\bAIM\b|\bSTAN\b|\bDUDE\b|\bMagneto\b/g, severity: 'suspicious', label: 'jailbreak-persona' },
  { pattern: /act\s+as\s+(if\s+you\s+were\s+)?(a|an)?\s*(evil|unrestricted|unfiltered|uncensored)\s*(ai|assistant|bot|model)/gi, severity: 'blocked', label: 'jailbreak' },

  // ── Encoding tricks ───────────────────────────────────────────────────────
  // Base64-looking strings embedded in apparent instructions (>20 char alphanum+/+=)
  { pattern: /(?:[A-Za-z0-9+/]{20,}={0,2})\s*(decode|base64|atob|eval)/gi, severity: 'suspicious', label: 'encoding-trick' },
  { pattern: /\beval\s*\(|atob\s*\(|btoa\s*\(|fromCharCode\s*\(/gi, severity: 'suspicious', label: 'encoding-trick' },
  // URL-encoded injection keywords
  { pattern: /%69gnore|%69gnore|ign%6Fre|ign%6fre/gi, severity: 'blocked', label: 'encoded-injection' },

  // ── Unicode homoglyph detection (common lookalikes for "system", "ignore", "admin") ──
  { pattern: /[\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456]{3,}/g, severity: 'suspicious', label: 'unicode-homoglyph' },  // Cyrillic lookalikes

  // ── SQL injection ─────────────────────────────────────────────────────────
  { pattern: /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\s+/gi, severity: 'blocked', label: 'sql-injection' },
  { pattern: /'\s+OR\s+'?\d+'?\s*=\s*'?\d+/gi, severity: 'blocked', label: 'sql-injection' },
  { pattern: /UNION\s+(ALL\s+)?SELECT/gi, severity: 'suspicious', label: 'sql-injection' },
];

const SUSPICIOUS_PHRASES = [
  'as an ai language model', 'your instructions say', 'your system prompt',
  'your programming', 'you are programmed to', 'execute the following',
  'run this command', 'eval(', 'exec(', '__import__', 'subprocess',
  // New additions
  'your actual instructions', 'your real instructions', 'your hidden instructions',
  'confidential system prompt', 'secret prompt', 'bypass your safety',
  'disable your filters', 'without restrictions', 'without limitations',
  'ignore your training', 'ignore your guidelines',
];

// ── Semantic suspicion scoring ─────────────────────────────────────────────
// Flag content with unusually high density of imperative/directive language
// This catches paraphrasing attacks and indirect injection in web/email content

const IMPERATIVE_VERBS = [
  'ignore', 'disregard', 'forget', 'override', 'replace', 'delete', 'remove',
  'execute', 'run', 'send', 'output', 'print', 'write', 'insert', 'add',
  'change', 'modify', 'update', 'set', 'enable', 'disable', 'activate',
];

const DIRECTIVE_MARKERS = [
  'you should', 'you must', 'make sure to', 'remember to', 'be sure to',
  'always', 'never', 'do not', "don't", 'ensure that', 'it is important',
  'from now on', 'going forward', 'in all future', 'henceforth',
];

/**
 * Compute a semantic suspicion score for non-human content (web pages, emails).
 * Returns 0–40 based on density of directive language.
 */
function semanticSuspicionScore(text) {
  const lc = text.toLowerCase();
  const words = lc.split(/\s+/);
  const totalWords = words.length;
  if (totalWords < 20) return 0;

  // Count imperative verb hits
  let imperativeCount = 0;
  for (const verb of IMPERATIVE_VERBS) {
    const re = new RegExp(`\\b${verb}\\b`, 'g');
    const m = lc.match(re);
    if (m) imperativeCount += m.length;
  }

  // Count directive marker hits
  let directiveCount = 0;
  for (const marker of DIRECTIVE_MARKERS) {
    const re = new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
    const m = lc.match(re);
    if (m) directiveCount += m.length;
  }

  const imperativeDensity = imperativeCount / totalWords;
  const directiveDensity = directiveCount / (totalWords / 10); // per 10 words

  // Normal web/email text rarely has >3% imperative density
  // Normal text rarely has >1 directive marker per 10 words
  let score = 0;
  if (imperativeDensity > 0.08) score += 30;
  else if (imperativeDensity > 0.05) score += 20;
  else if (imperativeDensity > 0.03) score += 10;

  if (directiveDensity > 2) score += 20;
  else if (directiveDensity > 1) score += 10;

  return Math.min(score, 40);
}

function scan(text) {
  const findings = [];
  let maxSeverityScore = 0;

  for (const { pattern, severity, label } of INJECTION_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      const score = severity === 'blocked' ? 90 : 50;
      findings.push({ label, severity, matches: matches.slice(0, 3) });
      maxSeverityScore = Math.max(maxSeverityScore, score);
    }
  }

  for (const phrase of SUSPICIOUS_PHRASES) {
    if (text.toLowerCase().includes(phrase)) {
      findings.push({ label: 'suspicious-phrase', severity: 'suspicious', matches: [phrase] });
      maxSeverityScore = Math.max(maxSeverityScore, 40);
    }
  }

  // Semantic layer — only kicks in if no hard blocks already found
  if (maxSeverityScore < 90) {
    const semanticScore = semanticSuspicionScore(text);
    if (semanticScore >= 30) {
      findings.push({ label: 'high-directive-density', severity: 'suspicious', matches: [`semantic score: ${semanticScore}`] });
      maxSeverityScore = Math.max(maxSeverityScore, semanticScore);
    } else if (semanticScore > 0) {
      findings.push({ label: 'elevated-directive-density', severity: 'info', matches: [`semantic score: ${semanticScore}`] });
      // Don't raise maxSeverityScore for low semantic scores
    }
  }

  const risk = maxSeverityScore >= 80 ? 'blocked' : maxSeverityScore >= 40 ? 'suspicious' : 'clean';
  return { risk, score: maxSeverityScore, findings };
}

async function main() {
  let text = '';

  const fileFlag = process.argv.indexOf('--file');
  if (fileFlag !== -1 && process.argv[fileFlag + 1]) {
    const fs = require('fs');
    text = fs.readFileSync(process.argv[fileFlag + 1], 'utf8');
  } else if (process.argv[2] && process.argv[2] !== '--file') {
    text = process.argv.slice(2).join(' ');
  } else {
    // Read from stdin
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    text = Buffer.concat(chunks).toString('utf8');
  }

  if (!text.trim()) {
    console.log(JSON.stringify({ risk: 'clean', score: 0, findings: [], note: 'empty input' }));
    process.exit(0);
  }

  const result = scan(text);
  console.log(JSON.stringify(result, null, 2));

  const exitCode = result.risk === 'blocked' ? 2 : result.risk === 'suspicious' ? 1 : 0;
  process.exit(exitCode);
}

main().catch(err => {
  console.error(JSON.stringify({ error: err.message }));
  process.exit(2);
});
