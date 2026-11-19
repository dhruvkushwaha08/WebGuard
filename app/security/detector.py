"""Heuristic request detector. Detection supplements parameterized SQL and output escaping."""
import html
import re
import urllib.parse

SQL_RULES = [
 ("UNION_SELECT", re.compile(r"(?:['\"]\s*union\s+(?:all\s+)?select\b|\bunion\s+(?:all\s+)?select\b.{0,120}(?:--|/\*|#|;))", re.I | re.S), "UNION SELECT in an injection context"),
 ("BOOLEAN_TAUTOLOGY", re.compile(r"(?:['\"]\s*or\s+\d+\s*=\s*\d+|['\"]\s*or\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+['\"]|\bor\s+\d+\s*=\s*\d+.{0,20}(?:--|/\*|#))", re.I | re.S), "Boolean tautology pattern"),
 ("SQL_COMMENT", re.compile(r"(?:['\"][^'\"]{0,120}(?:--|/\*|#)|\b(?:union|select|or|and)\b.{0,80}(?:--|/\*|#))", re.I | re.S), "SQL comment marker in an injection context"),
 ("QUOTE_LOGIC", re.compile(r"['\"]\s*(?:or|and)\b", re.I), "Quote followed by SQL boolean operator"),
]
XSS_RULES = [
 ("SCRIPT_TAG", re.compile(r"<\s*script\b[^>]*(?:\bsrc\s*=|>[\s\S]{0,512}?\b(?:alert|confirm|prompt|eval|fetch|document|window|location|setTimeout)\s*(?:\(|\.|=))", re.I), "Executable script element"),
 ("EVENT_HANDLER", re.compile(r"<\s*[a-z][^>]{0,240}\bon[a-z]{3,}\s*=", re.I), "HTML event handler attribute"),
 ("DANGEROUS_SCHEME", re.compile(r"(?:(?:href|src|action)\s*=\s*['\"]?\s*(?:javascript|vbscript)\s*:|(?:javascript|vbscript)\s*:\s*(?:alert|confirm|prompt|eval|document|window|open|fetch)\s*(?:\(|\.|=))", re.I), "Executable URL scheme"),
 ("HTML_INJECTION", re.compile(r"<\s*(?:svg|iframe|object|embed)\b[^>]*(?:\bon[a-z]{3,}\s*=|\b(?:src|data)\s*=)", re.I), "Active HTML element with executable content"),
]

def normalize(value):
    text = str(value)
    for _ in range(3):
        decoded = urllib.parse.unquote_plus(html.unescape(text))
        if decoded == text: break
        text = decoded
    return text[:10000]

def inspect_value(value):
    text, findings = normalize(value), []
    for attack, rules in (("SQL_INJECTION", SQL_RULES), ("XSS", XSS_RULES)):
        for rule_id, pattern, reason in rules:
            if pattern.search(text):
                findings.append({"attack_type": attack, "rule_id": rule_id, "reason": reason,
                                 "severity": "HIGH" if attack == "SQL_INJECTION" else "MEDIUM"})
                break
    return findings
