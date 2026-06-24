import re


ATTACK_PATTERNS = {
    "sql_injection": [
        re.compile(r"(?i)(\bUNION\b\s+\bSELECT\b|\bSELECT\b.+\bFROM\b|\bOR\b\s+1=1|--|;\s*DROP\s+TABLE)"),
    ],
    "xss": [
        re.compile(r"(?i)<\s*script[^>]*>"),
        re.compile(r"(?i)javascript:\s*"),
        re.compile(r"(?i)onerror\s*=|onload\s*="),
    ],
    "path_traversal": [
        re.compile(r"(\.\./|\.\\\\|%2e%2e%2f|%2e%2e/)"),
    ],
    "file_inclusion": [
        re.compile(r"(?i)(\bfile\b\s*=\s*|\b(include|require)(_once)?\b|php://|https?://)"),
    ],
    "command_injection": [
        re.compile(r"(?i)(;|&&|\|\||\|)\s*(cat|ls|whoami|curl|wget|bash|sh|cmd|powershell)\b"),
    ],
    "xxe": [
        re.compile(r"(?is)(<!DOCTYPE\s+[^>]+\[.*<!ENTITY\s+[^>]+>.*\]>)"),
        re.compile(r"(?is)(SYSTEM\s+\"(file|https?)://)"),
    ],
}

RISK_SCORES = {
    "sql_injection": 9,
    "xss": 8,
    "csrf": 7,
    "path_traversal": 8,
    "file_inclusion": 9,
    "command_injection": 9,
    "xxe": 10,
    "rate_limit": 6,
    "blacklist": 10,
}
