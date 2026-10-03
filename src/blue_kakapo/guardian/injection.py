"""Untrusted-content handling: prompt-injection detection, output-handling guards, and the Rule of Two.

All alert/log/intel/tool content is untrusted DATA. These helpers (a) flag likely injection attempts
so they can be quarantined/logged (we design for blast-radius, not perfect prevention — LLM01/ASI01/
ASI06), (b) catch unsafe model output before it is rendered/executed (LLM10), and (c) enforce the
**Rule of Two**: an agent must not simultaneously (1) handle untrusted input, (2) hold sensitive
access, and (3) be able to change external state. Break at least one leg.
"""

from __future__ import annotations

import re
import unicodedata

# Common Latin-lookalikes (Cyrillic/Greek) + zero-width chars, so a homoglyph-obfuscated keyword
# ("rаnsоmware" with Cyrillic а/о) can't slip past the keyword/injection scanners. Not exhaustive —
# defense-in-depth, honestly: a determined attacker can still use rarer confusables or synonyms.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "с": "c",
        "р": "p",
        "х": "x",
        "у": "y",
        "ѕ": "s",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "һ": "h",
        "ԛ": "q",
        "ԝ": "w",
        "ɡ": "g",
        "ⅼ": "l",
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "ε": "e",
        "ν": "v",
        "τ": "t",
        "ι": "i",
        "κ": "k",
        "​": "",
        "‌": "",
        "‍": "",
        "﻿": "",
        " ": " ",
    }
)


def fold_confusables(text: str) -> str:
    """NFKC-normalize, casefold, map common Latin-lookalikes to ASCII, and drop zero-width chars.

    Casefold runs **before** the translate so uppercase homoglyphs (e.g. Cyrillic ``Ѕ``/``І``) fold to
    their lowercase forms, which the map then converts. The scan paths are case-insensitive, so folding
    case here is safe."""
    return unicodedata.normalize("NFKC", text).casefold().translate(_CONFUSABLES)


_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(the\s+)?(above|previous|system)",
    r"you\s+are\s+now\s+",
    r"system\s+prompt",
    r"reveal\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)",
    r"\bexfiltrat",
    r"do\s+anything\s+now|\bDAN\b",
    r"override\s+(your\s+)?(guardrails|safety|policy)",
    r"print\s+your\s+(instructions|system\s+prompt)",
    r"</?(system|instructions)>",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

# Output that should never be rendered/executed unescaped (LLM10 improper output handling).
_UNSAFE_OUTPUT_RE = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"\bon(error|load|click)\s*=", re.IGNORECASE),
    re.compile(r"\$\([^)]*\)"),  # shell/command substitution
    re.compile(r"`[^`]+`"),  # backtick command substitution
]


def scan_injection(text: str) -> list[str]:
    """Return the injection patterns that matched (empty = clean). Confusable-folded first."""
    folded = fold_confusables(text)
    return [
        p.pattern
        for p, raw in zip(_INJECTION_RE, _INJECTION_PATTERNS, strict=True)
        if p.search(folded)
    ]


def contains_injection(text: str) -> bool:
    return any(p.search(fold_confusables(text)) for p in _INJECTION_RE)


def contains_unsafe_output(text: str) -> bool:
    """True if model output contains markup/command patterns unsafe to render or execute."""
    return any(p.search(text) for p in _UNSAFE_OUTPUT_RE)


def as_untrusted(label: str, content: str) -> str:
    """Wrap external content so a prompt presents it unmistakably as data, not instructions."""
    return f"<untrusted source={label!r}>\n{content}\n</untrusted>"


def rule_of_two_ok(
    *, untrusted_input: bool, sensitive_access: bool, external_state_change: bool
) -> bool:
    """True iff fewer than all three legs are present (at least one is broken)."""
    return sum((untrusted_input, sensitive_access, external_state_change)) < 3
