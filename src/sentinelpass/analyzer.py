"""Explainable password assessment. This is a heuristic, not a crack-time guarantee."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.json")
COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "qwerty", "qwerty123",
    "letmein", "admin", "welcome", "iloveyou", "abc123", "passw0rd",
}
SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    """Load policy JSON and validate its supported settings."""
    policy_path = Path(path) if path else DEFAULT_POLICY_PATH
    with policy_path.open("r", encoding="utf-8") as handle:
        policy = json.load(handle)
    required = {
        "minimum_length", "recommended_length", "require_uppercase",
        "require_lowercase", "require_digit", "require_symbol",
        "max_repeated_run", "score_thresholds",
    }
    missing = required - policy.keys()
    if missing:
        raise ValueError(f"Policy is missing keys: {', '.join(sorted(missing))}")
    if not (1 <= int(policy["minimum_length"]) <= int(policy["recommended_length"])):
        raise ValueError("Length settings must satisfy 1 <= minimum_length <= recommended_length.")
    thresholds = policy["score_thresholds"]
    if not (0 <= int(thresholds["moderate"]) < int(thresholds["strong"]) <= 100):
        raise ValueError("Score thresholds must satisfy 0 <= moderate < strong <= 100.")
    if int(policy["max_repeated_run"]) < 2:
        raise ValueError("max_repeated_run must be at least 2.")
    return policy


def _has_sequence(password: str, minimum: int = 3) -> bool:
    candidate = password.lower()
    for sequence in SEQUENCES:
        for i in range(len(sequence) - minimum + 1):
            chunk = sequence[i:i + minimum]
            if chunk in candidate or chunk[::-1] in candidate:
                return True
    return False


def _longest_repeated_run(password: str) -> int:
    longest = current = 0
    previous = None
    for char in password:
        current = current + 1 if char == previous else 1
        longest = max(longest, current)
        previous = char
    return longest


def _character_pool(password: str) -> int:
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() and not c.isspace() for c in password):
        pool += 33
    if any(c.isspace() for c in password):
        pool += 1
    return pool


def analyze_password(password: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a transparent heuristic assessment without retaining the password."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    policy = policy or load_policy()
    if not password:
        return {
            "score": 0, "category": "Weak", "length": 0,
            "estimated_entropy_bits": 0.0, "checks": {},
            "findings": ["Password is empty."],
            "recommendations": ["Use a unique password or passphrase."],
            "disclaimer": "Heuristic estimate only; not a guarantee of resistance to cracking.",
        }

    checks = {
        "minimum_length": len(password) >= int(policy["minimum_length"]),
        "recommended_length": len(password) >= int(policy["recommended_length"]),
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() and not c.isspace() for c in password),
        "not_common": password.casefold() not in COMMON_PASSWORDS,
        "no_obvious_sequence": not _has_sequence(password),
        "no_long_repeated_run": _longest_repeated_run(password) < int(policy["max_repeated_run"]),
    }

    # A simple explainable rubric, not a calibrated probability of cracking.
    score = min(35, len(password) * 2)
    score += 15 if checks["lowercase"] else 0
    score += 15 if checks["uppercase"] else 0
    score += 15 if checks["digit"] else 0
    score += 15 if checks["symbol"] else 0
    score += 10 if checks["recommended_length"] else 0
    score -= 30 if not checks["not_common"] else 0
    score -= 10 if not checks["no_obvious_sequence"] else 0
    score -= 10 if not checks["no_long_repeated_run"] else 0
    score = max(0, min(100, score))

    thresholds = policy["score_thresholds"]
    category = "Weak" if score < int(thresholds["moderate"]) else (
        "Moderate" if score < int(thresholds["strong"]) else "Strong"
    )

    findings: list[str] = []
    if not checks["minimum_length"]:
        findings.append(f"Below the configured minimum of {policy['minimum_length']} characters.")
    elif not checks["recommended_length"]:
        findings.append(f"Meets the minimum; consider {policy['recommended_length']} or more characters.")
    else:
        findings.append("Meets the recommended length.")
    for key, label in (
        ("lowercase", "lowercase letters"),
        ("uppercase", "uppercase letters"),
        ("digit", "digits"),
        ("symbol", "symbols"),
    ):
        if not checks[key]:
            findings.append(f"Missing {label}.")
    if not checks["not_common"]:
        findings.append("Matches a common password in the built-in demonstration list.")
    if not checks["no_obvious_sequence"]:
        findings.append("Contains an obvious sequence or keyboard-row pattern.")
    if not checks["no_long_repeated_run"]:
        findings.append("Contains a long repeated-character run.")

    recommendations = []
    if not checks["recommended_length"]:
        recommendations.append(f"Use at least {policy['recommended_length']} characters; a long unique passphrase can help.")
    if not checks["not_common"]:
        recommendations.append("Avoid common passwords and predictable substitutions.")
    if not checks["no_obvious_sequence"]:
        recommendations.append("Avoid keyboard rows, alphabet runs, and number sequences.")
    if not checks["no_long_repeated_run"]:
        recommendations.append("Avoid repeated-character runs.")
    if not recommendations:
        recommendations.append("Keep it unique to this account and store it in a reputable password manager.")

    pool = _character_pool(password)
    entropy = round(len(password) * math.log2(pool), 1) if pool > 1 else 0.0
    return {
        "score": score,
        "category": category,
        "length": len(password),
        "estimated_entropy_bits": entropy,
        "checks": checks,
        "findings": findings,
        "recommendations": recommendations,
        "disclaimer": "Heuristic estimate only; not a guarantee of resistance to cracking. Entropy assumes random character selection, which human-chosen passwords often do not have.",
    }
