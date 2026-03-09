from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
US_SSN_RE = re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b")
DOB_RE = re.compile(r"\b(?:19|20)\d\d[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _valid_ipv4(text: str) -> bool:
    for candidate in IPV4_RE.findall(text):
        octets = candidate.split(".")
        if all(int(octet) <= 255 for octet in octets):
            return True
    return False


def _passes_luhn(number: str) -> bool:
    total = 0
    reverse_digits = number[::-1]
    for index, char in enumerate(reverse_digits):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _contains_credit_card(text: str) -> bool:
    candidates = re.findall(r"(?:\d[ -]?){13,19}", text)
    for candidate in candidates:
        digits = _digits_only(candidate)
        if 13 <= len(digits) <= 19 and _passes_luhn(digits):
            return True
    return False


def _contains_phone(text: str) -> bool:
    candidates = re.findall(r"\+?[\d(). -]{10,}", text)
    for candidate in candidates:
        digits = _digits_only(candidate)
        if 10 <= len(digits) <= 15:
            return True
    return False


def detect_pii_types(value: str) -> list[str]:
    if not value:
        return []

    detected: list[str] = []
    if EMAIL_RE.search(value):
        detected.append("email")
    if US_SSN_RE.search(value):
        detected.append("us_ssn")
    if DOB_RE.search(value):
        detected.append("date_of_birth")
    if _valid_ipv4(value):
        detected.append("ipv4_address")
    if _contains_phone(value):
        detected.append("phone_number")
    if _contains_credit_card(value):
        detected.append("credit_card")

    return detected
