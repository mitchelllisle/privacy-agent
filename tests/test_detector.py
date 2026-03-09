from privacyagent.detector import detect_pii_types


def test_detects_email() -> None:
    pii = detect_pii_types("Contact me at jane@example.com")
    assert "email" in pii


def test_detects_phone_and_ssn() -> None:
    pii = detect_pii_types("Call +1 (415) 555-0101, SSN 123-45-6789")
    assert "phone_number" in pii
    assert "us_ssn" in pii


def test_detects_credit_card() -> None:
    pii = detect_pii_types("Payment card 4242 4242 4242 4242")
    assert "credit_card" in pii


def test_ignores_plain_text() -> None:
    pii = detect_pii_types("No sensitive content here")
    assert pii == []
