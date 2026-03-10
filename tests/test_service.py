import sys
import types

import pytest

from privacyagent.service import PrivacyService


def test_service_scans_nested_payload_and_returns_matches_with_baml(monkeypatch) -> None:
    payload = {
        "user": {
            "name": "Jane Doe",
            "email": "jane@example.com",
            "phones": ["+1 415 555 0101", "no-phone"],
        },
        "payment": {"card": "4242 4242 4242 4242"},
        "metadata": {"attempt": 1},
    }

    class Match:
        def __init__(self, path: str, value: str, types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.value = value
            self.types = types
            self.confidence = confidence
            self.reason = reason

    class Response:
        def __init__(self) -> None:
            self.matches = [
                Match("$.user.email", "jane@example.com", ["email"], 0.99, "Contains an email address."),
                Match("$.user.phones[0]", "+1 415 555 0101", ["phone_number"], 0.95, "Contains a phone number."),
                Match("$.payment.card", "4242 4242 4242 4242", ["credit_card"], 0.98, "Passes card pattern checks."),
            ]

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str) -> Response:
            assert "$.user.email: jane@example.com" in context
            assert system_instructions
            return Response()

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")
    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    service = PrivacyService()
    result = service.run(payload)

    assert result.fields_scanned >= 5
    assert result.fields_matched == 3
    assert {item.type: item.count for item in result.types} == {
        "credit_card": 1,
        "email": 1,
        "phone_number": 1,
    }

    matched_paths = {m.path for m in result.matches}
    assert "$.user.email" in matched_paths
    assert "$.user.phones[0]" in matched_paths
    assert "$.payment.card" in matched_paths
    assert not hasattr(result.matches[0], "value")


def test_service_propagates_underlying_baml_error(monkeypatch) -> None:
    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            raise ValueError("invalid x-api-key")

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")
    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    service = PrivacyService()

    with pytest.raises(ValueError, match="invalid x-api-key"):
        service.run({"email": "jane@example.com"})


def test_service_uses_baml_agent_when_available(monkeypatch) -> None:
    payload = {
        "email": "agent@example.com",
        "card": "4242 4242 4242 4242",
    }

    class Match:
        def __init__(self, path: str, value: str, types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.value = value
            self.types = types
            self.confidence = confidence
            self.reason = reason

    class Response:
        def __init__(self) -> None:
            self.matches = [
                Match(
                    path="$.email",
                    value="agent@example.com",
                    types=["email"],
                    confidence=0.99,
                    reason="Matches canonical email pattern.",
                )
            ]

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str) -> Response:
            assert "$.email: agent@example.com" in context
            assert system_instructions
            return Response()

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")

    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    service = PrivacyService()
    result = service.run(payload)

    assert result.fields_matched == 1
    assert result.matches[0].path == "$.email"
    assert result.types[0].type == "email"
    assert result.types[0].count == 1


def test_service_omits_matches_when_configured(monkeypatch) -> None:
    payload = {"email": "agent@example.com", "ip": "10.0.0.1"}

    class Match:
        def __init__(self, path: str, types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.types = types
            self.confidence = confidence
            self.reason = reason

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            return [
                Match("$.email", ["email"], 0.97, "Strong signal"),
                Match("$.ip", ["ipv4_address"], 0.91, "Strong signal"),
            ]

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")

    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    service = PrivacyService()
    result = service.run(payload, return_matches=False)

    assert result.matches is None
    assert result.fields_matched == 2
    assert {item.type: item.count for item in result.types} == {
        "email": 1,
        "ipv4_address": 1,
    }


def test_service_applies_threshold_filter(monkeypatch) -> None:
    payload = {
        "email": "agent@example.com",
        "dob": "2000-01-01",
    }

    class Match:
        def __init__(self, path: str, types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.types = types
            self.confidence = confidence
            self.reason = reason

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            return [
                Match("$.email", ["email"], 0.97, "Strong signal"),
                Match("$.dob", ["date_of_birth"], 0.55, "Weak context"),
            ]

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")

    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    service = PrivacyService()
    result = service.run(payload, threshold=0.9)

    assert result.fields_matched == 1
    assert result.matches[0].path == "$.email"


def test_service_runs_reviewer_when_requested(monkeypatch) -> None:
    payload = {
        "email": "agent@example.com",
        "ip": "10.0.0.1",
    }

    class Match:
        def __init__(self, path: str, types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.types = types
            self.confidence = confidence
            self.reason = reason

    class ReviewResult:
        def __init__(self, path: str, types: list[str], is_valid: bool, confidence: float, reason: str) -> None:
            self.path = path
            self.types = types
            self.is_valid = is_valid
            self.confidence = confidence
            self.reason = reason

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            return [
                Match("$.email", ["email"], 0.97, "Strong signal"),
                Match("$.ip", ["ipv4_address"], 0.91, "Pattern and key match"),
            ]

        @staticmethod
        def ReviewPIIDetection(detections: str, context: str):
            assert "$.email" in detections
            assert "$.ip" in detections
            return [
                ReviewResult("$.email", ["email"], True, 0.98, "Valid email address."),
                ReviewResult("$.ip", ["ipv4_address"], True, 0.95, "Valid IPv4 address."),
            ]

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")

    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    service = PrivacyService()
    result = service.run(payload, review=True)

    assert result.review is not None
    assert len(result.review) == 2
    reviewed_paths = {r.path for r in result.review}
    assert "$.email" in reviewed_paths
    assert "$.ip" in reviewed_paths
    assert all(r.is_valid for r in result.review)


def test_service_does_not_run_reviewer_by_default(monkeypatch) -> None:
    payload = {"email": "agent@example.com"}

    class Match:
        def __init__(self, path: str, types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.types = types
            self.confidence = confidence
            self.reason = reason

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            return [Match("$.email", ["email"], 0.97, "Strong signal")]

        @staticmethod
        def ReviewPIIDetection(detections: str, context: str):
            raise AssertionError("reviewer should not be called")

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")

    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    service = PrivacyService()
    result = service.run(payload)

    assert result.review is None
