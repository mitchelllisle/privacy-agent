import sys
import types

from fastapi.testclient import TestClient

from privacyagent.app import app


def _classification_result(entries: list[tuple[str, str]], top: str = "confidential"):
    class ClassifiedType:
        def __init__(self, type: str, classification: str) -> None:
            self.type = type
            self.classification = classification

    class ClassificationResult:
        def __init__(self) -> None:
            self.classification = top
            self.types = [ClassifiedType(type=t, classification=c) for t, c in entries]

    return ClassificationResult()


def test_run_endpoint_returns_pii_matches(monkeypatch) -> None:
    class Match:
        def __init__(self, path: str, value: str, pii_types: list[str]) -> None:
            self.path = path
            self.value = value
            self.pii_types = pii_types
            self.confidence = 0.97
            self.reason = "PII pattern match."

    class Response:
        def __init__(self) -> None:
            self.matches = [
                Match("$.email", "alice@example.com", ["email"]),
                Match("$.nested.phone", "+1 415 555 0101", ["phone_number"]),
            ]

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str) -> Response:
            assert "$.email: alice@example.com" in context
            assert system_instructions
            return Response()

        @staticmethod
        def ClassifyDetectedTypes(detected_types, policy_context):
            return _classification_result(
                [("email", "confidential"), ("phone_number", "confidential")],
                top="confidential",
            )

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")
    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    client = TestClient(app)
    response = client.post(
        "/run",
        json={
            "data": {
                "email": "alice@example.com",
                "nested": {"phone": "+1 415 555 0101"},
            }
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["pii_values"] == 2
    assert payload["classification"] == "confidential"
    assert payload["types"] == [
        {"type": "email", "classification": "confidential", "count": 1},
        {"type": "phone_number", "classification": "confidential", "count": 1},
    ]
    assert len(payload["matches"]) == 2
    assert "value" not in payload["matches"][0]


def test_run_endpoint_applies_threshold_filter(monkeypatch) -> None:
    class Match:
        def __init__(self, path: str, pii_types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.pii_types = pii_types
            self.confidence = confidence
            self.reason = reason

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            return [
                Match("$.email", ["email"], 0.98, "Strong email signal"),
                Match("$.dob", ["date_of_birth"], 0.60, "Weak context"),
            ]

        @staticmethod
        def ClassifyDetectedTypes(detected_types, policy_context):
            return _classification_result(
                [("email", "confidential"), ("date_of_birth", "confidential")],
                top="confidential",
            )

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")
    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    client = TestClient(app)
    response = client.post(
        "/run",
        json={
            "data": {"email": "alice@example.com", "dob": "2000-01-01"},
            "config": {"threshold": 0.9},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["pii_values"] == 1
    assert payload["classification"] == "confidential"
    assert payload["types"] == [{"type": "email", "classification": "confidential", "count": 1}]
    assert payload["matches"][0]["path"] == "$.email"


def test_run_endpoint_omits_matches_when_configured(monkeypatch) -> None:
    class Match:
        def __init__(self, path: str, pii_types: list[str], confidence: float, reason: str) -> None:
            self.path = path
            self.pii_types = pii_types
            self.confidence = confidence
            self.reason = reason

    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            return [
                Match("$.email", ["email"], 0.97, "Strong signal"),
                Match("$.ip", ["ipv4_address"], 0.92, "Pattern and key match"),
            ]

        @staticmethod
        def ClassifyDetectedTypes(detected_types, policy_context):
            return _classification_result(
                [("email", "confidential"), ("ipv4_address", "confidential")],
                top="confidential",
            )

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")
    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    client = TestClient(app)
    response = client.post(
        "/run",
        json={
            "data": {"email": "alice@example.com", "ip": "10.0.0.1"},
            "config": {"return_matches": False},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["pii_values"] == 2
    assert payload["classification"] == "confidential"
    assert payload["types"] == [
        {"type": "email", "classification": "confidential", "count": 1},
        {"type": "ipv4_address", "classification": "confidential", "count": 1},
    ]
    assert "matches" not in payload


def test_run_endpoint_returns_502_with_real_error(monkeypatch) -> None:
    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            raise ValueError("invalid x-api-key")

        @staticmethod
        def ClassifyDetectedTypes(detected_types, policy_context):
            return _classification_result([], top="private")

    fake_sync = types.SimpleNamespace(b=FakeB())
    fake_pkg = types.ModuleType("baml_client")
    monkeypatch.setitem(sys.modules, "baml_client", fake_pkg)
    monkeypatch.setitem(sys.modules, "baml_client.sync_client", fake_sync)

    client = TestClient(app)
    response = client.post("/run", json={"data": {"email": "alice@example.com"}})

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert "ValueError" in detail
    assert "invalid x-api-key" in detail
