import sys
import types

from fastapi.testclient import TestClient

from privacyagent.app import app


def test_run_endpoint_returns_pii_matches(monkeypatch) -> None:
    class Match:
        def __init__(self, path: str, value: str, types: list[str]) -> None:
            self.path = path
            self.value = value
            self.types = types
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
    assert payload["fields_matched"] == 2
    assert payload["types"] == [
        {"type": "email", "count": 1},
        {"type": "phone_number", "count": 1},
    ]
    assert len(payload["matches"]) == 2
    assert "types" in payload["matches"][0]
    assert "pii_types" not in payload["matches"][0]
    assert "value" not in payload["matches"][0]


def test_run_endpoint_applies_threshold_filter(monkeypatch) -> None:
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
                Match("$.email", ["email"], 0.98, "Strong email signal"),
                Match("$.dob", ["date_of_birth"], 0.60, "Weak context"),
            ]

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
    assert payload["fields_matched"] == 1
    assert payload["types"] == [{"type": "email", "count": 1}]
    assert payload["matches"][0]["path"] == "$.email"


def test_run_endpoint_omits_matches_when_configured(monkeypatch) -> None:
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
                Match("$.ip", ["ipv4_address"], 0.92, "Pattern and key match"),
            ]

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
    assert payload["fields_matched"] == 2
    assert payload["types"] == [
        {"type": "email", "count": 1},
        {"type": "ipv4_address", "count": 1},
    ]
    assert "matches" not in payload


def test_run_endpoint_returns_502_with_real_error(monkeypatch) -> None:
    class FakeB:
        @staticmethod
        def DetectPIIWithContext(context: str, system_instructions: str):
            raise ValueError("invalid x-api-key")

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
