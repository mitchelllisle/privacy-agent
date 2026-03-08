from fastapi.testclient import TestClient

from classifyagent.app import app
from baml_client.sync_client import b


def test_run_endpoint_returns_classifications(monkeypatch) -> None:
    class ItemClassification:
        def __init__(self, name: str, classification: str, rationale: str, confidence: float) -> None:
            self.name = name
            self.classification = classification
            self.rationale = rationale
            self.confidence = confidence

    class Response:
        def __init__(self) -> None:
            self.classifications = [
                ItemClassification(
                    name="customer_email",
                    classification="confidential",
                    rationale="Contains email samples.",
                    confidence=0.97,
                )
            ]

    def fake_classify_payload_items(payload, policy_context):
        assert payload[0]["name"] == "customer_email"
        return Response()

    monkeypatch.setattr(b, "ClassifyPayloadItems", fake_classify_payload_items)

    client = TestClient(app)
    response = client.post(
        "/run",
        json={
            "payload": [
                {
                    "name": "customer_email",
                    "description": "Email for account communication",
                    "samples": ["alice@example.com"],
                }
            ]
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["classifications"][0]["name"] == "customer_email"
    assert body["classifications"][0]["classification"] == "confidential"


def test_run_endpoint_returns_502_with_real_error(monkeypatch) -> None:
    def fake_classify_payload_items(payload, policy_context):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(b, "ClassifyPayloadItems", fake_classify_payload_items)

    client = TestClient(app)
    response = client.post(
        "/run",
        json={"payload": [{"name": "x", "description": "", "samples": ["sample"]}]},
    )

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert "RuntimeError" in detail
    assert "model unavailable" in detail
