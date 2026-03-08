import pytest
from baml_client.sync_client import b

from classifyagent.models import PayloadItem
from classifyagent.service import ClassificationService


def test_service_returns_classifications_from_baml(monkeypatch) -> None:
    payload = [
        PayloadItem(
            name="customer_email",
            description="Email for account communication",
            samples=["alice@example.com"],
        ),
        PayloadItem(
            name="marketing_banner_copy",
            description="Homepage hero message",
            samples=["Save 20% this week"],
        ),
    ]

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
                    rationale="Contains direct contact information.",
                    confidence=0.98,
                ),
                ItemClassification(
                    name="marketing_banner_copy",
                    classification="public",
                    rationale="Promotional content intended for publication.",
                    confidence=0.95,
                ),
            ]

    def fake_classify_payload_items(payload, policy_context):
        assert payload[0]["name"] == "customer_email"
        assert policy_context
        return Response()

    monkeypatch.setattr(b, "ClassifyPayloadItems", fake_classify_payload_items)

    service = ClassificationService()
    result = service.run(payload)

    assert len(result.classifications) == 2
    assert result.classifications[0].name == "customer_email"
    assert result.classifications[0].classification == "confidential"
    assert result.classifications[1].classification == "public"


def test_service_propagates_underlying_baml_error(monkeypatch) -> None:
    def fake_classify_payload_items(payload, policy_context):
        raise ValueError("invalid x-api-key")

    monkeypatch.setattr(b, "ClassifyPayloadItems", fake_classify_payload_items)

    service = ClassificationService()

    with pytest.raises(ValueError, match="invalid x-api-key"):
        service.run([PayloadItem(name="email", description="", samples=["a@b.com"])])
