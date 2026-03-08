from __future__ import annotations

from baml_client.sync_client import b  # type: ignore
from classifyagent.models import ClassificationEntry, PayloadItem


def classify_payload_with_agent(payload: list[PayloadItem]) -> list[ClassificationEntry]:
    if not payload:
        return []


    response = b.ClassifyPayloadItems(
        payload=[item.model_dump() for item in payload],
        policy_context=(
            "Classify each item by combining field semantics (name/description) and sample values. "
            "Use public, private, confidential, or highly-confidential."
        ),
    )

    return [
        ClassificationEntry(
            name=item.name,
            classification=item.classification,
            rationale=item.rationale,
            confidence=item.confidence,
        )
        for item in response.classifications
    ]
