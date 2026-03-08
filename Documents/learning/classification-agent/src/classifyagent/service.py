from __future__ import annotations

from classifyagent.classifier import classify_payload_with_agent
from classifyagent.models import PayloadItem, RunResult


class ClassificationService:
    def run(self, payload: list[PayloadItem]) -> RunResult:
        classifications = classify_payload_with_agent(payload)
        return RunResult(classifications=classifications)
