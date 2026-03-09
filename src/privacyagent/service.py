from __future__ import annotations

from collections import Counter
from typing import Any

from privacyagent.analyzer import analyze_pii_with_agent
from privacyagent.models import PiiMatch, PiiTypeCount, RunResult


class PrivacyService:
    def run(
        self,
        data: Any,
        threshold: float | None = None,
        return_matches: bool = True,
    ) -> RunResult:
        matches, fields_scanned = analyze_pii_with_agent(data)

        if threshold is not None:
            matches = [
                match
                for match in matches
                if match.confidence is not None and match.confidence >= threshold
            ]

        pii_type_counts = Counter(
            pii_type
            for match in matches
            for pii_type in match.pii_types
        )

        if not pii_type_counts:
            return RunResult(
                fields_scanned=fields_scanned,
                pii_values=0,
                classification="private",
                types=[],
                matches=[] if return_matches else None,
            )

        from baml_client.sync_client import b  # type: ignore

        detected_types = sorted(pii_type_counts.keys())
        classification_response = b.ClassifyDetectedTypes(
            detected_types=detected_types,
            policy_context=(
                "Use private for non-sensitive internal-only values, confidential for standard PII, "
                "and highly-confidential for government ID and highly sensitive identity data."
            ),
        )

        per_type_classification: dict[str, str] = {}
        response_types = getattr(classification_response, "types", [])
        for entry in response_types:
            type_name = str(getattr(entry, "type", "")).strip()
            cls = str(getattr(entry, "classification", "")).strip()
            if type_name and cls:
                per_type_classification[type_name] = cls

        level_rank = {
            "private": 0,
            "confidential": 1,
            "highly-confidential": 2,
        }

        def pick_highest(levels: list[str]) -> str:
            filtered = [lvl for lvl in levels if lvl in level_rank]
            if not filtered:
                return "confidential"
            return max(filtered, key=lambda lvl: level_rank[lvl])

        classified_matches = [
            match.model_copy(
                update={
                    "classification": pick_highest(
                        [per_type_classification.get(t, "confidential") for t in match.pii_types]
                    )
                }
            )
            for match in matches
        ]
        top_level_classification = str(
            getattr(classification_response, "classification", "private")
        )

        return RunResult(
            fields_scanned=fields_scanned,
            pii_values=len(classified_matches),
            classification=top_level_classification,
            types=[
                PiiTypeCount(
                    type=pii_type,
                    classification=per_type_classification.get(pii_type, "confidential"),
                    count=count,
                )
                for pii_type, count in sorted(pii_type_counts.items())
            ],
            matches=list(classified_matches) if return_matches else None,
        )
