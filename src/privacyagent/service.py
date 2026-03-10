from __future__ import annotations

"""Service layer that orchestrates analysis and result aggregation."""

from collections import Counter
from typing import Any

from privacyagent.analyzer import analyze_pii_with_agent, review_pii_detections
from privacyagent.models import PiiMatch, PiiTypeCount, RunResult


class PrivacyService:
    """Use the analyzer to detect PII and build API response models."""

    def run(
        self,
        data: Any,
        threshold: float | None = None,
        return_matches: bool = True,
        review: bool = False,
    ) -> RunResult:
        """Run PII detection and aggregate output counts.

        Args:
            data: Arbitrary JSON-like payload to inspect.
            threshold: Optional confidence cutoff applied to matches.
            return_matches: Whether to include detailed match records.
            review: Whether to run the reviewer agent to validate detections.

        Returns:
            A `RunResult` containing counts, optional detailed matches, and optional review verdicts.
        """
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
            for pii_type in match.types
        )

        reviewed = review_pii_detections(matches, data) if review else None

        if not pii_type_counts:
            return RunResult(
                fields_scanned=fields_scanned,
                fields_matched=0,
                types=[],
                matches=[] if return_matches else None,
                review=reviewed,
            )

        return RunResult(
            fields_scanned=fields_scanned,
            fields_matched=len(matches),
            types=[
                PiiTypeCount(
                    type=pii_type,
                    count=count,
                )
                for pii_type, count in sorted(pii_type_counts.items())
            ],
            matches=list(matches) if return_matches else None,
            review=reviewed,
        )
