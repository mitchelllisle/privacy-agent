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
            for pii_type in match.types
        )

        if not pii_type_counts:
            return RunResult(
                fields_scanned=fields_scanned,
                fields_matched=0,
                types=[],
                matches=[] if return_matches else None,
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
        )
