from __future__ import annotations

"""Pydantic request/response models for the privacy agent API."""

from typing import Any

from pydantic import BaseModel, Field

class RunConfig(BaseModel):
    """Optional runtime controls for a detection request.

    Attributes:
        threshold: Minimum confidence required for a match to be returned.
        return_matches: Whether to include detailed match entries in response.
        review: Whether to run the reviewer agent to validate detections.
    """
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    return_matches: bool = True
    review: bool = False


class RunRequest(BaseModel):
    """Top-level API request payload.

    Attributes:
        data: Arbitrary JSON-like payload to scan for PII.
        config: Optional runtime options for this request.
    """
    data: Any = Field(default_factory=dict)
    config: RunConfig | None = None


class PiiMatch(BaseModel):
    """Single detected PII match.

    Attributes:
        path: JSONPath-like location of the matched value.
        types: One or more detected PII types for the value.
        confidence: Optional model confidence in the detection.
        reason: Optional short explanation for the detection.
    """
    path: str
    types: list[str]
    confidence: float | None = None
    reason: str = ""


class ReviewedMatch(BaseModel):
    """Reviewer verdict for a single detected PII match.

    Attributes:
        path: JSONPath-like location of the original match.
        types: PII types that were under review.
        is_valid: Whether the reviewer considers the detection a true positive.
        confidence: Reviewer's confidence in its verdict.
        reason: Brief explanation for the verdict.
    """
    path: str
    types: list[str]
    is_valid: bool
    confidence: float | None = None
    reason: str = ""


class PiiTypeCount(BaseModel):
    """Aggregate count for a detected PII type.

    Attributes:
        type: PII type identifier.
        count: Number of matched fields for this type.
    """
    type: str
    count: int


class RunResult(BaseModel):
    """API response for a detection run.

    Attributes:
        fields_scanned: Number of candidate fields evaluated.
        fields_matched: Number of fields returned as PII matches.
        types: Per-type aggregate match counts.
        matches: Optional detailed match records.
        review: Optional reviewer verdicts for each detected match.
    """
    fields_scanned: int
    fields_matched: int
    types: list[PiiTypeCount]
    matches: list[PiiMatch] | None = None
    review: list[ReviewedMatch] | None = None
