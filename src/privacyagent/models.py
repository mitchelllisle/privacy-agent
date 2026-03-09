from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ClassificationLevel = Literal["private", "confidential", "highly-confidential"]


class RunConfig(BaseModel):
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    return_matches: bool = True


class RunRequest(BaseModel):
    data: Any = Field(default_factory=dict)
    config: RunConfig | None = None


class PiiMatch(BaseModel):
    path: str
    pii_types: list[str]
    classification: ClassificationLevel = "confidential"
    confidence: float | None = None
    reason: str = ""


class PiiTypeCount(BaseModel):
    type: str
    classification: ClassificationLevel
    count: int


class RunResult(BaseModel):
    fields_scanned: int
    pii_values: int
    classification: ClassificationLevel
    types: list[PiiTypeCount]
    matches: list[PiiMatch] | None = None
