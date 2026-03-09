from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

class RunConfig(BaseModel):
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    return_matches: bool = True


class RunRequest(BaseModel):
    data: Any = Field(default_factory=dict)
    config: RunConfig | None = None


class PiiMatch(BaseModel):
    path: str
    types: list[str]
    confidence: float | None = None
    reason: str = ""


class PiiTypeCount(BaseModel):
    type: str
    count: int


class RunResult(BaseModel):
    fields_scanned: int
    fields_matched: int
    types: list[PiiTypeCount]
    matches: list[PiiMatch] | None = None
