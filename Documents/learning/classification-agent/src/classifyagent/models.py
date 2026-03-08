from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ClassificationLevel = Literal[
    "public",
    "private",
    "confidential",
    "highly-confidential",
]


class PayloadItem(BaseModel):
    name: str = Field(min_length=1)
    description: str = ""
    samples: list[str] = Field(default_factory=list)


class RunRequest(BaseModel):
    payload: list[PayloadItem] = Field(default_factory=list)


class ClassificationEntry(BaseModel):
    name: str
    classification: ClassificationLevel
    rationale: str = ""
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class RunResult(BaseModel):
    classifications: list[ClassificationEntry]
