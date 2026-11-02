"""Shared immutable data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TokenKind(str, Enum):
    """Lexical token categories, including trivia so source can be preserved."""

    IDENTIFIER = "identifier"
    KEYWORD = "keyword"
    NUMBER = "number"
    STRING = "string"
    SYMBOL = "symbol"
    WHITESPACE = "whitespace"
    COMMENT = "comment"


@dataclass(frozen=True, slots=True)
class Token:
    """A source token with exact character offsets and line/column metadata."""

    kind: TokenKind
    value: str
    raw: str
    start: int
    end: int
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class Finding:
    """A fingerprint or structural observation about the input."""

    name: str
    confidence: float
    evidence: tuple[str, ...] = ()
    details: str = ""


@dataclass(frozen=True, slots=True)
class TransformEvent:
    """An auditable transformation performed by the pipeline."""

    stage: str
    description: str
    count: int = 1
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AnalysisReport:
    """Machine-readable analysis and transformation summary."""

    source_name: str
    source_bytes: int
    detected_encodings: str
    findings: list[Finding] = field(default_factory=list)
    events: list[TransformEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    layers_processed: int = 0
    syntax_structure_valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report using JSON-compatible primitives."""
        return {
            "source_name": self.source_name,
            "source_bytes": self.source_bytes,
            "detected_encodings": self.detected_encodings,
            "findings": [asdict(item) for item in self.findings],
            "events": [asdict(item) for item in self.events],
            "warnings": list(self.warnings),
            "layers_processed": self.layers_processed,
            "syntax_structure_valid": self.syntax_structure_valid,
        }
