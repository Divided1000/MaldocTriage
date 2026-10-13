"""Core data models and risk scoring for MaldocTriage."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    """Severity of a single finding. Higher means more suspicious.

    The integer value doubles as the base scoring weight contributed by a
    finding of that severity.
    """

    INFO = 0
    LOW = 3
    MEDIUM = 10
    HIGH = 25
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        return cls[label.strip().upper()]


# Risk bands keyed by the inclusive lower bound of the total score.
RISK_BANDS = [
    (50, "critical"),
    (25, "high"),
    (10, "medium"),
    (1, "low"),
    (0, "clean"),
]

# Ordering helper so callers can compare risk bands.
RISK_ORDER = ["clean", "low", "medium", "high", "critical"]


def score_to_band(score: int) -> str:
    """Map a numeric score to a named risk band."""
    for threshold, band in RISK_BANDS:
        if score >= threshold:
            return band
    return "clean"


def band_rank(band: str) -> int:
    """Return the ordinal rank of a risk band (clean=0 .. critical=4)."""
    try:
        return RISK_ORDER.index(band)
    except ValueError:
        return 0


@dataclass
class Finding:
    """A single suspicious indicator discovered in a document."""

    # Short machine-readable id, e.g. "ooxml.vba_macro".
    id: str
    # One-line human description of what was found.
    title: str
    severity: Severity
    # Longer explanation / why it matters.
    detail: str = ""
    # Where in the file it was found (stream, object id, part name...).
    location: Optional[str] = None
    # Arbitrary supporting evidence (counts, decoded snippets, keywords).
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def weight(self) -> int:
        return int(self.severity)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "weight": self.weight,
            "detail": self.detail,
            "location": self.location,
            "evidence": self.evidence,
        }


@dataclass
class Report:
    """Aggregated triage result for a single file."""

    path: str
    file_type: str = "unknown"
    size: int = 0
    sha256: str = ""
    findings: List[Finding] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    @property
    def score(self) -> int:
        """Total risk score.

        Findings of the same id are counted with diminishing returns so that a
        document with 500 URLs does not swamp the score, but repeated distinct
        indicators still accumulate.
        """
        from collections import Counter

        counts: Counter = Counter()
        total = 0
        for finding in self.findings:
            n = counts[finding.id]
            # First occurrence full weight; subsequent occurrences decay.
            multiplier = 1.0 if n == 0 else max(0.25, 1.0 / (n + 1))
            total += finding.weight * multiplier
            counts[finding.id] += 1
        return int(round(total))

    @property
    def risk(self) -> str:
        return score_to_band(self.score)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "file_type": self.file_type,
            "size": self.size,
            "sha256": self.sha256,
            "score": self.score,
            "risk": self.risk,
            "findings": [f.to_dict() for f in self.findings],
            "iocs": self.iocs,
            "errors": self.errors,
        }
