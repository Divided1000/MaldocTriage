"""Analyzer base class."""

from __future__ import annotations

from ..iocs import extract_all
from ..models import Report


class Analyzer:
    """Base class for all format analyzers.

    Subclasses implement :meth:`analyze`, adding findings to the supplied
    report. Analyzers must be strictly static: read and parse bytes only, never
    execute, deflate-bomb-protect, or reach out to the network.
    """

    #: filetype constant this analyzer handles (overridden by subclasses).
    file_type = "unknown"

    def analyze(self, data: bytes, report: Report) -> None:
        raise NotImplementedError

    def sweep_iocs(self, data: bytes, report: Report) -> None:
        """Merge IOC extraction results into the report (order-preserving)."""
        found = extract_all(data)
        for kind, values in found.items():
            bucket = report.iocs.setdefault(kind, [])
            for value in values:
                if value not in bucket:
                    bucket.append(value)
