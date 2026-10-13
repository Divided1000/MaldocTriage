"""MaldocTriage - static-only triage for suspicious documents."""

__version__ = "0.1.0"

from .models import Finding, Report, Severity

__all__ = ["Finding", "Report", "Severity", "__version__"]
