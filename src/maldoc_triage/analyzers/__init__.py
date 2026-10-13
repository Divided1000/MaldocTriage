"""Per-format document analyzers."""

from .base import Analyzer
from .ooxml import OOXMLAnalyzer
from .ole import OLEAnalyzer
from .pdf import PDFAnalyzer
from .rtf import RTFAnalyzer

# Analyzers keyed by the filetype constant they handle.
ANALYZERS = {
    "ooxml": OOXMLAnalyzer,
    "ole": OLEAnalyzer,
    "pdf": PDFAnalyzer,
    "rtf": RTFAnalyzer,
}

__all__ = [
    "Analyzer",
    "OOXMLAnalyzer",
    "OLEAnalyzer",
    "PDFAnalyzer",
    "RTFAnalyzer",
    "ANALYZERS",
]
