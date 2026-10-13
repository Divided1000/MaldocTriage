"""Analyzer for PDF documents.

Static keyword/structure scan. We count occurrences of risk-bearing PDF names,
accounting for the common hex-escape obfuscation (e.g. /J#61vaScript) that
authors use to hide markers from naive scanners. Nothing is rendered or
executed.
"""

from __future__ import annotations

import re
from typing import Dict

from ..models import Finding, Report, Severity
from .base import Analyzer


def _deobfuscate_names(data: bytes) -> bytes:
    """Resolve #hh hex escapes inside PDF name tokens so markers are visible."""

    def repl(match: "re.Match[bytes]") -> bytes:
        try:
            return bytes([int(match.group(1), 16)])
        except ValueError:
            return match.group(0)

    return re.sub(rb"#([0-9A-Fa-f]{2})", repl, data)


# marker -> (finding id, title, severity, detail)
_MARKERS: Dict[bytes, tuple] = {
    b"/JavaScript": (
        "pdf.javascript", "JavaScript present", Severity.HIGH,
        "The PDF embeds JavaScript. PDF JS is used for exploitation, "
        "heap-spray setup, and dropper logic.",
    ),
    b"/JS": (
        "pdf.javascript", "JavaScript (/JS) present", Severity.HIGH,
        "A /JS action references embedded JavaScript.",
    ),
    b"/OpenAction": (
        "pdf.openaction", "Automatic OpenAction", Severity.HIGH,
        "An /OpenAction runs automatically when the document is opened, a "
        "common auto-exec trigger.",
    ),
    b"/AA": (
        "pdf.additional_action", "Additional action (/AA)", Severity.MEDIUM,
        "Additional-actions dictionaries fire on events (open, page, "
        "field) and can auto-trigger code.",
    ),
    b"/Launch": (
        "pdf.launch", "Launch action", Severity.CRITICAL,
        "A /Launch action can start an external program or command. This is "
        "a direct code-execution vector.",
    ),
    b"/EmbeddedFile": (
        "pdf.embedded_file", "Embedded file", Severity.MEDIUM,
        "The PDF carries an embedded file that can be extracted and run.",
    ),
    b"/URI": (
        "pdf.uri", "URI action", Severity.LOW,
        "A /URI action references an external URL (phishing / remote "
        "content).",
    ),
    b"/SubmitForm": (
        "pdf.submitform", "SubmitForm action", Severity.MEDIUM,
        "A /SubmitForm action can exfiltrate form/field data to a remote URL.",
    ),
    b"/RichMedia": (
        "pdf.richmedia", "RichMedia / embedded Flash", Severity.MEDIUM,
        "RichMedia annotations embed Flash/3D content historically abused for "
        "exploits.",
    ),
    b"/XFA": (
        "pdf.xfa", "XFA forms present", Severity.LOW,
        "XFA forms embed XML form logic that can host script.",
    ),
}


class PDFAnalyzer(Analyzer):
    file_type = "pdf"

    def analyze(self, data: bytes, report: Report) -> None:
        clean = _deobfuscate_names(data)

        report.add(
            Finding(
                id="pdf.document",
                title="PDF document",
                severity=Severity.INFO,
                detail="Parsed as a PDF; keyword scan performed statically.",
                evidence={"version": self._pdf_version(data)},
            )
        )

        for marker, (fid, title, severity, detail) in _MARKERS.items():
            count = clean.count(marker)
            if count:
                report.add(
                    Finding(
                        id=fid,
                        title=title,
                        severity=severity,
                        detail=detail,
                        evidence={"marker": marker.decode(), "count": count},
                    )
                )

        self._check_obfuscation(data, clean, report)
        self._check_encryption(clean, report)
        self.sweep_iocs(data, report)

    # -- helpers -----------------------------------------------------------

    def _pdf_version(self, data: bytes) -> str:
        m = re.search(rb"%PDF-(\d+\.\d+)", data[:1024])
        return m.group(1).decode() if m else "unknown"

    def _check_obfuscation(self, raw: bytes, clean: bytes, report: Report) -> None:
        # If deobfuscation changed risk markers, hex-escaping was used to hide them.
        if raw != clean:
            revealed = [
                m.decode() for m in _MARKERS
                if clean.count(m) > raw.count(m)
            ]
            if revealed:
                report.add(
                    Finding(
                        id="pdf.name_obfuscation",
                        title="Hex-escaped name obfuscation",
                        severity=Severity.MEDIUM,
                        detail=(
                            "Risk-bearing PDF names were hidden using #hh hex "
                            "escapes, a technique used to evade naive scanners."
                        ),
                        evidence={"revealed": sorted(set(revealed))},
                    )
                )

        # Many object streams / heavy filtering can indicate packing.
        if clean.count(b"/ObjStm") > 0 and clean.count(b"/JavaScript") == 0 and clean.count(b"/JS") == 0:
            # ObjStm alone is normal; only note it, do not score heavily.
            pass

    def _check_encryption(self, data: bytes, report: Report) -> None:
        if b"/Encrypt" in data:
            report.add(
                Finding(
                    id="pdf.encrypted",
                    title="Encrypted PDF",
                    severity=Severity.LOW,
                    detail=(
                        "The PDF is encrypted. Encryption can hinder static "
                        "analysis and is sometimes used to evade detection."
                    ),
                )
            )
