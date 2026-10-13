"""Analyzer for RTF documents.

RTF has no macros, but it is a heavy exploit/OLE carrier. We look for embedded
OLE objects (\\object, \\objdata), auto-update triggers (\\objupdate), Equation
Editor class names, and signs of hex obfuscation. Embedded OLE hex blobs are
decoded (statically) so IOC extraction can see inside them.
"""

from __future__ import annotations

import binascii
import re
from typing import List

from ..models import Finding, Report, Severity
from .base import Analyzer

_OBJDATA_RE = re.compile(rb"\\objdata\b", re.IGNORECASE)
_OBJECT_RE = re.compile(rb"\\object\b", re.IGNORECASE)
_OBJUPDATE_RE = re.compile(rb"\\objupdate\b", re.IGNORECASE)
_OBJCLASS_RE = re.compile(rb"\\objclass\s+([^\s{}\\]+)", re.IGNORECASE)
_DATASTORE_RE = re.compile(rb"\\datastore\b", re.IGNORECASE)

# Grab a run of hex that follows an \objdata control word.
_HEXBLOB_RE = re.compile(rb"\\objdata\b[^{}]*?([0-9A-Fa-f\s]{64,})", re.IGNORECASE)

_EQUATION_MARKERS = (b"Equation.3", b"Equation.2", b"Equation Native", b"OLE10Native")


class RTFAnalyzer(Analyzer):
    file_type = "rtf"

    def analyze(self, data: bytes, report: Report) -> None:
        report.add(
            Finding(
                id="rtf.document",
                title="RTF document",
                severity=Severity.INFO,
                detail="Parsed as RTF; static control-word scan performed.",
            )
        )

        has_object = bool(_OBJECT_RE.search(data))
        has_objdata = bool(_OBJDATA_RE.search(data))

        if has_object or has_objdata:
            report.add(
                Finding(
                    id="rtf.embedded_object",
                    title="Embedded OLE object",
                    severity=Severity.HIGH,
                    detail=(
                        "RTF embeds an OLE object (\\object/\\objdata). RTF is a "
                        "common exploit and payload carrier; the object may hold "
                        "an executable, script, or exploit."
                    ),
                )
            )

        if _OBJUPDATE_RE.search(data):
            report.add(
                Finding(
                    id="rtf.objupdate",
                    title="Auto-updating OLE object (\\objupdate)",
                    severity=Severity.CRITICAL,
                    detail=(
                        "\\objupdate forces the embedded object to update/load "
                        "automatically when the document opens, removing the "
                        "need for user interaction."
                    ),
                )
            )

        # Equation Editor / Ole10Native class names (common exploit carriers).
        classes = [m.decode("latin-1", "ignore") for m in _OBJCLASS_RE.findall(data)]
        decoded_blobs = self._decode_objdata(data)
        combined = data + b"\n".join(decoded_blobs)
        if any(marker in combined for marker in _EQUATION_MARKERS) or \
                any("equation" in c.lower() for c in classes):
            report.add(
                Finding(
                    id="rtf.equation_editor",
                    title="Equation Editor / native OLE object",
                    severity=Severity.HIGH,
                    detail=(
                        "An Equation Editor or Ole10Native object was found, a "
                        "classic exploit carrier (e.g. CVE-2017-11882)."
                    ),
                    evidence={"objclass": classes[:10]} if classes else {},
                )
            )

        if _DATASTORE_RE.search(data):
            report.add(
                Finding(
                    id="rtf.datastore",
                    title="\\datastore control word",
                    severity=Severity.MEDIUM,
                    detail=(
                        "\\datastore has been abused (e.g. CVE-2018-8570-era "
                        "lures) to smuggle object data past parsers."
                    ),
                )
            )

        self._check_obfuscation(data, report)

        # IOC sweep over both raw RTF and any decoded OLE blobs.
        self.sweep_iocs(data, report)
        for blob in decoded_blobs:
            self.sweep_iocs(blob, report)

    # -- helpers -----------------------------------------------------------

    def _decode_objdata(self, data: bytes) -> List[bytes]:
        """Statically hex-decode \\objdata blobs so IOCs inside are visible."""
        blobs: List[bytes] = []
        for match in _HEXBLOB_RE.finditer(data):
            hexdata = re.sub(rb"[^0-9A-Fa-f]", b"", match.group(1))
            if len(hexdata) % 2:
                hexdata = hexdata[:-1]
            try:
                blobs.append(binascii.unhexlify(hexdata))
            except (binascii.Error, ValueError):
                continue
        return blobs

    def _check_obfuscation(self, data: bytes, report: Report) -> None:
        # RTF obfuscation: lots of control words interleaved in hex object data,
        # or embedded whitespace/garbage control words within objdata.
        objdata_match = _HEXBLOB_RE.search(data)
        if objdata_match:
            segment = objdata_match.group(1)
            whitespace = sum(1 for b in segment if b in b" \t\r\n")
            if whitespace > len(segment) * 0.15 and len(segment) > 256:
                report.add(
                    Finding(
                        id="rtf.obfuscated_objdata",
                        title="Obfuscated OLE object data",
                        severity=Severity.MEDIUM,
                        detail=(
                            "The embedded hex object data is heavily "
                            "interspersed with whitespace/control words, a "
                            "known RTF anti-analysis technique."
                        ),
                    )
                )
