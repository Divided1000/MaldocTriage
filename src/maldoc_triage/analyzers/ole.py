"""Analyzer for legacy OLE2 compound file documents (.doc/.xls/.ppt).

Covers: VBA macro streams, auto-exec keywords, embedded OLE packages,
Equation Editor objects (CVE-2017-11882 / CVE-2018-0802 lure), and Flash objects.
"""

from __future__ import annotations

from typing import List

from .. import olecf
from ..models import Finding, Report, Severity
from .base import Analyzer

# Auto-execution macro entry points.
_AUTOEXEC_KEYWORDS = (
    b"AutoOpen", b"Auto_Open", b"AutoClose", b"Auto_Close", b"AutoExec",
    b"Document_Open", b"Document_Close", b"Workbook_Open", b"Auto_Exec",
)

# Suspicious API strings commonly seen in weaponized macros / shellcode stubs.
_SUSPICIOUS_APIS = (
    b"Shell", b"WScript.Shell", b"powershell", b"cmd.exe", b"CreateObject",
    b"URLDownloadToFile", b"WinHttp", b"MSXML2", b"ADODB.Stream",
    b"VirtualAlloc", b"CallWindowProc", b"GetObject",
)


class OLEAnalyzer(Analyzer):
    file_type = "ole"

    def analyze(self, data: bytes, report: Report) -> None:
        try:
            ole = olecf.parse(data)
        except olecf.OLEError as exc:
            report.add_error(f"ole: cannot parse compound file: {exc}")
            # Even if structural parse fails, still sweep raw bytes for IOCs.
            self.sweep_iocs(data, report)
            return

        streams = ole.list_streams()
        entries = ole.list_entries()
        lower = [s.lower() for s in streams]

        report.add(
            Finding(
                id="ole.compound_file",
                title="OLE2 compound file",
                severity=Severity.INFO,
                detail="Legacy OLE2 structured-storage document.",
                evidence={"stream_count": len(streams)},
            )
        )

        self._check_macros(ole, streams, lower, report)
        self._check_embedded(entries, report)

        # IOC sweep across all stream contents.
        for name in streams:
            try:
                blob = ole.read_stream(name)
            except olecf.OLEError:
                continue
            self.sweep_iocs(blob, report)

    # -- helpers -----------------------------------------------------------

    def _check_macros(self, ole, streams: List[str], lower: List[str], report: Report) -> None:
        has_vba = any("vba" in n for n in lower)
        macro_streams = [s for s, l in zip(streams, lower) if "vba" in l]
        if has_vba:
            report.add(
                Finding(
                    id="ole.vba_macro",
                    title="VBA macro storage present",
                    severity=Severity.HIGH,
                    detail=(
                        "A VBA storage/stream was found inside the compound "
                        "file. The document contains macro code; review it in "
                        "isolation."
                    ),
                    evidence={"streams": macro_streams[:20]},
                )
            )

        # Scan streams for auto-exec and suspicious API strings. We prefer
        # macro/VBA-named streams but also inspect sibling module streams when
        # a VBA project is present, since module names are arbitrary.
        candidates = streams if has_vba else [
            s for s in streams if "vba" in s.lower() or "macro" in s.lower()
        ]
        for name in candidates:
            try:
                blob = ole.read_stream(name)
            except olecf.OLEError:
                continue
            auto_hits = sorted({k.decode() for k in _AUTOEXEC_KEYWORDS if k in blob})
            if auto_hits:
                report.add(
                    Finding(
                        id="ole.vba_autoexec",
                        title="VBA auto-execution keyword",
                        severity=Severity.CRITICAL,
                        detail=(
                            "Auto-execution entry point(s) found in a macro "
                            "stream; the macro runs on open/close without user "
                            "interaction."
                        ),
                        location=name,
                        evidence={"keywords": auto_hits},
                    )
                )
            api_hits = sorted({k.decode(errors="ignore") for k in _SUSPICIOUS_APIS if k in blob})
            if api_hits:
                report.add(
                    Finding(
                        id="ole.suspicious_api",
                        title="Suspicious API string in macro stream",
                        severity=Severity.HIGH,
                        detail=(
                            "Macro references APIs frequently abused for "
                            "download/exec or process launching."
                        ),
                        location=name,
                        evidence={"apis": api_hits},
                    )
                )

    def _check_embedded(self, entries: List[str], report: Report) -> None:
        lower = [e.lower() for e in entries]

        if any("equation" in e or "\x01ole10native" in e for e in lower):
            report.add(
                Finding(
                    id="ole.equation_editor",
                    title="Equation Editor / OLE10Native object",
                    severity=Severity.HIGH,
                    detail=(
                        "An Equation Editor or Ole10Native object was found. "
                        "These are classic exploit carriers (e.g. "
                        "CVE-2017-11882) and native-payload packagers."
                    ),
                    evidence={
                        "entries": [e for e in entries if "equation" in e.lower()
                                    or "ole10native" in e.lower()][:10]
                    },
                )
            )

        if any("package" in e for e in lower):
            report.add(
                Finding(
                    id="ole.embedded_package",
                    title="Embedded OLE package",
                    severity=Severity.MEDIUM,
                    detail=(
                        "An OLE Package object can embed and drop an arbitrary "
                        "file (script/executable) onto disk."
                    ),
                )
            )

        if any("contents" in e and "flash" in e for e in lower) or any("shockwave" in e for e in lower):
            report.add(
                Finding(
                    id="ole.flash_object",
                    title="Embedded Flash/Shockwave object",
                    severity=Severity.MEDIUM,
                    detail="Embedded Flash objects have been used to deliver exploits.",
                )
            )
