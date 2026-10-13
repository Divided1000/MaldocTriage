"""Analyzer for OOXML (zip-based Office) documents.

Covers: VBA macros, remote template injection, DDE auto-exec fields, external
and remote relationships, embedded OLE objects, and ActiveX controls.
"""

from __future__ import annotations

import re
import zipfile
from io import BytesIO
from typing import List

from ..models import Finding, Report, Severity
from .base import Analyzer

# Max uncompressed bytes we will read from any single part (zip-bomb guard).
_MAX_PART_BYTES = 32 * 1024 * 1024

# External relationship targets that point off-document. TargetMode="External".
_EXTERNAL_REL_RE = re.compile(rb'TargetMode\s*=\s*"External"', re.IGNORECASE)
_REL_TARGET_RE = re.compile(rb'Target\s*=\s*"([^"]+)"', re.IGNORECASE)
_REL_TYPE_RE = re.compile(rb'Type\s*=\s*"([^"]+)"', re.IGNORECASE)

# Relationship types that are dangerous when combined with an external target.
_TEMPLATE_REL = b"attachedTemplate"
_OLEOBJECT_REL = b"oleObject"
_FRAME_RELS = (b"frame", b"subDocument")

# DDE markers inside document XML.
_DDE_RE = re.compile(rb"\bDDEAUTO\b|\bDDE\b", re.IGNORECASE)
_FIELD_INSTR_RE = re.compile(rb"w:fldSimple|w:instrText", re.IGNORECASE)


class OOXMLAnalyzer(Analyzer):
    file_type = "ooxml"

    def analyze(self, data: bytes, report: Report) -> None:
        try:
            zf = zipfile.ZipFile(BytesIO(data))
        except (zipfile.BadZipFile, OSError) as exc:
            report.add_error(f"ooxml: cannot open zip: {exc}")
            return

        with zf:
            names = zf.namelist()
            self._check_macros(zf, names, report)
            self._check_relationships(zf, names, report)
            self._check_dde(zf, names, report)
            self._check_embedded(names, report)

            # IOC sweep over text-bearing parts only (xml, rels, bin).
            for name in names:
                if name.endswith((".xml", ".rels", ".bin", ".vml")):
                    payload = self._read(zf, name)
                    if payload:
                        self.sweep_iocs(payload, report)

    # -- helpers -----------------------------------------------------------

    def _read(self, zf: zipfile.ZipFile, name: str) -> bytes:
        try:
            info = zf.getinfo(name)
        except KeyError:
            return b""
        if info.file_size > _MAX_PART_BYTES:
            return b""
        try:
            with zf.open(name) as fh:
                return fh.read(_MAX_PART_BYTES)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return b""

    def _check_macros(self, zf, names: List[str], report: Report) -> None:
        macro_parts = [n for n in names if n.lower().endswith("vbaproject.bin")]
        if not macro_parts:
            return
        report.add(
            Finding(
                id="ooxml.vba_macro",
                title="VBA macro project present",
                severity=Severity.HIGH,
                detail=(
                    "The document carries a vbaProject.bin, meaning it contains "
                    "VBA macro code. Macros are a primary malware delivery "
                    "mechanism. Inspect the macro source in an isolated "
                    "environment."
                ),
                location=macro_parts[0],
                evidence={"parts": macro_parts},
            )
        )
        # Macro-enabled content type but file extension may hide it.
        for part in macro_parts:
            blob = self._read(zf, part)
            if b"AutoOpen" in blob or b"Document_Open" in blob or b"Auto_Open" in blob:
                report.add(
                    Finding(
                        id="ooxml.vba_autoexec",
                        title="VBA auto-execution keyword in macro stream",
                        severity=Severity.CRITICAL,
                        detail=(
                            "An auto-execution entry point (AutoOpen / "
                            "Document_Open / Auto_Open) was found, so the macro "
                            "runs automatically when the document is opened."
                        ),
                        location=part,
                    )
                )
                break

    def _check_relationships(self, zf, names: List[str], report: Report) -> None:
        rels = [n for n in names if n.endswith(".rels")]
        for rel in rels:
            blob = self._read(zf, rel)
            if not blob:
                continue
            # Walk each Relationship element so type/target/mode stay paired.
            for element in re.findall(rb"<Relationship\b[^>]*?/?>", blob):
                target_m = _REL_TARGET_RE.search(element)
                type_m = _REL_TYPE_RE.search(element)
                is_external = bool(_EXTERNAL_REL_RE.search(element))
                target = target_m.group(1) if target_m else b""
                rtype = type_m.group(1) if type_m else b""

                if _TEMPLATE_REL in rtype and (
                    is_external or target.lower().startswith((b"http", b"\\\\", b"ftp", b"mhtml"))
                ):
                    report.add(
                        Finding(
                            id="ooxml.template_injection",
                            title="Remote template injection reference",
                            severity=Severity.CRITICAL,
                            detail=(
                                "An attachedTemplate relationship points to an "
                                "external location. On open, Word fetches and "
                                "loads the remote template, a well-known "
                                "payload-delivery and credential-theft "
                                "technique."
                            ),
                            location=rel,
                            evidence={"target": target.decode("latin-1", "ignore")},
                        )
                    )
                elif is_external and target.lower().startswith((b"http", b"ftp", b"\\\\", b"mhtml")):
                    report.add(
                        Finding(
                            id="ooxml.external_relationship",
                            title="External relationship target",
                            severity=Severity.MEDIUM,
                            detail=(
                                "A relationship references an external/remote "
                                "resource. This can be used for tracking, "
                                "template loading, or remote content fetches."
                            ),
                            location=rel,
                            evidence={
                                "target": target.decode("latin-1", "ignore"),
                                "type": rtype.decode("latin-1", "ignore"),
                            },
                        )
                    )

                if _OLEOBJECT_REL in rtype:
                    report.add(
                        Finding(
                            id="ooxml.ole_relationship",
                            title="Embedded OLE object relationship",
                            severity=Severity.MEDIUM,
                            detail=(
                                "The document references an embedded OLE object. "
                                "OLE objects can host executables, scripts, or "
                                "exploit payloads (e.g. Equation Editor)."
                            ),
                            location=rel,
                        )
                    )

    def _check_dde(self, zf, names: List[str], report: Report) -> None:
        doc_parts = [
            n for n in names
            if n.endswith(".xml") and ("document" in n or "worksheet" in n or n.startswith("word/"))
        ]
        for part in doc_parts:
            blob = self._read(zf, part)
            if not blob:
                continue
            if _DDE_RE.search(blob) and _FIELD_INSTR_RE.search(blob):
                report.add(
                    Finding(
                        id="ooxml.dde",
                        title="DDE / DDEAUTO field instruction",
                        severity=Severity.HIGH,
                        detail=(
                            "A DDE field instruction was found. DDE can launch "
                            "external programs (e.g. cmd.exe/powershell) without "
                            "a macro and is a known code-execution vector."
                        ),
                        location=part,
                    )
                )
                break

    def _check_embedded(self, names: List[str], report: Report) -> None:
        embedded = [n for n in names if "embeddings/" in n.lower()]
        if embedded:
            report.add(
                Finding(
                    id="ooxml.embedded_object",
                    title="Embedded object part(s) present",
                    severity=Severity.LOW,
                    detail=(
                        "The archive contains embedded object parts. These may "
                        "hold OLE packages, scripts, or executables."
                    ),
                    evidence={"parts": embedded[:20], "count": len(embedded)},
                )
            )
        activex = [n for n in names if "activex" in n.lower()]
        if activex:
            report.add(
                Finding(
                    id="ooxml.activex",
                    title="ActiveX control(s) present",
                    severity=Severity.MEDIUM,
                    detail=(
                        "ActiveX controls can be abused to trigger code "
                        "execution or load additional components."
                    ),
                    evidence={"parts": activex[:20], "count": len(activex)},
                )
            )
