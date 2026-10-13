"""Scan orchestration: read a file, detect its type, run the right analyzer."""

from __future__ import annotations

import hashlib
import os
from typing import Iterable, Iterator, List

from . import filetype
from .analyzers import ANALYZERS
from .models import Finding, Report, Severity

# Hard ceiling on how much of a file we load into memory.
_MAX_FILE_BYTES = 256 * 1024 * 1024


def scan_bytes(data: bytes, path: str = "<bytes>") -> Report:
    """Triage an in-memory document."""
    report = Report(path=path, size=len(data))
    report.sha256 = hashlib.sha256(data).hexdigest()

    ftype = filetype.detect(data)
    report.file_type = ftype

    analyzer_cls = ANALYZERS.get(ftype)
    if analyzer_cls is None:
        report.add(
            Finding(
                id="core.unsupported_type",
                title="Unsupported or unrecognized file type",
                severity=Severity.INFO,
                detail=(
                    "No format-specific analyzer matched. Only an IOC sweep was "
                    "performed. The file may be benign, corrupt, or a type "
                    "MaldocTriage does not yet support."
                ),
                evidence={"detected": ftype},
            )
        )
        # Still provide value: sweep for IOCs.
        from .iocs import extract_all
        for kind, values in extract_all(data).items():
            report.iocs[kind] = values
        return report

    try:
        analyzer_cls().analyze(data, report)
    except Exception as exc:  # analyzers must be robust; never crash the scan
        report.add_error(f"{ftype}: analyzer error: {exc!r}")

    return report


def scan_file(path: str) -> Report:
    """Triage a document on disk."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        report = Report(path=path)
        report.add_error(f"cannot stat file: {exc}")
        return report

    if size > _MAX_FILE_BYTES:
        report = Report(path=path, size=size)
        report.add_error(
            f"file too large to scan ({size} bytes > {_MAX_FILE_BYTES} limit)"
        )
        return report

    try:
        with open(path, "rb") as fh:
            data = fh.read(_MAX_FILE_BYTES)
    except OSError as exc:
        report = Report(path=path, size=size)
        report.add_error(f"cannot read file: {exc}")
        return report

    return scan_bytes(data, path=path)


def iter_target_files(paths: Iterable[str], recursive: bool = False) -> Iterator[str]:
    """Expand input paths into concrete files (optionally recursing dirs)."""
    for path in paths:
        if os.path.isdir(path):
            if recursive:
                for root, _dirs, files in os.walk(path):
                    for name in sorted(files):
                        yield os.path.join(root, name)
            else:
                for name in sorted(os.listdir(path)):
                    full = os.path.join(path, name)
                    if os.path.isfile(full):
                        yield full
        else:
            yield path


def scan_paths(paths: Iterable[str], recursive: bool = False) -> List[Report]:
    return [scan_file(p) for p in iter_target_files(paths, recursive=recursive)]
