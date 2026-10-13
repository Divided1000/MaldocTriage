"""Content-based file type detection.

Detection relies on magic bytes and structure, not on the file extension, so a
renamed `.docm` saved as `invoice.pdf` is still classified correctly.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO

# Canonical type identifiers used throughout the analyzers.
OOXML = "ooxml"          # Zip-based Office Open XML (docx/xlsx/pptx + macro variants)
OLE = "ole"              # Legacy OLE2 compound file (doc/xls/ppt)
PDF = "pdf"
RTF = "rtf"
ZIP = "zip"              # Generic zip that is not recognizable Office OOXML
UNKNOWN = "unknown"

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def detect(data: bytes) -> str:
    """Classify a document from its content."""
    if not data:
        return UNKNOWN

    # RTF and PDF may be preceded by a UTF-8 BOM or whitespace.
    head = data[:1024].lstrip(b"\xef\xbb\xbf \t\r\n")

    if head.startswith(b"{\\rtf"):
        return RTF

    # PDF signature can legitimately appear a few hundred bytes in.
    if b"%PDF-" in data[:1024]:
        return PDF

    if data.startswith(_OLE_MAGIC):
        return OLE

    if data.startswith(_ZIP_MAGIC):
        return _classify_zip(data)

    return UNKNOWN


def _classify_zip(data: bytes) -> str:
    """Distinguish OOXML from a plain zip by inspecting the archive layout."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError, struct.error):
        return ZIP

    # OOXML always carries a [Content_Types].xml at the root.
    if "[Content_Types].xml" in names:
        return OOXML
    # Fallback: presence of the standard Office part directories.
    if any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
        return OOXML
    return ZIP


def is_office_family(ftype: str) -> bool:
    return ftype in (OOXML, OLE)
