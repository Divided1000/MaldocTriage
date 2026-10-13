"""Minimal, read-only OLE2 Compound File parser (stdlib-only).

This parser enumerates the directory entries and reads individual streams. It is
intentionally conservative: on any structural anomaly it raises OLEError rather
than guessing, and it caps the amount of data it will follow to avoid resource
exhaustion from malformed/hostile files. It never executes anything.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional

_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_MAXREGSECT = 0xFFFFFFFA

_MAX_SECTORS = 1_000_000  # guard against absurd sector counts


class OLEError(Exception):
    """Raised when the stream is not a valid/parseable OLE2 file."""


class DirEntry:
    __slots__ = ("name", "entry_type", "start_sector", "size", "index")

    def __init__(self, name: str, entry_type: int, start_sector: int, size: int, index: int):
        self.name = name
        self.entry_type = entry_type  # 0 empty, 1 storage, 2 stream, 5 root
        self.start_sector = start_sector
        self.size = size
        self.index = index

    @property
    def is_stream(self) -> bool:
        return self.entry_type == 2

    @property
    def is_storage(self) -> bool:
        return self.entry_type in (1, 5)


class OleFile:
    """A parsed OLE2 compound file."""

    def __init__(self, data: bytes):
        self._data = data
        self.entries: List[DirEntry] = []
        self._parse()

    # -- public API --------------------------------------------------------

    def list_streams(self) -> List[str]:
        return [e.name for e in self.entries if e.is_stream]

    def list_entries(self) -> List[str]:
        return [e.name for e in self.entries if e.entry_type != 0]

    def read_stream(self, name: str, max_bytes: int = 8 * 1024 * 1024) -> bytes:
        for entry in self.entries:
            if entry.is_stream and entry.name == name:
                return self._read_entry(entry, max_bytes)
        raise OLEError(f"stream not found: {name}")

    # -- parsing -----------------------------------------------------------

    def _parse(self) -> None:
        d = self._data
        if len(d) < 512 or d[:8] != _SIGNATURE:
            raise OLEError("not an OLE2 compound file")

        (self.sector_shift,) = struct.unpack_from("<H", d, 30)
        (self.mini_sector_shift,) = struct.unpack_from("<H", d, 32)
        self.sector_size = 1 << self.sector_shift
        self.mini_sector_size = 1 << self.mini_sector_shift
        if self.sector_size not in (512, 4096):
            raise OLEError(f"unexpected sector size {self.sector_size}")

        (self.num_fat_sectors,) = struct.unpack_from("<I", d, 44)
        (self.dir_start,) = struct.unpack_from("<I", d, 48)
        (self.mini_cutoff,) = struct.unpack_from("<I", d, 56)
        (self.minifat_start,) = struct.unpack_from("<I", d, 60)
        (self.num_minifat_sectors,) = struct.unpack_from("<I", d, 64)
        (self.difat_start,) = struct.unpack_from("<I", d, 68)
        (self.num_difat_sectors,) = struct.unpack_from("<I", d, 72)

        self._difat = self._read_difat()
        self._fat = self._read_fat()
        self._dir_sectors = self._follow_chain(self.dir_start)
        self._read_directory()
        self._minifat = self._read_minifat()
        self._mini_stream = self._read_mini_stream()

    def _sector_offset(self, sector: int) -> int:
        return 512 + sector * self.sector_size

    def _read_sector(self, sector: int) -> bytes:
        off = self._sector_offset(sector)
        chunk = self._data[off:off + self.sector_size]
        if len(chunk) < self.sector_size:
            # Pad truncated final sector so chain-walking stays bounded.
            chunk = chunk + b"\x00" * (self.sector_size - len(chunk))
        return chunk

    def _read_difat(self) -> List[int]:
        difat: List[int] = list(struct.unpack_from("<109I", self._data, 76))
        sector = self.difat_start
        guard = 0
        while sector not in (_ENDOFCHAIN, _FREESECT) and sector <= _MAXREGSECT:
            guard += 1
            if guard > _MAX_SECTORS:
                raise OLEError("DIFAT chain too long")
            block = self._read_sector(sector)
            values = struct.unpack_from(f"<{self.sector_size // 4}I", block)
            difat.extend(values[:-1])
            sector = values[-1]
        return [s for s in difat if s <= _MAXREGSECT]

    def _read_fat(self) -> List[int]:
        fat: List[int] = []
        per = self.sector_size // 4
        for fat_sector in self._difat[: self.num_fat_sectors or len(self._difat)]:
            block = self._read_sector(fat_sector)
            fat.extend(struct.unpack_from(f"<{per}I", block))
            if len(fat) > _MAX_SECTORS:
                raise OLEError("FAT too large")
        return fat

    def _follow_chain(self, start: int) -> List[int]:
        chain: List[int] = []
        sector = start
        guard = 0
        while sector not in (_ENDOFCHAIN, _FREESECT) and sector <= _MAXREGSECT:
            chain.append(sector)
            guard += 1
            if guard > _MAX_SECTORS:
                raise OLEError("sector chain too long")
            if sector >= len(self._fat):
                break
            sector = self._fat[sector]
        return chain

    def _read_chain_bytes(self, start: int) -> bytes:
        return b"".join(self._read_sector(s) for s in self._follow_chain(start))

    def _read_directory(self) -> None:
        raw = b"".join(self._read_sector(s) for s in self._dir_sectors)
        entry_size = 128
        for i in range(0, len(raw), entry_size):
            entry = raw[i:i + entry_size]
            if len(entry) < entry_size:
                break
            (name_len,) = struct.unpack_from("<H", entry, 64)
            entry_type = entry[66]
            if entry_type == 0:  # unused
                continue
            name_len = max(0, min(name_len, 64))
            name = entry[: name_len].decode("utf-16-le", "ignore").rstrip("\x00")
            (start_sector,) = struct.unpack_from("<I", entry, 116)
            (size_low,) = struct.unpack_from("<I", entry, 120)
            (size_high,) = struct.unpack_from("<I", entry, 124)
            size = size_low | (size_high << 32)
            self.entries.append(
                DirEntry(name, entry_type, start_sector, size, len(self.entries))
            )

    def _read_minifat(self) -> List[int]:
        if self.minifat_start in (_ENDOFCHAIN, _FREESECT):
            return []
        raw = self._read_chain_bytes(self.minifat_start)
        count = len(raw) // 4
        return list(struct.unpack_from(f"<{count}I", raw)) if count else []

    def _read_mini_stream(self) -> bytes:
        root = next((e for e in self.entries if e.entry_type == 5), None)
        if root is None or root.size == 0:
            return b""
        return self._read_chain_bytes(root.start_sector)[: root.size]

    def _read_mini_chain(self, start: int, size: int) -> bytes:
        out = bytearray()
        sector = start
        guard = 0
        while sector not in (_ENDOFCHAIN, _FREESECT) and sector <= _MAXREGSECT:
            off = sector * self.mini_sector_size
            out += self._mini_stream[off:off + self.mini_sector_size]
            guard += 1
            if guard > _MAX_SECTORS or sector >= len(self._minifat):
                break
            sector = self._minifat[sector]
        return bytes(out[:size])

    def _read_entry(self, entry: DirEntry, max_bytes: int) -> bytes:
        size = min(entry.size, max_bytes)
        if entry.size < self.mini_cutoff:
            return self._read_mini_chain(entry.start_sector, size)
        return self._read_chain_bytes(entry.start_sector)[:size]


def parse(data: bytes) -> OleFile:
    return OleFile(data)
