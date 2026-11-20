"""Read a NumPy .npy header and detect an object dtype. The array is not loaded."""

import ast
import struct
from dataclasses import dataclass
from typing import Any

_MAGIC = b"\x93NUMPY"


@dataclass
class NpyHeader:
    error: str | None = None
    descr: Any = None
    is_object: bool = False
    version: tuple[int, int] | None = None
    data_offset: int | None = None


def descr_is_object(descr: Any) -> bool:
    """True when a NumPy descr names the object dtype, including nested fields."""
    if isinstance(descr, str):
        text = descr.strip()
        if not text:
            return False
        endian = text[0] if text[0] in "|<>=" else ""
        rest = text[1:] if endian else text
        if not rest or not rest[0].isalpha():
            return False
        typechar = rest[0]
        size = rest[1:]
        if size and not size.isdigit():
            return False
        return typechar == "O"
    if isinstance(descr, dict):
        formats = descr.get("formats", descr.get("descr"))
        if formats is None:
            return False
        if not isinstance(formats, list):
            formats = [formats]
        return descr_is_object(formats)
    if isinstance(descr, list):
        for item in descr:
            if isinstance(item, (list, tuple)):
                # ('name', descr) or ('name', descr, shape) or a bare nested descr
                fields = item[1:] if item and isinstance(item[0], str) else item
                if any(descr_is_object(field) for field in fields):
                    return True
            elif descr_is_object(item):
                return True
        return False
    if isinstance(descr, tuple):
        fields = descr[1:] if descr and isinstance(descr[0], str) else descr
        return any(descr_is_object(field) for field in fields)
    return False


def read_npy_header(fh, *, max_header_bytes: int) -> NpyHeader:
    magic = fh.read(6)
    if magic != _MAGIC:
        return NpyHeader(error="not a NumPy .npy file")
    version = fh.read(2)
    if len(version) < 2:
        return NpyHeader(error="truncated npy version")
    major, minor = version[0], version[1]
    if major == 1:
        raw_len = fh.read(2)
        if len(raw_len) < 2:
            return NpyHeader(error="truncated npy header length", version=(major, minor))
        (hlen,) = struct.unpack("<H", raw_len)
    elif major in (2, 3):
        raw_len = fh.read(4)
        if len(raw_len) < 4:
            return NpyHeader(error="truncated npy header length", version=(major, minor))
        (hlen,) = struct.unpack("<I", raw_len)
    else:
        return NpyHeader(error=f"unsupported npy version {major}.{minor}", version=(major, minor))
    if hlen > max_header_bytes:
        return NpyHeader(
            error=f"npy header length {hlen} exceeds cap {max_header_bytes}",
            version=(major, minor),
        )
    header = fh.read(hlen)
    if len(header) < hlen:
        return NpyHeader(error="truncated npy header", version=(major, minor))
    try:
        text = header.decode("latin-1")
        meta = ast.literal_eval(text)
    except (SyntaxError, ValueError, MemoryError) as exc:
        return NpyHeader(error=f"npy header did not parse: {exc}", version=(major, minor))
    if not isinstance(meta, dict) or "descr" not in meta:
        return NpyHeader(error="npy header is not a dtype map", version=(major, minor))
    descr = meta["descr"]
    return NpyHeader(
        descr=descr,
        is_object=descr_is_object(descr),
        version=(major, minor),
        data_offset=fh.tell(),
    )
