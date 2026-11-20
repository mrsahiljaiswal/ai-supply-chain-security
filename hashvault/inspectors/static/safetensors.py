"""Validate a safetensors header and tensor byte ranges without reading values."""

import json
import math
import struct
from dataclasses import dataclass, field
from pathlib import Path

# Byte widths from the safetensors spec. F4 is packed 2 values per byte.
_DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E5M2": 1,
    "F8_E4M3": 1,
    "F8_E8M0": 1,
    "U16": 2,
    "I16": 2,
    "F16": 2,
    "BF16": 2,
    "U32": 4,
    "I32": 4,
    "F32": 4,
    "C64": 8,
    "U64": 8,
    "I64": 8,
    "F64": 8,
    "C128": 16,
}
_MAX_RANK = 64


@dataclass
class RegionCheck:
    status: str
    reason: str | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class SafetensorsAnalysis:
    structure: RegionCheck
    trailing: RegionCheck
    tensor_count: int = 0
    data_length: int = 0


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _fail(reason: str, **evidence) -> SafetensorsAnalysis:
    evidence.setdefault("reason", reason)
    return SafetensorsAnalysis(
        structure=RegionCheck("failed", reason, evidence),
        trailing=RegionCheck("not_applicable", "safetensors structure is invalid", {}),
    )


def _expected_nbytes(meta: dict) -> int | None:
    dtype = meta.get("dtype")
    shape = meta.get("shape")
    known = dtype == "F4" or (isinstance(dtype, str) and dtype in _DTYPE_BYTES)
    if not known:
        return None
    if not isinstance(shape, list) or len(shape) > _MAX_RANK:
        return None
    if not all(_is_int(dim) and dim >= 0 for dim in shape):
        return None
    try:
        count = math.prod(shape)
    except (OverflowError, ValueError):
        return None
    if dtype == "F4":
        return (count + 1) // 2
    return count * _DTYPE_BYTES[dtype]


def analyze_safetensors(path: Path, *, max_header_bytes: int) -> SafetensorsAnalysis:
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            prefix = fh.read(8)
            if len(prefix) < 8:
                return _fail("header length is truncated", file=path.name)
            (header_len,) = struct.unpack("<Q", prefix)
            if header_len <= 0:
                return _fail("header length is empty", header_length=header_len)
            if header_len > max_header_bytes:
                return _fail(
                    "header length exceeds cap",
                    header_length=header_len,
                    cap=max_header_bytes,
                )
            if header_len > size - 8:
                return _fail(
                    "header length extends past end of file",
                    header_length=header_len,
                    file_size=size,
                )
            raw = fh.read(header_len)
    except OSError as exc:
        return SafetensorsAnalysis(
            structure=RegionCheck("error", f"unreadable file: {exc}", {}),
            trailing=RegionCheck("error", f"unreadable file: {exc}", {}),
        )

    if len(raw) < header_len:
        return _fail("header is truncated", header_length=header_len, read=len(raw))
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return _fail("header JSON did not parse", detail=str(exc), header_length=header_len)
    if not isinstance(header, dict):
        return _fail("header is not a metadata-or-tensor map", json_type=type(header).__name__)

    data_len = size - 8 - header_len
    ranges: list[tuple[str, int, int]] = []
    for key, meta in header.items():
        if key == "__metadata__":
            if meta is not None and not isinstance(meta, dict):
                return _fail("__metadata__ is not an object", file=str(path))
            continue
        if not isinstance(meta, dict):
            return _fail("tensor entry is not an object", tensor=key)
        offsets = meta.get("data_offsets")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not _is_int(offsets[0])
            or not _is_int(offsets[1])
        ):
            return _fail("tensor data_offsets are invalid", tensor=key)
        start, end = offsets
        if start < 0 or end < start or end > data_len:
            return _fail(
                "tensor offset is out of range",
                tensor=key,
                start=start,
                end=end,
                data_length=data_len,
            )
        shape = meta.get("shape")
        if not isinstance(shape, list) or len(shape) > _MAX_RANK or not all(
            _is_int(dim) and dim >= 0 for dim in shape
        ):
            return _fail("tensor shape is invalid", tensor=key)
        dtype = meta.get("dtype")
        if not isinstance(dtype, str):
            return _fail("tensor dtype is missing", tensor=key)
        expected = _expected_nbytes(meta)
        if expected is not None and (end - start) != expected:
            return _fail(
                "tensor byte length does not match dtype and shape",
                tensor=key,
                start=start,
                end=end,
                expected_bytes=expected,
                dtype=dtype,
            )
        ranges.append((key, start, end))

    cursor = 0
    for key, start, end in ranges:
        if start < cursor:
            return _fail(
                "tensor offsets overlap or are out of order",
                tensor=key,
                start=start,
                end=end,
                expected_start=cursor,
            )
        if start > cursor:
            return _fail(
                "tensor offsets leave a gap and do not cover the data",
                tensor=key,
                start=start,
                end=end,
                expected_start=cursor,
            )
        cursor = end

    structure = RegionCheck("passed", evidence={
        "header_length": header_len,
        "tensor_count": len(ranges),
        "data_length": data_len,
        "covered_until": cursor,
    })
    trailing_n = data_len - cursor
    if trailing_n > 0:
        trailing = RegionCheck(
            "failed",
            f"{trailing_n} trailing bytes after the last tensor",
            {
                "trailing_bytes": trailing_n,
                "data_length": data_len,
                "covered_until": cursor,
            },
        )
    else:
        trailing = RegionCheck("passed", evidence={
            "trailing_bytes": 0,
            "data_length": data_len,
            "covered_until": cursor,
        })
    return SafetensorsAnalysis(structure, trailing, tensor_count=len(ranges), data_length=data_len)
