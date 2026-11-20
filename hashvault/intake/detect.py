import io
import json
import pickletools
import re
import struct
import zipfile
from pathlib import Path, PurePosixPath

import yaml

ARCHIVE_FORMATS = {"zip", "torch_zip", "tar", "gzip", "bz2", "xz"}
COMPRESSED_STREAM_FORMATS = {"gzip", "bz2", "xz"}
WEIGHT_FORMATS = {"safetensors", "pickle", "torch_zip", "npy", "joblib", "unsupported"}

_EXTENSIONS = {
    ".safetensors": "safetensors",
    ".bin": "torch",
    ".pt": "torch",
    ".pth": "torch",
    ".ckpt": "torch",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".joblib": "joblib",
    ".npy": "npy",
    ".npz": "zip",
    ".zip": "zip",
    ".tar": "tar",
    ".tgz": "tar",
    ".tbz2": "tar",
    ".txz": "tar",
    ".gz": "gzip",
    ".bz2": "bz2",
    ".xz": "xz",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".py": "python",
    ".txt": "text",
    ".md": "text",
    ".gguf": "unsupported",
    ".ggml": "unsupported",
    ".onnx": "unsupported",
    ".h5": "unsupported",
    ".hdf5": "unsupported",
    ".keras": "unsupported",
    ".tflite": "unsupported",
    ".msgpack": "unsupported",
    ".pb": "unsupported",
}

_COMPATIBLE = {
    "torch": {"torch_zip", "pickle"},
    "pickle": {"pickle", "joblib"},
    "joblib": {"joblib", "pickle"},
    "zip": {"zip", "torch_zip"},
    "gzip": {"gzip", "tar"},
    "bz2": {"bz2", "tar"},
    "xz": {"xz", "tar"},
    "yaml": {"yaml", "json"},
    "text": {"text", "json", "yaml", "python"},
}

_UNSUPPORTED_MAGIC = (
    (0, b"GGUF"),
    (0, b"\x89HDF\r\n\x1a\n"),
    (4, b"TFL3"),
)

_LEGACY_PICKLE_START = set(b"(}])")
_LEGACY_GLOBAL_RE = re.compile(rb"^c[A-Za-z_][\w.]*\n[A-Za-z_][\w.]*\n")
_ZLIB_HEADERS = {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}
_HEAD_BYTES = 64 * 1024
_PICKLE_PROBE_BYTES = 1024 * 1024


def extension_format(name: str) -> str | None:
    p = PurePosixPath(name.replace("\\", "/"))
    suffixes = [s.lower() for s in p.suffixes]
    if len(suffixes) >= 2 and suffixes[-2] == ".tar" and suffixes[-1] in {".gz", ".bz2", ".xz"}:
        return "tar"
    if not suffixes:
        return None
    return _EXTENSIONS.get(suffixes[-1])


def is_compatible(ext_format: str | None, detected: str) -> bool:
    if ext_format is None:
        return True
    return detected in _COMPATIBLE.get(ext_format, {ext_format})


def is_tar_header(block: bytes) -> bool:
    return len(block) >= 262 and block[257:262] == b"ustar"


def _looks_like_safetensors(head: bytes, size: int) -> bool:
    if len(head) < 9:
        return False
    (n,) = struct.unpack("<Q", head[:8])
    return 2 <= n <= size - 8 and head[8:9] == b"{"


def _looks_like_legacy_pickle(path: Path, head: bytes, size: int) -> bool:
    if not head or (head[0] not in _LEGACY_PICKLE_START and not _LEGACY_GLOBAL_RE.match(head)):
        return False
    with open(path, "rb") as f:
        f.seek(size - 1)
        if f.read(1) != b".":
            return False
        f.seek(0)
        probe = f.read(_PICKLE_PROBE_BYTES)
    opcodes = 0
    try:
        for op, _arg, _pos in pickletools.genops(io.BytesIO(probe)):
            opcodes += 1
            if op.name == "STOP":
                return True
    except (ValueError, struct.error, UnicodeDecodeError):
        return size > len(probe) and opcodes >= 8
    return False


def _is_torch_zip(path: Path) -> bool:
    with zipfile.ZipFile(path) as zf:
        return any(n == "data.pkl" or n.endswith("/data.pkl") for n in zf.namelist())


def _decode_text(head: bytes) -> str | None:
    if b"\x00" in head:
        return None
    try:
        return head.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start >= len(head) - 3 and len(head) == _HEAD_BYTES:
            return head[: exc.start].decode("utf-8")
        return None


def _classify_text(path: Path, ext: str | None, text_head: str, size: int, max_parse: int) -> str:
    if ext == "python":
        return "python"
    stripped = text_head.lstrip()
    if ext == "json" or stripped[:1] in {"{", "["}:
        if size <= max_parse:
            try:
                json.loads(path.read_bytes().decode("utf-8"))
                return "json"
            except (ValueError, UnicodeDecodeError):
                pass
    if ext == "yaml" and size <= max_parse:
        try:
            yaml.safe_load(path.read_bytes().decode("utf-8"))
            return "yaml"
        except (yaml.YAMLError, UnicodeDecodeError):
            pass
    return "text"


def detect_format(path: Path, name: str, max_parse_bytes: int = 64 * 1024 * 1024) -> str:
    size = path.stat().st_size
    with open(path, "rb") as f:
        head = f.read(_HEAD_BYTES)
    ext = extension_format(name)

    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        try:
            return "torch_zip" if _is_torch_zip(path) else "zip"
        except (zipfile.BadZipFile, OSError, ValueError):
            return "zip"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if is_tar_header(head):
        return "tar"
    if head[:6] == b"\x93NUMPY":
        return "npy"
    for offset, magic in _UNSUPPORTED_MAGIC:
        if head[offset : offset + len(magic)] == magic:
            return "unsupported"
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return "joblib" if ext == "joblib" else "pickle"
    if ext == "joblib" and head[:2] in _ZLIB_HEADERS:
        return "joblib"
    if _looks_like_safetensors(head, size):
        return "safetensors"
    if _looks_like_legacy_pickle(path, head, size):
        return "joblib" if ext == "joblib" else "pickle"
    text = _decode_text(head)
    if text is not None:
        return _classify_text(path, ext, text, size, max_parse_bytes)
    if ext == "unsupported":
        return "unsupported"
    return "unknown"
