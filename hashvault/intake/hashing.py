import hashlib
from collections.abc import Iterable
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def root_hash(pairs: Iterable[tuple[str, str]]) -> str:
    lines = sorted(f"{path}:{sha}" for path, sha in pairs)
    h = hashlib.sha256()
    for line in lines:
        h.update(line.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()
