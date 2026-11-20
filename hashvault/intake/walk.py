import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from hashvault.intake.hashing import CHUNK_SIZE
from hashvault.policy import IntakeLimits


class LimitExceeded(Exception):
    def __init__(self, limit: str, message: str):
        super().__init__(message)
        self.limit = limit


class ArchiveCorrupt(Exception):
    pass


@dataclass
class StagedItem:
    path: str
    parent: str | None
    depth: int
    fs_path: Path
    size: int
    sha256: str
    detected_format: str | None = None
    in_torch_zip: bool = False


@dataclass
class IntakeState:
    work_dir: Path
    limits: IntakeLimits
    total_bytes: int = 0
    file_count: int = 0
    dir_count: int = 0
    items: list[StagedItem] = field(default_factory=list)
    issues: dict[str, list[dict]] = field(default_factory=dict)
    _blob_seq: int = 0

    @property
    def artifact_dir(self) -> Path:
        return self.work_dir / "artifact"

    @property
    def expanded_dir(self) -> Path:
        return self.work_dir / "expanded"

    def issue(self, check_id: str, **details) -> None:
        self.issues.setdefault(check_id, []).append(details)

    def add_file(self) -> None:
        self.file_count += 1
        if self.file_count > self.limits.max_file_count:
            raise LimitExceeded(
                "max_file_count", f"file count exceeds {self.limits.max_file_count}"
            )

    def add_dir(self) -> None:
        self.dir_count += 1
        if self.dir_count > self.limits.max_file_count:
            raise LimitExceeded(
                "max_file_count", f"directory count exceeds {self.limits.max_file_count}"
            )

    def add_bytes(self, n: int) -> None:
        self.total_bytes += n
        if self.total_bytes > self.limits.max_total_bytes:
            raise LimitExceeded(
                "max_total_bytes", f"staged size exceeds {self.limits.max_total_bytes} bytes"
            )

    def new_blob(self) -> Path:
        self._blob_seq += 1
        self.expanded_dir.mkdir(parents=True, exist_ok=True)
        return self.expanded_dir / f"{self._blob_seq:06d}.blob"

    def rel(self, p: Path) -> str:
        return p.relative_to(self.work_dir).as_posix()


def copy_stream(
    src: BinaryIO,
    dst: Path,
    state: IntakeState,
    compressed_size: int | None = None,
    label: str = "",
) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    limits = state.limits
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "xb") as out:
        while chunk := src.read(CHUNK_SIZE):
            size += len(chunk)
            state.add_bytes(len(chunk))
            if (
                compressed_size is not None
                and size > limits.compression_ratio_min_bytes
                and size > limits.max_compression_ratio * max(compressed_size, 1)
            ):
                raise LimitExceeded(
                    "max_compression_ratio",
                    f"{label}: compression ratio exceeds {limits.max_compression_ratio}:1",
                )
            h.update(chunk)
            out.write(chunk)
    return size, h.hexdigest()


_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def member_name_problem(name: str, max_path_bytes: int) -> str | None:
    if "\x00" in name:
        return "NUL byte in name"
    if len(name.encode("utf-8", "surrogateescape")) > max_path_bytes:
        return f"path longer than {max_path_bytes} bytes"
    n = name.replace("\\", "/")
    if n.startswith("/") or _DRIVE_RE.match(n):
        return "absolute path"
    if ".." in n.split("/"):
        return "path traversal (..)"
    return None


def normalize_member_name(name: str) -> str:
    return "/".join(p for p in name.replace("\\", "/").split("/") if p not in ("", "."))


def _special_kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device file"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "special file"


def _copy_regular(src: Path, dst: Path, rel: str, state: IntakeState, depth: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(src, flags)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            state.issue("intake.special_files", path=rel, reason="not a regular file at open time")
            return
        state.add_file()
        size, sha = copy_stream(f, dst, state)
    state.items.append(StagedItem(rel, None, depth, dst, size, sha))


def stage_local_tree(src_root: Path, state: IntakeState) -> None:
    dest_root = state.artifact_dir
    dest_root.mkdir(parents=True, exist_ok=True)
    if src_root.is_file():
        st = src_root.stat()
        if st.st_nlink > 1:
            state.issue("intake.special_files", path=src_root.name, reason="hardlink (copied by content)")
        _copy_regular(src_root, dest_root / src_root.name, src_root.name, state, 0)
        return
    stack: list[tuple[Path, str]] = [(src_root, "")]
    while stack:
        current, rel_dir = stack.pop()
        with os.scandir(current) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            rel = f"{rel_dir}{entry.name}"
            problem = member_name_problem(rel, state.limits.max_path_bytes)
            if problem:
                state.issue("intake.special_files", path=rel, reason=problem)
                continue
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                state.add_dir()
                (dest_root / rel).mkdir(parents=True, exist_ok=True)
                stack.append((Path(entry.path), rel + "/"))
            elif stat.S_ISREG(st.st_mode):
                if st.st_nlink > 1:
                    state.issue("intake.special_files", path=rel, reason="hardlink (copied by content)")
                _copy_regular(Path(entry.path), dest_root / rel, rel, state, 0)
            else:
                kind = _special_kind(st.st_mode)
                detail = {"path": rel, "reason": f"{kind} not followed"}
                if kind == "symlink":
                    detail["target"] = os.readlink(entry.path)
                state.issue("intake.special_files", **detail)


def make_read_only(root: Path) -> None:
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                os.chmod(p, 0o444)
        os.chmod(dirpath, 0o555)


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    os.chmod(root, 0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            os.chmod(os.path.join(dirpath, name), 0o755)
        for name in filenames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                os.chmod(p, 0o644)
