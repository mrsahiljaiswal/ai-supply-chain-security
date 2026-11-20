import bz2
import gzip
import io
import lzma
import stat
import tarfile
import zipfile
import zlib
from pathlib import PurePosixPath

from hashvault.intake.detect import is_tar_header
from hashvault.intake.walk import (
    ArchiveCorrupt,
    IntakeState,
    LimitExceeded,
    StagedItem,
    copy_stream,
    member_name_problem,
    normalize_member_name,
)

_OPENERS = {"gzip": gzip.open, "bz2": bz2.open, "xz": lzma.open}
_STREAM_ERRORS = (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError)


class _GuardedReader(io.RawIOBase):
    def __init__(self, stream, compressed_size: int, state: IntakeState, label: str):
        self._stream = stream
        self._compressed = max(compressed_size, 1)
        self._state = state
        self._label = label
        self.produced = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self._stream.read(len(b))
        n = len(data)
        b[:n] = data
        self.produced += n
        limits = self._state.limits
        if self.produced > limits.max_total_bytes:
            raise LimitExceeded(
                "max_total_bytes",
                f"{self._label}: decompressed stream exceeds {limits.max_total_bytes} bytes",
            )
        if (
            self.produced > limits.compression_ratio_min_bytes
            and self.produced > limits.max_compression_ratio * self._compressed
        ):
            raise LimitExceeded(
                "max_compression_ratio",
                f"{self._label}: compression ratio exceeds {limits.max_compression_ratio}:1",
            )
        return n


def _reject(state: IntakeState, item: StagedItem, name: str, reason: str) -> None:
    state.issue("intake.archive_member_rejected", path=f"{item.path}!/{name}", reason=reason)


def _add_member(
    state: IntakeState, item: StagedItem, name: str, src, compressed_size: int | None, torch: bool
) -> StagedItem:
    state.add_file()
    blob = state.new_blob()
    logical = f"{item.path}!/{normalize_member_name(name)}"
    size, sha = copy_stream(src, blob, state, compressed_size=compressed_size, label=logical)
    member = StagedItem(logical, item.path, item.depth + 1, blob, size, sha, in_torch_zip=torch)
    state.items.append(member)
    return member


def _expand_zip(item: StagedItem, state: IntakeState, torch: bool) -> None:
    try:
        zf = zipfile.ZipFile(item.fs_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveCorrupt(f"{item.path}: {exc}") from exc
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                state.add_dir()
                continue
            name = info.filename
            reasons = []
            if problem := member_name_problem(name, state.limits.max_path_bytes):
                reasons.append(problem)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                reasons.append("symlink" if stat.S_ISLNK(mode) else "special file")
            if reasons:
                state.add_file()
                _reject(state, item, name, "; ".join(reasons))
                continue
            if info.flag_bits & 0x1:
                raise ArchiveCorrupt(f"{item.path}!/{name}: encrypted member cannot be inspected")
            try:
                with zf.open(info) as src:
                    _add_member(state, item, name, src, info.compress_size, torch)
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, *_STREAM_ERRORS) as exc:
                raise ArchiveCorrupt(f"{item.path}!/{name}: {exc}") from exc


def _expand_tar_stream(item: StagedItem, fileobj, state: IntakeState) -> None:
    try:
        tf = tarfile.open(fileobj=fileobj, mode="r|")
        with tf:
            for m in tf:
                if m.isdir():
                    state.add_dir()
                    continue
                reasons = []
                if problem := member_name_problem(m.name, state.limits.max_path_bytes):
                    reasons.append(problem)
                if m.issym():
                    reasons.append(f"symlink -> {m.linkname}")
                elif m.islnk():
                    reasons.append(f"hardlink -> {m.linkname}")
                elif m.ischr() or m.isblk():
                    reasons.append("device file")
                elif m.isfifo():
                    reasons.append("fifo")
                elif not m.isreg():
                    reasons.append("special member type")
                if reasons:
                    state.add_file()
                    _reject(state, item, m.name, "; ".join(reasons))
                    continue
                src = tf.extractfile(m)
                _add_member(state, item, m.name, src, None, False)
    except LimitExceeded:
        raise
    except (tarfile.TarError, *_STREAM_ERRORS) as exc:
        raise ArchiveCorrupt(f"{item.path}: {exc}") from exc


def _expand_compressed(item: StagedItem, state: IntakeState) -> None:
    opener = _OPENERS[item.detected_format]
    compressed = item.fs_path.stat().st_size
    try:
        with opener(item.fs_path, "rb") as probe:
            head = probe.read(512)
    except _STREAM_ERRORS as exc:
        raise ArchiveCorrupt(f"{item.path}: {exc}") from exc
    try:
        with opener(item.fs_path, "rb") as stream:
            guarded = _GuardedReader(stream, compressed, state, item.path)
            if is_tar_header(head):
                item.detected_format = "tar"
                _expand_tar_stream(item, guarded, state)
                return
            name = PurePosixPath(item.path.split("!/")[-1]).stem or "stream"
            _add_member(state, item, name, guarded, None, False)
    except (LimitExceeded, ArchiveCorrupt):
        raise
    except _STREAM_ERRORS as exc:
        raise ArchiveCorrupt(f"{item.path}: {exc}") from exc


def expand_archive(item: StagedItem, state: IntakeState) -> None:
    if item.depth + 1 > state.limits.max_archive_depth:
        raise LimitExceeded(
            "max_archive_depth",
            f"{item.path}: archive nesting exceeds depth {state.limits.max_archive_depth}",
        )
    fmt = item.detected_format
    if fmt in ("zip", "torch_zip"):
        _expand_zip(item, state, torch=fmt == "torch_zip")
    elif fmt == "tar":
        try:
            with open(item.fs_path, "rb") as raw:
                _expand_tar_stream(item, raw, state)
        except OSError as exc:
            raise ArchiveCorrupt(f"{item.path}: {exc}") from exc
    elif fmt in _OPENERS:
        _expand_compressed(item, state)
