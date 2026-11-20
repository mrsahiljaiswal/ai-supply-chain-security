"""Walk a pickle opcode stream without executing it.

pickletools.genops is the only pickle API used. pickle.load, pickle.loads,
and any framework loader are not called.
"""

import bz2
import io
import lzma
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import pickletools

from hashvault.inspectors.static.rules import classify_callable

_MARK = object()
_UNKNOWN = object()

_STRING_OPS = frozenset({
    "STRING",
    "BINSTRING",
    "SHORT_BINSTRING",
    "UNICODE",
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
})
_MEMO_PUT = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_MEMO_GET = frozenset({"GET", "BINGET", "LONG_BINGET"})
_KEEP_CONTAINER = frozenset({"APPENDS", "SETITEMS", "ADDITEMS"})
_OPCODE_PREFERENCE = (
    "GLOBAL",
    "STACK_GLOBAL",
    "INST",
    "OBJ",
    "REDUCE",
    "NEWOBJ",
    "NEWOBJ_EX",
)
_ZLIB_HEADERS = {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}


class SimulatorError(Exception):
    pass


@dataclass(frozen=True)
class _Text:
    value: str


@dataclass(frozen=True)
class _Global:
    module: str
    name: str


@dataclass(frozen=True)
class Reference:
    module: str | None
    name: str | None
    opcode: str
    position: int | None
    resolved: bool


@dataclass
class CallableRecord:
    module: str | None
    name: str | None
    opcode: str
    opcodes: list[str]
    position: int | None
    classification: str
    resolved: bool

    def as_dict(self) -> dict:
        return {
            "module": self.module,
            "name": self.name,
            "opcode": self.opcode,
            "opcodes": list(self.opcodes),
            "position": self.position,
            "classification": self.classification,
            "resolved": self.resolved,
        }


@dataclass
class PickleAnalysis:
    error: str | None = None
    protocol: int | None = None
    opcode_count: int = 0
    references: list[Reference] = field(default_factory=list)
    callables: list[CallableRecord] = field(default_factory=list)
    trailing_after_stop: int = 0
    compression: str | None = None

    @property
    def dangerous(self) -> list[CallableRecord]:
        return [c for c in self.callables if c.classification == "dangerous"]

    @property
    def unknown(self) -> list[CallableRecord]:
        return [c for c in self.callables if c.classification == "unknown"]

    @property
    def safe(self) -> list[CallableRecord]:
        return [c for c in self.callables if c.classification == "safe"]


def _as_text(value) -> str | None:
    if isinstance(value, _Text):
        return value.value
    return None


def _pop(stack: list, opcode: str):
    if not stack:
        raise SimulatorError(f"stack underflow at {opcode}")
    return stack.pop()


def _split_pair(arg) -> tuple[str, str] | None:
    if not isinstance(arg, str) or " " not in arg:
        return None
    module, name = arg.split(" ", 1)
    if not module or not name:
        return None
    return module, name


def _text_arg(arg) -> str | None:
    if isinstance(arg, str):
        return arg
    if isinstance(arg, bytes):
        try:
            return arg.decode("utf-8")
        except UnicodeDecodeError:
            return arg.decode("latin-1")
    return None


def _record(refs: list[Reference], module, name, opcode, pos, resolved: bool) -> None:
    refs.append(Reference(
        module=module if resolved else None,
        name=name,
        opcode=opcode,
        position=pos,
        resolved=resolved,
    ))


def _pop_mark(stack: list, opcode: str) -> list:
    popped = []
    while stack:
        item = stack.pop()
        if item is _MARK:
            return popped
        popped.append(item)
    raise SimulatorError(f"MARK missing at {opcode}")


def _step(op, arg, pos, stack: list, memo: dict, refs: list[Reference]) -> None:
    name = op.name
    if name == "MARK":
        stack.append(_MARK)
        return
    if name == "POP":
        _pop(stack, name)
        return
    if name == "DUP":
        item = _pop(stack, name)
        stack.append(item)
        stack.append(item)
        return
    if name == "POP_MARK":
        _pop_mark(stack, name)
        return
    if name in _MEMO_PUT:
        memo[int(arg)] = stack[-1] if stack else _UNKNOWN
        if not stack:
            raise SimulatorError(f"stack underflow at {name}")
        return
    if name == "MEMOIZE":
        if not stack:
            raise SimulatorError("stack underflow at MEMOIZE")
        memo[len(memo)] = stack[-1]
        return
    if name in _MEMO_GET:
        stack.append(memo.get(int(arg), _UNKNOWN))
        return
    if name in _STRING_OPS:
        text = _text_arg(arg)
        stack.append(_Text(text) if text is not None else _UNKNOWN)
        return
    if name == "GLOBAL":
        pair = _split_pair(arg)
        if pair is None:
            _record(refs, None, None, name, pos, False)
            stack.append(_UNKNOWN)
            return
        module, qual = pair
        _record(refs, module, qual, name, pos, True)
        stack.append(_Global(module, qual))
        return
    if name == "STACK_GLOBAL":
        qual = _as_text(_pop(stack, name))
        module = _as_text(_pop(stack, name))
        if module is None or qual is None:
            _record(refs, None, qual or module, name, pos, False)
            stack.append(_UNKNOWN)
            return
        _record(refs, module, qual, name, pos, True)
        stack.append(_Global(module, qual))
        return
    if name == "INST":
        _pop_mark(stack, name)
        pair = _split_pair(arg)
        if pair is None:
            _record(refs, None, None, name, pos, False)
            stack.append(_UNKNOWN)
            return
        module, qual = pair
        _record(refs, module, qual, name, pos, True)
        stack.append(_Global(module, qual))
        return
    if name == "OBJ":
        items = _pop_mark(stack, name)
        cls = items[-1] if items else _UNKNOWN
        if isinstance(cls, _Global):
            _record(refs, cls.module, cls.name, name, pos, True)
            stack.append(cls)
        else:
            _record(refs, None, None, name, pos, False)
            stack.append(_UNKNOWN)
        return
    if name in {"REDUCE", "NEWOBJ"}:
        _pop(stack, name)
        fn = _pop(stack, name)
        if isinstance(fn, _Global):
            _record(refs, fn.module, fn.name, name, pos, True)
        stack.append(_UNKNOWN)
        return
    if name == "NEWOBJ_EX":
        _pop(stack, name)
        _pop(stack, name)
        fn = _pop(stack, name)
        if isinstance(fn, _Global):
            _record(refs, fn.module, fn.name, name, pos, True)
        stack.append(_UNKNOWN)
        return
    if name in {"EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID"}:
        _record(refs, None, f"{name}:{arg}" if arg is not None else name, name, pos, False)
        if name == "BINPERSID":
            _pop(stack, name)
        stack.append(_UNKNOWN)
        return
    if any(item is pickletools.markobject for item in op.stack_before):
        below = next(i for i, item in enumerate(op.stack_before) if item is pickletools.markobject)
        _pop_mark(stack, name)
        kept = [_pop(stack, name) for _ in range(below)]
        if name in _KEEP_CONTAINER and kept:
            stack.append(kept[0])
            return
        for _ in op.stack_after:
            stack.append(_UNKNOWN)
        return
    for _ in op.stack_before:
        _pop(stack, name)
    for _ in op.stack_after:
        stack.append(_UNKNOWN)


def _prefer_opcode(opcodes: list[str]) -> str:
    for name in _OPCODE_PREFERENCE:
        if name in opcodes:
            return name
    return opcodes[0]


def _classify(refs: list[Reference]) -> list[CallableRecord]:
    groups: dict[tuple, list[Reference]] = {}
    order: list[tuple] = []
    for ref in refs:
        if ref.resolved and ref.module and ref.name:
            key = ("resolved", ref.module, ref.name)
        else:
            key = ("unresolved", ref.opcode, ref.position, ref.name)
        if key not in groups:
            order.append(key)
            groups[key] = []
        groups[key].append(ref)
    records = []
    for key in order:
        items = groups[key]
        opcodes = [item.opcode for item in items]
        opcode = _prefer_opcode(opcodes)
        position = next((item.position for item in items if item.opcode == opcode), items[0].position)
        if key[0] == "resolved":
            module, name = key[1], key[2]
            kind = classify_callable(module, name)
            records.append(CallableRecord(
                module=module, name=name, opcode=opcode, opcodes=opcodes,
                position=position, classification=kind, resolved=True,
            ))
        else:
            records.append(CallableRecord(
                module=None, name=items[0].name, opcode=opcode, opcodes=opcodes,
                position=position, classification="unknown", resolved=False,
            ))
    return records


def _trailing_bytes(fh) -> int:
    pos = fh.tell()
    fh.seek(0, io.SEEK_END)
    end = fh.tell()
    fh.seek(pos)
    return max(0, end - pos)


def walk_pickle(fh) -> PickleAnalysis:
    """Disassemble one pickle stream. A parse failure is an error, never a pass."""
    refs: list[Reference] = []
    stack: list = []
    memo: dict = {}
    count = 0
    protocol = None
    try:
        for op, arg, pos in pickletools.genops(fh):
            count += 1
            if op.name == "PROTO" and protocol is None and isinstance(arg, int):
                protocol = arg
            _step(op, arg, pos, stack, memo, refs)
    except SimulatorError as exc:
        return PickleAnalysis(
            error=f"opcode stream could not be followed: {exc}",
            protocol=protocol, opcode_count=count, references=refs,
            callables=_classify(refs),
        )
    except Exception as exc:
        return PickleAnalysis(
            error=f"truncated or invalid pickle: {exc}",
            protocol=protocol, opcode_count=count, references=refs,
            callables=_classify(refs),
        )
    trailing = _trailing_bytes(fh)
    analysis = PickleAnalysis(
        protocol=0 if protocol is None else protocol,
        opcode_count=count,
        references=refs,
        callables=_classify(refs),
        trailing_after_stop=trailing,
    )
    if count == 0:
        analysis.error = "truncated or invalid pickle: empty stream"
    elif trailing:
        analysis.error = f"trailing bytes after STOP ({trailing})"
    return analysis


def _is_raw_pickle(head: bytes) -> bool:
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return True
    return bool(head[:1]) and head[0] in b"([{}])c"


def _compression_kind(head: bytes) -> str | None:
    if head[:2] in _ZLIB_HEADERS:
        return "zlib"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    return None


def _decompress(data: bytes, kind: str, max_bytes: int) -> bytes:
    try:
        if kind == "zlib":
            dec = zlib.decompressobj()
            out = dec.decompress(data, max_bytes + 1)
            eof = dec.eof
        elif kind == "gzip":
            dec = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
            out = dec.decompress(data, max_bytes + 1)
            eof = dec.eof
        elif kind == "bz2":
            dec = bz2.BZ2Decompressor()
            out = dec.decompress(data, max_bytes + 1)
            eof = dec.eof
        elif kind == "xz":
            dec = lzma.LZMADecompressor()
            out = dec.decompress(data, max_bytes + 1)
            eof = dec.eof
        else:
            raise ValueError(f"unsupported compression {kind}")
    except Exception as exc:
        raise ValueError(f"{kind} payload could not be decompressed: {exc}") from exc
    if len(out) > max_bytes:
        raise ValueError(f"decompressed pickle exceeds size cap {max_bytes}")
    if not eof:
        raise ValueError(f"{kind} payload is truncated or exceeds the size cap")
    return out


def analyze_pickle_file(path: Path, *, max_bytes: int, allow_compressed: bool) -> PickleAnalysis:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return PickleAnalysis(error=f"unreadable file: {exc}")
    if size > max_bytes:
        return PickleAnalysis(error=f"file is {size} bytes, over cap {max_bytes}")
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            fh.seek(0)
            kind = _compression_kind(head) if allow_compressed else None
            if kind and not _is_raw_pickle(head):
                try:
                    raw = _decompress(fh.read(), kind, max_bytes)
                except ValueError as exc:
                    return PickleAnalysis(error=str(exc), compression=kind)
                analysis = walk_pickle(io.BytesIO(raw))
                analysis.compression = kind
                return analysis
            analysis = walk_pickle(fh)
            return analysis
    except OSError as exc:
        return PickleAnalysis(error=f"unreadable file: {exc}")
