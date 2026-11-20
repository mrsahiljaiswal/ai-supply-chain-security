"""Generate intake test fixtures. All "malicious" content is inert marker data and is never loaded."""

import argparse
import gzip
import io
import json
import math
import os
import pickle
import struct
import tarfile
import zipfile
from pathlib import Path

MARKER = "hashvault-fixture-marker"
MARKER_PICKLE_P0 = b"cbuiltins\nprint\n(S'" + MARKER.encode() + b"'\ntR."


def safetensors_bytes(tensors: dict[str, list[int]]) -> bytes:
    header: dict = {"__metadata__": {"format": "pt", "fixture": MARKER}}
    blobs = []
    offset = 0
    for name, shape in tensors.items():
        n = math.prod(shape)
        data = struct.pack(f"<{n}f", *[(i % 17) / 17.0 for i in range(n)])
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + len(data)]}
        blobs.append(data)
        offset += len(data)
    hb = json.dumps(header, separators=(",", ":")).encode()
    hb += b" " * (-len(hb) % 8)
    return struct.pack("<Q", len(hb)) + hb + b"".join(blobs)


FULL_TENSORS = {
    "model.embed_tokens.weight": [32, 8],
    "model.layers.0.self_attn.q_proj.weight": [8, 8],
    "model.layers.0.mlp.up_proj.weight": [16, 8],
    "lm_head.weight": [32, 8],
}
FULL_PARAMS = sum(math.prod(s) for s in FULL_TENSORS.values())
LORA_TENSORS = {
    "base_model.model.layers.0.self_attn.q_proj.lora_A.weight": [4, 8],
    "base_model.model.layers.0.self_attn.q_proj.lora_B.weight": [8, 4],
}
CONFIG = {
    "model_type": "qwen2",
    "architectures": ["Qwen2ForCausalLM"],
    "hidden_size": 8,
    "num_hidden_layers": 1,
    "vocab_size": 32,
    "torch_dtype": "float32",
}
ADAPTER_CONFIG = {
    "base_model_name_or_path": "Qwen/Qwen2.5-0.5B",
    "peft_type": "LORA",
    "r": 4,
    "lora_alpha": 8,
    "target_modules": ["q_proj", "v_proj"],
}


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    return path


def full_model(d: Path) -> Path:
    _write(d / "config.json", json.dumps(CONFIG, indent=2))
    _write(d / "generation_config.json", json.dumps({"max_new_tokens": 16}))
    _write(d / "tokenizer.json", json.dumps({"version": "1.0", "model": {"type": "BPE"}}))
    _write(d / "model.safetensors", safetensors_bytes(FULL_TENSORS))
    return d


def lora_adapter(d: Path) -> Path:
    _write(d / "adapter_config.json", json.dumps(ADAPTER_CONFIG, indent=2))
    _write(d / "adapter_model.safetensors", safetensors_bytes(LORA_TENSORS))
    _write(d / "README.md", "# fixture LoRA adapter\n")
    return d


def pickle_as_safetensors(d: Path) -> Path:
    _write(d / "config.json", json.dumps(CONFIG))
    _write(d / "model.safetensors", pickle.dumps({"marker": MARKER}, protocol=4))
    _write(d / "legacy.safetensors", MARKER_PICKLE_P0)
    return d


def torch_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"marker": MARKER}, protocol=2))
        zf.writestr("archive/byteorder", "little")
        zf.writestr("archive/data/0", struct.pack("<16f", *range(16)))
        zf.writestr("archive/version", "3\n")
    return buf.getvalue()


def torch_checkpoint(d: Path) -> Path:
    _write(d / "config.json", json.dumps(CONFIG))
    _write(d / "pytorch_model.bin", torch_zip_bytes())
    return d


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _targz_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def nested_archive(path: Path) -> Path:
    deep = _zip_bytes({
        "model/config.json": json.dumps(CONFIG).encode(),
        "model/model.safetensors": safetensors_bytes(FULL_TENSORS),
    })
    mid = _targz_bytes({"payload/deep.zip": deep, "payload/notes.txt": b"nested fixture\n"})
    return _write(path, _zip_bytes({"bundle/inner.tar.gz": mid, "bundle/README.md": b"outer\n"}))


def nested_zips(path: Path, levels: int) -> Path:
    data = _zip_bytes({"leaf.txt": b"leaf\n"})
    for i in range(levels - 1):
        data = _zip_bytes({f"level{levels - 1 - i}.zip": data})
    return _write(path, data)


def zip_bomb(path: Path, size: int = 50 * 1024 * 1024) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("zeros.bin", b"\x00" * size)
    return _write(path, buf.getvalue())


def gzip_bomb(path: Path, size: int = 50 * 1024 * 1024) -> Path:
    return _write(path, gzip.compress(b"\x00" * size, compresslevel=9))


def evil_tar(path: Path) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        def add(name, data=b"", type_=tarfile.REGTYPE, linkname=""):
            info = tarfile.TarInfo(name)
            info.type = type_
            info.linkname = linkname
            info.size = len(data) if type_ == tarfile.REGTYPE else 0
            tf.addfile(info, io.BytesIO(data) if type_ == tarfile.REGTYPE else None)

        add("ok.txt", b"fine\n")
        add("../evil", MARKER.encode())
        add("/abs/evil", MARKER.encode())
        add("link-to-passwd", type_=tarfile.SYMTYPE, linkname="/etc/passwd")
        add("hard", type_=tarfile.LNKTYPE, linkname="ok.txt")
        add("dev", type_=tarfile.CHRTYPE)
    return _write(path, buf.getvalue())


def gguf_file(path: Path) -> Path:
    return _write(path, b"GGUF" + struct.pack("<IQQ", 3, 0, 0) + b"\x00" * 64)


def unknown_binary(d: Path) -> Path:
    full_model(d)
    _write(d / "blob.dat", bytes((i * 37 + 11) % 256 for i in range(4096)) + b"\x00\xff")
    return d


def with_symlink(d: Path) -> Path:
    full_model(d)
    os.symlink("/etc/passwd", d / "passwd-link")
    return d


def build_all(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    return {
        "full_model": full_model(root / "full_model"),
        "lora": lora_adapter(root / "lora"),
        "pickle_as_safetensors": pickle_as_safetensors(root / "pickle_as_safetensors"),
        "torch_checkpoint": torch_checkpoint(root / "torch_checkpoint"),
        "nested": nested_archive(root / "nested.zip"),
        "depth5": nested_zips(root / "depth5.zip", 5),
        "depth6": nested_zips(root / "depth6.zip", 6),
        "zip_bomb": zip_bomb(root / "bomb.zip"),
        "gzip_bomb": gzip_bomb(root / "bomb.bin.gz"),
        "evil_tar": evil_tar(root / "evil.tar"),
        "gguf": gguf_file(root / "gguf" / "model.gguf"),
        "unknown_binary": unknown_binary(root / "unknown_binary"),
        "with_symlink": with_symlink(root / "with_symlink"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dest", type=Path, nargs="?", default=Path("tests/fixtures/generated"))
    args = parser.parse_args()
    for name, path in build_all(args.dest).items():
        print(f"{name}: {path}")
