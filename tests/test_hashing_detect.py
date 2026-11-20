import hashlib
import os
import pickle
import random
import shutil
import time
import tracemalloc

import pytest

import generate
from hashvault.intake.detect import detect_format, extension_format, is_compatible
from hashvault.intake.hashing import root_hash, sha256_file


def test_root_hash_order_independent():
    pairs = [(f"f{i}.bin", hashlib.sha256(str(i).encode()).hexdigest()) for i in range(50)]
    shuffled = pairs[:]
    random.Random(7).shuffle(shuffled)
    assert root_hash(pairs) == root_hash(shuffled)
    assert root_hash(pairs) != root_hash(pairs[:-1])


def test_same_files_different_order_identical_root(tmp_path, intake):
    a = generate.full_model(tmp_path / "a")
    b = tmp_path / "b"
    b.mkdir()
    for name in sorted(os.listdir(a), reverse=True):
        time.sleep(0.01)
        shutil.copyfile(a / name, b / name)
    ma, _ = intake(a)
    mb, _ = intake(b)
    assert ma.root_sha256 == mb.root_sha256


def test_root_hash_changes_with_content(tmp_path, intake):
    a = generate.full_model(tmp_path / "a")
    ma, _ = intake(a)
    (a / "config.json").write_text('{"model_type": "llama"}')
    mb, _ = intake(a)
    assert ma.root_sha256 != mb.root_sha256


def test_sha256_file_streams_with_flat_memory(tmp_path):
    p = tmp_path / "big.bin"
    with open(p, "wb") as f:
        f.truncate(64 * 1024 * 1024)
    tracemalloc.start()
    digest, size = sha256_file(p)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert size == 64 * 1024 * 1024
    assert peak < 4 * 1024 * 1024
    assert digest == hashlib.sha256(b"\x00" * size).hexdigest()


@pytest.mark.slow
@pytest.mark.skipif(not os.environ.get("HASHVAULT_SLOW"), reason="set HASHVAULT_SLOW=1")
def test_large_shard_2gib(tmp_path):
    p = tmp_path / "shard.bin"
    with open(p, "wb") as f:
        f.truncate(2 * 1024**3)
    tracemalloc.start()
    t0 = time.perf_counter()
    _, size = sha256_file(p)
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"2 GiB hashed in {elapsed:.1f}s, peak traced memory {peak / 1024:.0f} KiB")
    assert size == 2 * 1024**3
    assert peak < 8 * 1024 * 1024


@pytest.mark.parametrize(
    "name,data,expected",
    [
        ("x.safetensors", generate.safetensors_bytes({"t": [2, 2]}), "safetensors"),
        ("x.pkl", pickle.dumps([1, 2, 3], protocol=2), "pickle"),
        ("x.pkl", pickle.dumps({"a": 1}, protocol=5), "pickle"),
        ("x.pkl", pickle.dumps({"a": 1}, protocol=0), "pickle"),
        ("x.pkl", generate.MARKER_PICKLE_P0, "pickle"),
        ("x.joblib", pickle.dumps([1], protocol=4), "joblib"),
        ("x.npy", b"\x93NUMPY\x01\x00" + b"\x00" * 32, "npy"),
        ("x.gguf", b"GGUF\x03\x00\x00\x00" + b"\x00" * 16, "unsupported"),
        ("x.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 16, "unsupported"),
        ("x.onnx", b"\x08\x07\x12\x00\xff\xfe\x00\x01", "unsupported"),
        ("config.json", b'{"a": 1}', "json"),
        ("c.yaml", b"a: 1\nb: [1, 2]\n", "yaml"),
        ("m.py", b"import os\n", "python"),
        ("README.md", b"This is a readme.", "text"),
        ("x.bz2", b"BZh91AY&SY", "bz2"),
        ("x.xz", b"\xfd7zXZ\x00\x00", "xz"),
        ("blob", bytes(range(256)) * 4, "unknown"),
    ],
)
def test_detect_by_magic(tmp_path, name, data, expected):
    p = tmp_path / name
    p.write_bytes(data)
    assert detect_format(p, name) == expected


def test_torch_zip_detection(tmp_path):
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(generate.torch_zip_bytes())
    assert detect_format(p, p.name) == "torch_zip"


def test_extension_compatibility():
    assert extension_format("model.tar.gz") == "tar"
    assert extension_format("a/b/pytorch_model.bin") == "torch"
    assert extension_format("noext") is None
    assert is_compatible("torch", "torch_zip")
    assert is_compatible("torch", "pickle")
    assert not is_compatible("safetensors", "pickle")
    assert is_compatible(None, "unknown")
