import os
import stat
from pathlib import Path

import generate

BAD = {"failed", "error", "skipped"}


def entry(manifest, suffix):
    matches = [e for e in manifest.entries if e.path.endswith(suffix)]
    assert matches, f"no entry ending with {suffix}: {[e.path for e in manifest.entries]}"
    return matches[0]


def test_clean_full_model_all_checks_pass(fixtures, intake):
    manifest, checks = intake(fixtures["full_model"], claimed_base_model="Qwen/Qwen2.5-0.5B")
    assert manifest.artifact_type == "full_model"
    assert manifest.source == "local_dir"
    assert manifest.complete
    assert not [c for c in checks.values() if c.status in BAD]
    assert entry(manifest, "model.safetensors").detected_format == "safetensors"
    assert entry(manifest, "model.safetensors").role == "weights"
    assert entry(manifest, "config.json").role == "config"
    assert entry(manifest, "tokenizer.json").role == "tokenizer"
    assert manifest.claims["model_type"] == "qwen2"
    assert manifest.claims["num_hidden_layers"] == 1
    assert manifest.claims["custom_code_present"] is False
    assert manifest.estimated_params == generate.FULL_PARAMS
    assert len(manifest.root_sha256) == 64


def test_clean_lora_extracts_base(fixtures, intake):
    manifest, checks = intake(fixtures["lora"], artifact_type="lora_adapter",
                              claimed_base_model="Qwen/Qwen2.5-0.5B")
    assert manifest.artifact_type == "lora_adapter"
    assert manifest.claims["base_model_name_or_path"] == "Qwen/Qwen2.5-0.5B"
    assert manifest.claims["lora_r"] == 4
    assert manifest.claims["lora_target_modules"] == ["q_proj", "v_proj"]
    assert entry(manifest, "adapter_model.safetensors").role == "adapter_weights"
    assert checks["intake.type_mismatch"].status == "passed"
    assert not [c for c in checks.values() if c.status in BAD]


def test_pickle_renamed_safetensors_is_mismatch(fixtures, intake):
    manifest, checks = intake(fixtures["pickle_as_safetensors"])
    assert entry(manifest, "model.safetensors").detected_format == "pickle"
    assert entry(manifest, "legacy.safetensors").detected_format == "pickle"
    c = checks["intake.format_mismatch"]
    assert c.status == "failed" and c.severity == "warning"
    assert {f["path"] for f in c.details["files"]} == {"model.safetensors", "legacy.safetensors"}


def test_torch_zip_inner_pickle_depth_1(fixtures, intake):
    manifest, checks = intake(fixtures["torch_checkpoint"])
    outer = entry(manifest, "pytorch_model.bin")
    assert outer.detected_format == "torch_zip" and outer.role == "weights"
    inner = entry(manifest, "pytorch_model.bin!/archive/data.pkl")
    assert inner.depth == 1 and inner.parent == "pytorch_model.bin"
    assert inner.detected_format == "pickle"
    assert entry(manifest, "archive/data/0").detected_format == "torch_storage"
    assert manifest.artifact_type == "full_model"
    assert checks["intake.format_mismatch"].status == "passed"
    assert checks["intake.unknown_format"].status == "passed"


def test_nested_zip_in_targz_in_zip(fixtures, intake):
    manifest, checks = intake(fixtures["nested"])
    assert manifest.source == "local_archive"
    paths = {e.path: e for e in manifest.entries}
    tgz = "nested.zip!/bundle/inner.tar.gz"
    deep = f"{tgz}!/payload/deep.zip"
    assert paths[tgz].depth == 1 and paths[tgz].detected_format == "tar"
    assert paths[deep].depth == 2 and paths[deep].detected_format == "zip"
    leaf = paths[f"{deep}!/model/model.safetensors"]
    assert leaf.depth == 3 and leaf.parent == deep and leaf.detected_format == "safetensors"
    assert f"{deep}!/model/config.json" in paths
    assert f"{tgz}!/payload/notes.txt" in paths
    assert manifest.artifact_type == "full_model"
    assert checks["intake.archive_expansion"].status == "passed"
    assert not [c for c in checks.values() if c.status in BAD]


def test_depth_5_allowed(fixtures, intake):
    manifest, checks = intake(fixtures["depth5"])
    assert manifest.complete
    assert max(e.depth for e in manifest.entries) == 5


def test_depth_6_is_error_not_partial(fixtures, intake):
    manifest, checks = intake(fixtures["depth6"])
    c = checks["intake.limits"]
    assert c.status == "error" and c.details["limit"] == "max_archive_depth"
    assert not manifest.complete and manifest.entries == [] and manifest.root_sha256 is None
    assert not Path(manifest.work_dir, "expanded").exists()


def test_zip_bomb_is_error(fixtures, intake):
    manifest, checks = intake(fixtures["zip_bomb"])
    c = checks["intake.limits"]
    assert c.status == "error" and c.details["limit"] == "max_compression_ratio"
    assert manifest.entries == []


def test_gzip_bomb_is_error(fixtures, intake):
    manifest, checks = intake(fixtures["gzip_bomb"])
    assert checks["intake.limits"].details["limit"] == "max_compression_ratio"


def test_evil_tar_members_rejected(fixtures, intake):
    manifest, checks = intake(fixtures["evil_tar"])
    c = checks["intake.archive_member_rejected"]
    assert c.status == "failed" and c.severity == "critical"
    reasons = {m["path"].split("!/", 1)[1]: m["reason"] for m in c.details["members"]}
    assert "traversal" in reasons["../evil"]
    assert "absolute" in reasons["/abs/evil"]
    assert reasons["link-to-passwd"].startswith("symlink")
    assert reasons["hard"].startswith("hardlink")
    assert reasons["dev"] == "device file"
    member_paths = {e.path for e in manifest.entries}
    assert member_paths == {"evil.tar", "evil.tar!/ok.txt"}
    for p in Path(manifest.work_dir).rglob("*"):
        assert not p.is_symlink()
        assert p.name != "evil"


def test_gguf_skipped_unsupported(fixtures, intake):
    manifest, checks = intake(fixtures["gguf"])
    c = checks["intake.unsupported_format"]
    assert c.status == "skipped" and c.reason == "unsupported_format"
    assert entry(manifest, "model.gguf").detected_format == "unsupported"
    assert manifest.claims.get("config_missing") is True
    assert checks["intake.format_mismatch"].status == "passed"


def test_unknown_binary_failed_warning(fixtures, intake):
    manifest, checks = intake(fixtures["unknown_binary"])
    c = checks["intake.unknown_format"]
    assert c.status == "failed" and c.severity == "warning"
    assert c.details["files"] == ["blob.dat"]


def test_local_symlink_not_followed(fixtures, intake):
    manifest, checks = intake(fixtures["with_symlink"])
    c = checks["intake.special_files"]
    assert c.status == "failed"
    assert c.details["items"][0]["path"] == "passwd-link"
    assert c.details["items"][0]["target"] == "/etc/passwd"
    assert "passwd-link" not in {e.path for e in manifest.entries}


def test_type_mismatch(fixtures, intake):
    manifest, checks = intake(fixtures["lora"], artifact_type="full_model")
    c = checks["intake.type_mismatch"]
    assert c.status == "failed" and c.severity == "warning"
    assert manifest.artifact_type == "lora_adapter"


def test_staged_copy_is_read_only(fixtures, intake):
    manifest, _ = intake(fixtures["full_model"])
    staged = Path(manifest.work_dir) / entry(manifest, "model.safetensors").staged_path
    assert staged.exists()
    assert not os.access(staged, os.W_OK) or os.geteuid() == 0
    assert stat.S_IMODE(staged.stat().st_mode) == 0o444


def test_hashes_match_original(fixtures, intake):
    import hashlib

    manifest, _ = intake(fixtures["full_model"])
    original = (fixtures["full_model"] / "model.safetensors").read_bytes()
    assert entry(manifest, "model.safetensors").sha256 == hashlib.sha256(original).hexdigest()


def test_single_file_source(fixtures, intake):
    manifest, checks = intake(fixtures["full_model"] / "model.safetensors")
    assert manifest.source == "local_file"
    assert [e.path for e in manifest.entries] == ["model.safetensors"]
    assert manifest.claims["config_missing"] is True


def test_file_count_limit(tmp_path, work_root):
    from hashvault.contracts.request import ScanRequest
    from hashvault.intake.pipeline import run_intake
    from hashvault.policy import IntakeLimits, IntakePolicy, Policy

    d = tmp_path / "many"
    d.mkdir()
    for i in range(6):
        (d / f"f{i}.txt").write_text("x")
    policy = Policy(intake=IntakePolicy(limits=IntakeLimits(max_file_count=5)))
    manifest, checks = run_intake(ScanRequest(artifact=str(d)), policy, work_root=work_root)
    c = {c.check_id: c for c in checks}["intake.limits"]
    assert c.status == "error" and c.details["limit"] == "max_file_count"
    assert manifest.entries == []


def test_total_size_limit(fixtures, work_root):
    from hashvault.contracts.request import ScanRequest
    from hashvault.intake.pipeline import run_intake
    from hashvault.policy import IntakeLimits, IntakePolicy, Policy

    policy = Policy(intake=IntakePolicy(limits=IntakeLimits(max_total_bytes=512)))
    manifest, checks = run_intake(ScanRequest(artifact=str(fixtures["full_model"])), policy,
                                  work_root=work_root)
    c = {c.check_id: c for c in checks}["intake.limits"]
    assert c.status == "error" and c.details["limit"] == "max_total_bytes"


def test_corrupt_archive_is_error(tmp_path, intake):
    bad = tmp_path / "broken.zip"
    bad.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    manifest, checks = intake(bad)
    assert checks["intake.archive_expansion"].status == "error"
    assert not manifest.complete


def test_invalid_config_json_is_claims_error(tmp_path, intake):
    d = generate.full_model(tmp_path / "m")
    (d / "config.json").write_text("{not json")
    manifest, checks = intake(d)
    assert checks["intake.claims"].status == "error"
    assert checks["intake.format_mismatch"].status == "failed"


def test_custom_code_flagged(tmp_path, intake):
    import json

    d = generate.full_model(tmp_path / "m")
    cfg = dict(generate.CONFIG, auto_map={"AutoModel": "modeling_x.XModel"})
    (d / "config.json").write_text(json.dumps(cfg))
    (d / "modeling_x.py").write_text("class XModel:\n    pass\n")
    manifest, _ = intake(d)
    assert manifest.claims["custom_code_present"] is True
    assert manifest.claims["python_files"] == ["modeling_x.py"]
    assert entry(manifest, "modeling_x.py").role == "code"
