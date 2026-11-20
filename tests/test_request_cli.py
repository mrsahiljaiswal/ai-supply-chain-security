import json

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from hashvault.cli import app
from hashvault.contracts.request import ScanRequest, parse_hub_id

runner = CliRunner()


def run(*args):
    return runner.invoke(app, [str(a) for a in args])


def test_lora_type_requires_base(fixtures):
    with pytest.raises(ValidationError, match="requires --base"):
        ScanRequest(artifact=str(fixtures["lora"]), artifact_type="lora_adapter")


def test_hub_id_requires_allow_network():
    with pytest.raises(ValidationError, match="allow-network"):
        ScanRequest(artifact="Qwen/Qwen2.5-0.5B@main")
    req = ScanRequest(artifact="Qwen/Qwen2.5-0.5B@abc123", allow_network=True)
    assert req.hub_ref == ("Qwen/Qwen2.5-0.5B", "abc123")
    assert parse_hub_id("hf://org/name") == ("org/name", None)


def test_missing_path_rejected():
    with pytest.raises(ValidationError, match="does not exist"):
        ScanRequest(artifact="./definitely/not/here.bin")


def test_bad_fields_rejected(fixtures):
    with pytest.raises(ValidationError):
        ScanRequest(artifact=str(fixtures["full_model"]), artifact_type="checkpoint")
    with pytest.raises(ValidationError):
        ScanRequest(artifact=str(fixtures["full_model"]), claimed_base_sha256="xyz")
    with pytest.raises(ValidationError, match="unknown policy"):
        ScanRequest(artifact=str(fixtures["full_model"]), policy_profile="nope")
    with pytest.raises(ValidationError):
        ScanRequest(artifact=str(fixtures["full_model"]), surprise=True)


def test_cli_intake_prints_manifest(fixtures, work_root):
    r = run("intake", fixtures["full_model"], "--base", "Qwen/Qwen2.5-0.5B", "--work-dir", work_root)
    assert r.exit_code == 0, r.output
    out = json.loads(r.stdout)
    assert out["manifest"]["artifact_type"] == "full_model"
    assert {c["check_id"] for c in out["checks"]} >= {"intake.stage", "intake.limits", "intake.format_mismatch"}


def test_cli_lora_without_base_exit_2(fixtures, work_root):
    r = run("intake", fixtures["lora"], "--type", "lora_adapter", "--work-dir", work_root)
    assert r.exit_code == 2
    assert "--base" in r.output


def test_cli_detected_lora_without_base_exit_2(fixtures, work_root):
    r = run("intake", fixtures["lora"], "--work-dir", work_root)
    assert r.exit_code == 2
    assert "LoRA" in r.output


def test_cli_hub_without_network_exit_2(work_root):
    r = run("intake", "Qwen/Qwen2.5-0.5B", "--work-dir", work_root)
    assert r.exit_code == 2
    assert "allow-network" in r.output


def test_cli_unknown_policy_exit_2(fixtures, work_root):
    r = run("intake", fixtures["full_model"], "--policy", "lenient", "--work-dir", work_root)
    assert r.exit_code == 2


def test_cli_missing_artifact_exit_2():
    assert run("intake").exit_code == 2
    assert run("intake", "/no/such/path").exit_code == 2


def test_cli_request_file(fixtures, tmp_path, work_root):
    req = tmp_path / "scan.yaml"
    req.write_text(yaml.safe_dump({
        "artifact": str(fixtures["lora"]),
        "artifact_type": "lora_adapter",
        "claimed_base_model": "Qwen/Qwen2.5-0.5B",
        "claimed_publisher": "acme-ml",
        "policy_profile": "strict",
    }))
    out_dir = tmp_path / "reports"
    r = run("intake", "--request", req, "--work-dir", work_root, "--out", out_dir)
    assert r.exit_code == 0, r.output
    data = json.loads(r.stdout)
    assert data["request"]["claimed_publisher"] == "acme-ml"
    assert data["manifest"]["claims"]["base_model_name_or_path"] == "Qwen/Qwen2.5-0.5B"
    assert len(list(out_dir.glob("*.intake.json"))) == 1


def test_cli_request_file_overridden_by_flags(fixtures, tmp_path, work_root):
    req = tmp_path / "scan.yaml"
    req.write_text(yaml.safe_dump({"artifact": str(fixtures["lora"]), "artifact_type": "lora_adapter"}))
    assert run("intake", "--request", req, "--work-dir", work_root).exit_code == 2
    r = run("intake", "--request", req, "--base", "Qwen/Qwen2.5-0.5B", "--work-dir", work_root)
    assert r.exit_code == 0, r.output


def test_cli_policy_yaml_path(fixtures, tmp_path, work_root):
    pol = tmp_path / "tiny.yaml"
    pol.write_text(yaml.safe_dump({"name": "tiny", "intake": {"limits": {"max_total_bytes": 100}}}))
    r = run("intake", fixtures["full_model"], "--policy", pol, "--work-dir", work_root)
    assert r.exit_code == 0, r.output
    checks = {c["check_id"]: c for c in json.loads(r.stdout)["checks"]}
    assert checks["intake.limits"]["status"] == "error"


def test_cli_scan_stub_is_undetermined(fixtures, work_root):
    r = run("scan", fixtures["full_model"], "--base", "Qwen/Qwen2.5-0.5B", "--work-dir", work_root)
    assert r.exit_code == 20
    assert json.loads(r.stdout)["verdict"] == "Undetermined"
