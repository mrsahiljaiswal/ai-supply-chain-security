"""Provenance inspector tests. Fixtures are generated in-process; nothing calls the network."""

import json
import sys
import tempfile
import types
from pathlib import Path

import yaml
from typer.testing import CliRunner

import generate
from hashvault.cli import app
from hashvault.contracts.request import ScanRequest
from hashvault.inspectors.provenance import scan_provenance
from hashvault.intake.pipeline import run_intake
from hashvault.policy import load_policy

runner = CliRunner()


def write_registry(path: Path, models=None, trusted_names=None) -> Path:
    path.write_text(yaml.safe_dump({
        "models": models or [],
        "trusted_names": trusted_names or [],
    }), encoding="utf-8")
    return path


def model_entry(name, **kw):
    entry = {
        "name": name,
        "revision": None,
        "publisher": None,
        "root_sha256": None,
        "files": {},
        "config": None,
    }
    entry.update(kw)
    return entry


def scanned(artifact, work_root, registry: Path | None = None, **request):
    req = ScanRequest(artifact=str(artifact), **request)
    policy = load_policy(req.policy_profile)
    manifest, _intake = run_intake(req, policy, work_root=work_root)
    report = scan_provenance(req, manifest, policy, registry_path=registry)
    return req, manifest, report


def one(report, check_id):
    found = [check for check in report.checks if check.check_id == check_id]
    assert len(found) == 1, check_id
    return found[0]


def findings(report, check_id):
    return [item for item in report.findings if item.check_id == check_id]


def classification(payload):
    verdict = payload["verdict"]
    return verdict["classification"] if isinstance(verdict, dict) else verdict


def bundle_findings(payload):
    return [item for report in payload["reports"] for item in report["findings"]]


def bundle_checks(payload, inspector):
    report = next(item for item in payload["reports"] if item["inspector"] == inspector)
    return report["checks"]


def global_reduce(module: str, name: str) -> bytes:
    return b"\x80\x02c" + module.encode("ascii") + b"\n" + name.encode("ascii") + b"\n)R."


def invoke_scan(*args):
    argv = [str(arg) for arg in args]
    if "--out" not in argv:
        argv.extend(["--out", tempfile.mkdtemp(prefix="hv-scan-")])
    return runner.invoke(app, ["scan", *argv])


def test_root_hash_match_passes(fixtures, work_root, tmp_path):
    req = ScanRequest(artifact=str(fixtures["full_model"]), claimed_base_model="Qwen/Qwen2.5-0.5B")
    policy = load_policy("strict")
    manifest, _intake = run_intake(req, policy, work_root=work_root)
    registry = write_registry(tmp_path / "reg.yaml", [
        model_entry(
            "Qwen/Qwen2.5-0.5B",
            publisher="Qwen",
            root_sha256=manifest.root_sha256,
            files={entry.path: entry.sha256 for entry in manifest.entries},
        ),
    ])
    report = scan_provenance(
        req.model_copy(update={"claimed_publisher": "Qwen"}),
        manifest,
        policy,
        registry_path=registry,
    )
    check = one(report, "provenance_hash_match")
    assert check.status == "passed"
    assert findings(report, "provenance_hash_match") == []
    assert one(report, "provenance_publisher").status == "passed"


def test_root_hash_mismatch_is_critical_and_scan_exits_30(fixtures, work_root, tmp_path):
    registry = write_registry(tmp_path / "reg.yaml", [
        model_entry("Qwen/Qwen2.5-0.5B", root_sha256="0" * 64),
    ])
    result = invoke_scan(
        fixtures["full_model"], "--base", "Qwen/Qwen2.5-0.5B",
        "--registry", registry, "--work-dir", work_root,
    )
    assert result.exit_code == 30, result.stdout
    payload = json.loads(result.stdout)
    assert classification(payload) == "Blocked"
    assert result.exit_code != 0
    finding = next(item for item in bundle_findings(payload) if item["check_id"] == "provenance_hash_match")
    assert finding["severity"] == "critical"
    assert finding["evidence"]["file"] == "<root>"
    assert finding["evidence"]["expected"] == "0" * 64
    assert finding["evidence"]["actual"] != finding["evidence"]["expected"]
    check = next(item for item in bundle_checks(payload, "provenance") if item["check_id"] == "provenance_hash_match")
    assert check["status"] == "failed" and check["severity"] == "critical"


def test_file_hash_mismatch_names_the_file(fixtures, work_root, tmp_path):
    req = ScanRequest(artifact=str(fixtures["full_model"]), claimed_base_model="Qwen/Qwen2.5-0.5B")
    manifest, _intake = run_intake(req, load_policy("strict"), work_root=work_root)
    files = {entry.path: entry.sha256 for entry in manifest.entries}
    weight = next(path for path in files if path.endswith("model.safetensors"))
    files[weight] = "ab" * 32
    registry = write_registry(tmp_path / "reg.yaml", [
        model_entry("Qwen/Qwen2.5-0.5B", root_sha256=manifest.root_sha256, files=files),
    ])
    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root, registry, claimed_base_model="Qwen/Qwen2.5-0.5B",
    )
    check = one(report, "provenance_hash_match")
    assert check.status == "failed" and check.severity == "critical"
    finding = findings(report, "provenance_hash_match")[0]
    assert finding.evidence["file"].endswith("model.safetensors")
    assert finding.evidence["expected"] == "ab" * 32
    assert finding.evidence["actual"] != finding.evidence["expected"]


def test_no_registry_entry_skips_and_scan_exits_20(fixtures, work_root, tmp_path):
    registry = write_registry(tmp_path / "reg.yaml", [model_entry("other/model", root_sha256="0" * 64)])
    result = invoke_scan(
        fixtures["full_model"], "--base", "Qwen/Qwen2.5-0.5B",
        "--registry", registry, "--work-dir", work_root,
    )
    assert result.exit_code == 20, result.stdout
    payload = json.loads(result.stdout)
    assert classification(payload) == "Undetermined"
    check = next(item for item in bundle_checks(payload, "provenance") if item["check_id"] == "provenance_hash_match")
    assert check["status"] == "skipped"
    assert check["reason"] == "no_known_good_reference"
    assert check["status"] != "passed"
    assert bundle_findings(payload) == []
    assert result.exit_code != 0


def test_lora_base_claim_mismatch_is_warning(fixtures, work_root):
    _req, _manifest, report = scanned(
        fixtures["lora"], work_root, claimed_base_model="other/model",
    )
    check = one(report, "provenance_base_claim")
    assert check.status == "failed" and check.severity == "warning"
    finding = findings(report, "provenance_base_claim")[0]
    assert finding.severity == "warning"
    assert finding.evidence["base_model_name_or_path"] == "Qwen/Qwen2.5-0.5B"
    assert finding.evidence["claimed_base_model"] == "other/model"


def test_lora_base_claim_match_passes_and_missing_claim_skips(fixtures, work_root, tmp_path):
    _req, _manifest, report = scanned(
        fixtures["lora"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B",
    )
    assert one(report, "provenance_base_claim").status == "passed"

    folder = tmp_path / "lora-no-base"
    folder.mkdir()
    (folder / "adapter_config.json").write_text(json.dumps({"peft_type": "LORA", "r": 4}))
    (folder / "adapter_model.safetensors").write_bytes(generate.safetensors_bytes({
        "base_model.model.layers.0.self_attn.q_proj.lora_A.weight": [4, 8],
        "base_model.model.layers.0.self_attn.q_proj.lora_B.weight": [8, 4],
    }))
    _req, _manifest, report = scanned(folder, work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    check = one(report, "provenance_base_claim")
    assert check.status == "skipped" and check.reason == "claim_missing"


def test_full_model_without_base_claim_is_not_applicable(fixtures, work_root):
    _req, _manifest, report = scanned(fixtures["full_model"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    check = one(report, "provenance_base_claim")
    assert check.status == "not_applicable"
    assert check.reason == "no_base_claim"


def test_config_hidden_size_mismatch_names_the_field(fixtures, work_root, tmp_path):
    registry = write_registry(tmp_path / "reg.yaml", [
        model_entry("Qwen/Qwen2.5-0.5B", config={
            "model_type": "qwen2",
            "architectures": ["Qwen2ForCausalLM"],
            "hidden_size": 896,
            "num_hidden_layers": 1,
            "vocab_size": 32,
        }),
    ])
    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root, registry, claimed_base_model="Qwen/Qwen2.5-0.5B",
    )
    check = one(report, "provenance_config")
    assert check.status == "failed" and check.severity == "warning"
    finding = findings(report, "provenance_config")[0]
    assert finding.severity == "warning"
    assert "hidden_size" in finding.evidence["fields"]
    assert finding.evidence["expected"]["hidden_size"] == 896
    assert finding.evidence["actual"]["hidden_size"] == 8
    assert "hidden_size" in finding.message


def test_lora_config_is_not_applicable(fixtures, work_root, tmp_path):
    registry = write_registry(tmp_path / "reg.yaml", [
        model_entry("Qwen/Qwen2.5-0.5B", config={
            "model_type": "qwen2",
            "architectures": ["Qwen2ForCausalLM"],
            "hidden_size": 8,
            "num_hidden_layers": 1,
            "vocab_size": 32,
        }),
    ])
    _req, _manifest, report = scanned(
        fixtures["lora"], work_root, registry, claimed_base_model="Qwen/Qwen2.5-0.5B",
    )
    check = one(report, "provenance_config")
    assert check.status == "not_applicable"
    assert check.reason == "adapter_has_no_model_config"
    assert findings(report, "provenance_config") == []
    assert one(report, "provenance_base_claim").status == "passed"


def test_config_without_reference_skips(fixtures, work_root):
    _req, _manifest, report = scanned(fixtures["full_model"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    check = one(report, "provenance_config")
    assert check.status == "skipped" and check.reason == "no_reference_config"


def test_typosquat_lookalike_warns_and_exact_name_does_not(fixtures, work_root, tmp_path):
    trusted = ["Qwen/Qwen2.5-0.5B"]
    lookalike = write_registry(tmp_path / "look.yaml", trusted_names=trusted)
    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root, lookalike,
        claimed_base_model="Qwen/Qwen2.5-0.5B",
        claimed_repo="Qwen2.5-0.5B-official",
    )
    check = one(report, "provenance_typosquat")
    assert check.status == "failed" and check.severity == "warning"
    finding = findings(report, "provenance_typosquat")[0]
    assert finding.evidence["trusted_name"] == "Qwen/Qwen2.5-0.5B"
    assert finding.evidence["name"] == "Qwen2.5-0.5B-official"
    assert finding.evidence["score"] >= 90

    exact = write_registry(tmp_path / "exact.yaml", trusted_names=trusted)
    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root, exact,
        claimed_base_model="Qwen/Qwen2.5-0.5B",
        claimed_repo="Qwen/Qwen2.5-0.5B",
    )
    check = one(report, "provenance_typosquat")
    assert check.status == "passed"
    assert findings(report, "provenance_typosquat") == []

    distant = write_registry(tmp_path / "far.yaml", trusted_names=trusted)
    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root, distant,
        claimed_base_model="Qwen/Qwen2.5-0.5B",
        claimed_repo="bert-base-uncased",
    )
    assert one(report, "provenance_typosquat").status == "passed"


def test_no_trusted_names_skips(fixtures, work_root):
    _req, _manifest, report = scanned(fixtures["full_model"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    check = one(report, "provenance_typosquat")
    assert check.status == "skipped" and check.reason == "no_trusted_names"


def test_publisher_mismatch_is_warning_and_missing_publisher_is_not_passed(fixtures, work_root, tmp_path):
    registry = write_registry(tmp_path / "reg.yaml", [
        model_entry("Qwen/Qwen2.5-0.5B", publisher="Qwen"),
    ])
    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root, registry,
        claimed_base_model="Qwen/Qwen2.5-0.5B",
        claimed_publisher="someone-else",
    )
    check = one(report, "provenance_publisher")
    assert check.status == "failed" and check.severity == "warning"
    assert findings(report, "provenance_publisher")[0].evidence["expected"] == "Qwen"
    assert findings(report, "provenance_publisher")[0].evidence["actual"] == "someone-else"

    _req, _manifest, report = scanned(fixtures["full_model"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    check = one(report, "provenance_publisher")
    assert check.status == "skipped"
    assert check.reason == "publisher_not_claimed"
    assert check.status != "passed"
    assert findings(report, "provenance_publisher") == []

    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root,
        claimed_base_model="Qwen/Qwen2.5-0.5B",
        claimed_publisher="Qwen",
    )
    check = one(report, "provenance_publisher")
    assert check.status == "skipped"
    assert check.reason == "publisher_unverified"
    assert findings(report, "provenance_publisher") == []

    registry = write_registry(tmp_path / "with-publisher.yaml", [
        model_entry("Qwen/Qwen2.5-0.5B", publisher="Qwen"),
    ])
    _req, _manifest, report = scanned(
        fixtures["full_model"], work_root, registry,
        claimed_base_model="Qwen/Qwen2.5-0.5B",
    )
    check = one(report, "provenance_publisher")
    assert check.status == "skipped"
    assert check.reason == "publisher_not_claimed"
    assert findings(report, "provenance_publisher") == []


def test_hub_offline_skips(fixtures, work_root):
    _req, _manifest, report = scanned(fixtures["full_model"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    check = one(report, "provenance_hub_metadata")
    assert check.status == "skipped" and check.reason == "offline"


def test_hub_missing_library_is_error_and_scan_exits_20(monkeypatch, work_root):
    monkeypatch.setitem(sys.modules, "huggingface_hub", None)
    result = invoke_scan("acme/tiny-model@main", "--allow-network", "--work-dir", work_root)
    assert result.exit_code == 20, result.stdout
    payload = json.loads(result.stdout)
    assert classification(payload) == "Undetermined"
    check = next(item for item in bundle_checks(payload, "provenance") if item["check_id"] == "provenance_hub_metadata")
    assert check["status"] == "error"
    assert check["reason"] == "huggingface_hub_missing"
    assert result.exit_code != 0


def _fake_hub(calls: dict):
    mod = types.ModuleType("huggingface_hub")

    class HfApi:
        def model_info(self, repo_id, revision=None, files_metadata=False):
            calls["info"] = (repo_id, revision, files_metadata)
            return types.SimpleNamespace(
                sha="0123456789abcdef0123456789abcdef01234567",
                author="acme",
                private=False,
                siblings=[types.SimpleNamespace(size=100)],
                card_data=None,
            )

    def snapshot_download(repo_id, revision, local_dir):
        calls["download"] = (repo_id, revision)
        generate.full_model(Path(local_dir))

    mod.HfApi = HfApi
    mod.snapshot_download = snapshot_download
    return mod


def test_hub_mocked_failure_is_error_and_scan_exits_20(monkeypatch, work_root):
    monkeypatch.setitem(sys.modules, "huggingface_hub", _fake_hub({}))

    def boom(repo_id, revision=None):
        raise RuntimeError("hub metadata failed")

    monkeypatch.setattr("hashvault.inspectors.provenance.hub.fetch_hub_metadata", boom)
    result = invoke_scan("acme/tiny-model@main", "--allow-network", "--work-dir", work_root)
    assert result.exit_code == 20, result.stdout
    payload = json.loads(result.stdout)
    check = next(item for item in bundle_checks(payload, "provenance") if item["check_id"] == "provenance_hub_metadata")
    assert check["status"] == "error"
    assert "hub metadata failed" in check["reason"]
    assert classification(payload) == "Undetermined"
    assert result.exit_code != 0


def test_no_signature_skips_attestation(fixtures, work_root):
    _req, _manifest, report = scanned(fixtures["full_model"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    check = one(report, "provenance_attestation")
    assert check.status == "skipped" and check.reason == "no_attestation"
    assert check.status != "passed"


def test_signature_file_is_not_treated_as_passed(tmp_path, work_root):
    folder = tmp_path / "signed"
    folder.mkdir()
    (folder / "model.sig").write_bytes(b"not-a-real-signature")
    (folder / "signature").write_bytes(b"also-not-verified")
    _req, _manifest, report = scanned(folder, work_root)
    check = one(report, "provenance_attestation")
    assert check.status == "skipped"
    assert check.reason == "unsupported_signature_scheme"
    assert check.status != "passed"
    assert any(path.endswith("model.sig") for path in check.details["files"])


def test_os_system_pickle_still_exits_30_when_provenance_skips(tmp_path, work_root):
    path = tmp_path / "evil"
    path.mkdir()
    (path / "model.pkl").write_bytes(global_reduce("os", "system"))
    result = invoke_scan(path, "--work-dir", work_root)
    assert result.exit_code == 30, result.stdout
    payload = json.loads(result.stdout)
    assert classification(payload) == "Blocked"
    assert bundle_findings(payload)[0]["evidence"]["module"] == "os"
    assert bundle_findings(payload)[0]["evidence"]["name"] == "system"
    skipped = next(item for item in bundle_checks(payload, "provenance") if item["check_id"] == "provenance_hash_match")
    assert skipped["status"] == "skipped"
    assert skipped["reason"] == "no_known_good_reference"
    assert result.exit_code != 0


def test_hash_severity_comes_from_policy(fixtures, work_root, tmp_path):
    registry = write_registry(tmp_path / "reg.yaml", [
        model_entry("Qwen/Qwen2.5-0.5B", root_sha256="0" * 64),
    ])
    req = ScanRequest(artifact=str(fixtures["full_model"]), claimed_base_model="Qwen/Qwen2.5-0.5B")
    policy = load_policy("strict")
    policy.provenance.severities.provenance_hash_match = "warning"
    manifest, _intake = run_intake(req, policy, work_root=work_root)
    report = scan_provenance(req, manifest, policy, registry_path=registry)
    finding = findings(report, "provenance_hash_match")[0]
    assert finding.severity == "warning"
    assert one(report, "provenance_hash_match").severity == "warning"


def test_one_check_crashing_does_not_stop_the_others(monkeypatch, fixtures, work_root, tmp_path):
    req = ScanRequest(artifact=str(fixtures["full_model"]), claimed_base_model="Qwen/Qwen2.5-0.5B",
                      claimed_repo="not-a-trusted-name")
    policy = load_policy("strict")
    manifest, _intake = run_intake(req, policy, work_root=work_root)
    registry = write_registry(
        tmp_path / "reg.yaml",
        [model_entry("Qwen/Qwen2.5-0.5B", root_sha256=manifest.root_sha256)],
        trusted_names=["Qwen/Qwen2.5-0.5B"],
    )

    def boom(candidate, trusted):
        raise RuntimeError("scorer blew up")

    monkeypatch.setattr("hashvault.inspectors.provenance.inspector._score_name", boom)
    report = scan_provenance(req, manifest, policy, registry_path=registry)
    assert one(report, "provenance_hash_match").status == "passed"
    broken = one(report, "provenance_typosquat")
    assert broken.status == "error"
    assert "scorer blew up" in broken.reason
    assert one(report, "provenance_attestation").status == "skipped"


def test_missing_registry_file_is_usage_error_unless_static_is_critical(tmp_path, work_root):
    missing = tmp_path / "no-such-registry.yaml"
    folder = tmp_path / "clean"
    folder.mkdir()
    (folder / "readme.txt").write_text("hello\n")
    result = invoke_scan(folder, "--registry", missing, "--work-dir", work_root)
    assert result.exit_code == 2
    assert "registry" in result.output.lower()

    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "model.pkl").write_bytes(global_reduce("os", "system"))
    blocked = invoke_scan(evil, "--registry", missing, "--work-dir", work_root)
    assert blocked.exit_code == 30, blocked.stdout
    payload = json.loads(blocked.stdout)
    assert bundle_findings(payload)[0]["evidence"]["name"] == "system"
