import sys
import types
from pathlib import Path

import generate
from hashvault.contracts.request import ScanRequest
from hashvault.intake.pipeline import run_intake

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _fake_hub(calls: dict, sizes: list[int]):
    mod = types.ModuleType("huggingface_hub")

    class HfApi:
        def model_info(self, repo_id, revision=None, files_metadata=False):
            calls["info"] = (repo_id, revision)
            return types.SimpleNamespace(
                sha=COMMIT, siblings=[types.SimpleNamespace(size=s) for s in sizes]
            )

    def snapshot_download(repo_id, revision, local_dir):
        calls["download"] = (repo_id, revision)
        generate.full_model(Path(local_dir))

    mod.HfApi = HfApi
    mod.snapshot_download = snapshot_download
    return mod


def test_hub_source_pins_resolved_commit(monkeypatch, work_root):
    calls: dict = {}
    monkeypatch.setitem(sys.modules, "huggingface_hub", _fake_hub(calls, [100, 200]))
    req = ScanRequest(artifact="acme/tiny-model@main", allow_network=True)
    manifest, checks = run_intake(req, work_root=work_root)
    assert calls["info"] == ("acme/tiny-model", "main")
    assert calls["download"] == ("acme/tiny-model", COMMIT)
    assert manifest.source == "hf_hub" and manifest.resolved_revision == COMMIT
    assert manifest.artifact_type == "full_model"
    assert {e.path for e in manifest.entries} >= {"config.json", "model.safetensors"}
    assert not Path(manifest.work_dir, "download").exists()


def test_hub_declared_size_over_limit_is_error(monkeypatch, work_root):
    calls: dict = {}
    monkeypatch.setitem(sys.modules, "huggingface_hub", _fake_hub(calls, [5 * 1024**3]))
    req = ScanRequest(artifact="acme/huge@main", allow_network=True)
    manifest, checks = run_intake(req, work_root=work_root)
    c = {c.check_id: c for c in checks}["intake.limits"]
    assert c.status == "error" and c.details["limit"] == "max_total_bytes"
    assert "download" not in calls


def test_hub_missing_library_is_stage_error(monkeypatch, work_root):
    monkeypatch.setitem(sys.modules, "huggingface_hub", None)
    req = ScanRequest(artifact="acme/tiny@main", allow_network=True)
    manifest, checks = run_intake(req, work_root=work_root)
    c = {c.check_id: c for c in checks}["intake.stage"]
    assert c.status == "error" and "huggingface_hub" in c.reason
