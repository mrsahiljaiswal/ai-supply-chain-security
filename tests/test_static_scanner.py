"""Static scanner tests. Fixtures are generated in-process; nothing here is a real exploit."""

import json
import pickle
import pickletools
import struct
import zlib
from collections import OrderedDict
from pathlib import Path

import pytest
from typer.testing import CliRunner

import generate
from hashvault.cli import app
from hashvault.contracts.request import ScanRequest
from hashvault.inspectors.static import scan_static
from hashvault.intake.pipeline import run_intake
from hashvault.policy import load_policy

runner = CliRunner()


def global_reduce(module: str, name: str) -> bytes:
    """Protocol-2 GLOBAL + REDUCE bytes. Built with struct, never loaded."""
    return b"\x80\x02c" + module.encode("ascii") + b"\n" + name.encode("ascii") + b"\n)R."


def stack_global_reduce(module: str, name: str) -> bytes:
    """Protocol-4 STACK_GLOBAL + REDUCE. Strings are SHORT_BINUNICODE, not loaded."""
    def short(text: str) -> bytes:
        raw = text.encode("ascii")
        return bytes((0x8C, len(raw))) + raw

    return b"\x80\x04" + short(module) + short(name) + b"\x93)R."


def npy_bytes(descr: str, shape: tuple, payload: bytes) -> bytes:
    literal = "{'descr': %r, 'fortran_order': False, 'shape': %r, }" % (descr, shape)
    body = literal.encode("latin-1") + b"\n"
    return b"\x93NUMPY" + bytes((1, 0)) + struct.pack("<H", len(body)) + body + payload


def safetensors_past_eof() -> bytes:
    header = {"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 100]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    return struct.pack("<Q", len(raw)) + raw


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def scan_at(artifact, work_root, **kw):
    req = ScanRequest(artifact=str(artifact), **kw)
    policy = load_policy(req.policy_profile)
    manifest, _intake = run_intake(req, policy, work_root=work_root)
    return manifest, scan_static(manifest, policy)


def of(report, check_id, path_suffix=None):
    found = []
    for check in report.checks:
        if check.check_id != check_id:
            continue
        path = str(check.details.get("path", ""))
        if path_suffix is None or path.endswith(path_suffix):
            found.append(check)
    return found


def test_builder_global_is_not_executed():
    blob = global_reduce("os", "system")
    ops = [(op.name, arg) for op, arg, _pos in pickletools.genops(blob)]
    assert ("GLOBAL", "os system") in ops
    assert ops[-1][0] == "STOP"
    assert b"os" in blob and b"system" in blob


def test_clean_safetensors_model(fixtures, work_root):
    _manifest, report = scan_at(fixtures["full_model"], work_root, claimed_base_model="Qwen/Qwen2.5-0.5B")
    structure = of(report, "safetensors_structure", "model.safetensors")
    trailing = of(report, "safetensors_trailing_bytes", "model.safetensors")
    assert len(structure) == 1 and structure[0].status == "passed"
    assert len(trailing) == 1 and trailing[0].status == "passed"
    assert report.findings == []
    assert of(report, "custom_code_present")[0].status == "passed"


def test_safetensors_trailing_bytes_are_critical(tmp_path, work_root):
    blob = generate.safetensors_bytes({"w": [4]}) + b"TRAILER"
    path = write(tmp_path / "trail" / "model.safetensors", blob)
    _manifest, report = scan_at(path.parent, work_root)
    trailing = of(report, "safetensors_trailing_bytes", "model.safetensors")
    assert trailing[0].status == "failed"
    assert trailing[0].severity == "critical"
    assert trailing[0].details["trailing_bytes"] == len(b"TRAILER")
    findings = [f for f in report.findings if f.check_id == "safetensors_trailing_bytes"]
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].evidence["file"].endswith("model.safetensors")
    assert of(report, "safetensors_structure", "model.safetensors")[0].status == "passed"


def test_safetensors_offset_past_eof_is_critical(tmp_path, work_root):
    path = write(tmp_path / "oob" / "model.safetensors", safetensors_past_eof())
    _manifest, report = scan_at(path.parent, work_root)
    structure = of(report, "safetensors_structure", "model.safetensors")
    assert structure[0].status == "failed"
    assert structure[0].severity == "critical"
    findings = [f for f in report.findings if f.check_id == "safetensors_structure"]
    assert len(findings) == 1 and findings[0].severity == "critical"
    assert findings[0].evidence["end"] == 100
    assert "out of range" in findings[0].message


def test_plain_dict_pickle_passes(tmp_path, work_root):
    blob = pickle.dumps({"marker": "hashvault-fixture", "n": 1}, protocol=4)
    path = write(tmp_path / "dict" / "model.pkl", blob)
    _manifest, report = scan_at(path.parent, work_root)
    scan = of(report, "pickle_opcode_scan", "model.pkl")
    assert len(scan) == 1 and scan[0].status == "passed"
    assert scan[0].details["callables"] == []
    assert not any(f.severity == "critical" for f in report.findings)
    assert of(report, "pickle_dangerous_callable", "model.pkl")[0].status == "passed"


@pytest.mark.parametrize("protocol", [0, 2, 4, 5])
def test_nested_dict_protocols_pass(tmp_path, work_root, protocol):
    blob = pickle.dumps({"a": 1, "b": [1, 2, {"c": "d"}]}, protocol=protocol)
    path = write(tmp_path / f"p{protocol}" / "model.pkl", blob)
    _manifest, report = scan_at(path.parent, work_root)
    assert of(report, "pickle_opcode_scan", "model.pkl")[0].status == "passed"
    assert not any(f.severity == "critical" for f in report.findings)


def test_ordered_dict_rebuild_is_not_critical(tmp_path, work_root):
    blob = pickle.dumps(OrderedDict([("a", 1)]), protocol=4)
    path = write(tmp_path / "od" / "model.pkl", blob)
    _manifest, report = scan_at(path.parent, work_root)
    dangerous = of(report, "pickle_dangerous_callable", "model.pkl")[0]
    assert dangerous.status == "passed"
    listed = json.dumps(dangerous.details["callables"])
    assert "collections" in listed and "OrderedDict" in listed
    assert not any(f.severity == "critical" for f in report.findings)
    assert of(report, "pickle_unknown_global", "model.pkl")[0].status == "passed"


def test_os_system_global_is_critical(tmp_path, work_root):
    path = write(tmp_path / "evil" / "model.pkl", global_reduce("os", "system"))
    _manifest, report = scan_at(path.parent, work_root)
    findings = [f for f in report.findings if f.check_id == "pickle_dangerous_callable"]
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].evidence["module"] == "os"
    assert findings[0].evidence["name"] == "system"
    assert findings[0].evidence["opcode"] == "GLOBAL"
    assert findings[0].evidence["file"].endswith("model.pkl")
    failed = of(report, "pickle_dangerous_callable", "model.pkl")[0]
    assert failed.status == "failed" and failed.severity == "critical"
    assert of(report, "pickle_opcode_scan", "model.pkl")[0].status == "passed"


def test_os_system_stack_global_is_critical(tmp_path, work_root):
    path = write(tmp_path / "stack" / "model.pkl", stack_global_reduce("os", "system"))
    _manifest, report = scan_at(path.parent, work_root)
    finding = next(f for f in report.findings if f.check_id == "pickle_dangerous_callable")
    assert finding.evidence["module"] == "os"
    assert finding.evidence["name"] == "system"
    assert finding.evidence["opcode"] == "STACK_GLOBAL"
    assert finding.severity == "critical"


def test_unknown_global_is_warning_not_critical(tmp_path, work_root):
    path = write(tmp_path / "unk" / "model.pkl", global_reduce("foo.bar", "Baz"))
    _manifest, report = scan_at(path.parent, work_root)
    unknown = of(report, "pickle_unknown_global", "model.pkl")[0]
    assert unknown.status == "failed" and unknown.severity == "warning"
    assert unknown.status != "passed"
    findings = [f for f in report.findings if f.check_id == "pickle_unknown_global"]
    assert len(findings) == 1
    assert findings[0].evidence["module"] == "foo.bar"
    assert findings[0].evidence["name"] == "Baz"
    assert not any(f.severity == "critical" for f in report.findings)
    assert of(report, "pickle_dangerous_callable", "model.pkl")[0].status == "passed"


def test_truncated_pickle_is_error_not_passed(tmp_path, work_root):
    path = write(tmp_path / "trunc" / "model.pkl", b"\x80\x04")
    _manifest, report = scan_at(path.parent, work_root)
    scan = of(report, "pickle_opcode_scan", "model.pkl")
    assert len(scan) == 1
    assert scan[0].status == "error"
    assert scan[0].status != "passed"
    assert scan[0].reason
    assert not any(c.status == "passed" and c.check_id == "pickle_opcode_scan" for c in report.checks)
    assert not any(f.severity == "critical" for f in report.findings)


def test_npy_object_dtype_is_critical_and_tail_is_scanned(tmp_path, work_root):
    payload = pickle.dumps({"k": 1}, protocol=4)
    path = write(tmp_path / "obj" / "weights.npy", npy_bytes("|O", (1,), payload))
    _manifest, report = scan_at(path.parent, work_root)
    npy = of(report, "npy_object_dtype", "weights.npy")[0]
    assert npy.status == "failed" and npy.severity == "critical"
    findings = [f for f in report.findings if f.check_id == "npy_object_dtype"]
    assert len(findings) == 1 and findings[0].severity == "critical"
    assert findings[0].evidence["descr"] == "|O"
    assert of(report, "pickle_opcode_scan", "weights.npy")[0].status == "passed"


def test_npy_object_tail_with_os_system(tmp_path, work_root):
    path = write(tmp_path / "objbad" / "weights.npy", npy_bytes("|O", (1,), global_reduce("os", "system")))
    _manifest, report = scan_at(path.parent, work_root)
    assert any(f.check_id == "npy_object_dtype" and f.severity == "critical" for f in report.findings)
    dangerous = [f for f in report.findings if f.check_id == "pickle_dangerous_callable"]
    assert len(dangerous) == 1
    assert dangerous[0].evidence["module"] == "os" and dangerous[0].evidence["name"] == "system"


def test_npy_structured_object_field_is_critical(tmp_path, work_root):
    literal = "{'descr': [('a', '<f4'), ('b', '|O')], 'fortran_order': False, 'shape': (1,), }"
    body = literal.encode("latin-1") + b"\n"
    blob = b"\x93NUMPY" + bytes((1, 0)) + struct.pack("<H", len(body)) + body
    blob += pickle.dumps({"k": 1}, protocol=4)
    path = write(tmp_path / "struct" / "weights.npy", blob)
    _manifest, report = scan_at(path.parent, work_root)
    npy = of(report, "npy_object_dtype", "weights.npy")[0]
    assert npy.status == "failed" and npy.severity == "critical"


def test_safetensors_gap_is_critical(tmp_path, work_root):
    header = {
        "a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        "b": {"dtype": "F32", "shape": [1], "data_offsets": [8, 12]},
    }
    raw = json.dumps(header, separators=(",", ":")).encode()
    blob = struct.pack("<Q", len(raw)) + raw + b"\x00" * 12
    path = write(tmp_path / "gap" / "model.safetensors", blob)
    _manifest, report = scan_at(path.parent, work_root)
    structure = of(report, "safetensors_structure", "model.safetensors")[0]
    assert structure.status == "failed" and structure.severity == "critical"
    assert "gap" in structure.reason


def test_torch_rebuild_helpers_are_not_critical(tmp_path, work_root):
    folder = tmp_path / "rebuild"
    folder.mkdir()
    write(folder / "rebuild.pkl", global_reduce("torch._utils", "_rebuild_tensor_v2"))
    write(folder / "storage.pkl", global_reduce("torch", "FloatStorage"))
    write(folder / "numpy.pkl", global_reduce("numpy.core.multiarray", "_reconstruct"))
    _manifest, report = scan_at(folder, work_root)
    assert not any(f.severity == "critical" for f in report.findings)
    for name in ("rebuild.pkl", "storage.pkl", "numpy.pkl"):
        dangerous = of(report, "pickle_dangerous_callable", name)[0]
        assert dangerous.status == "passed", name
        assert of(report, "pickle_unknown_global", name)[0].status == "passed"


def test_torch_zip_inner_pickle_is_scanned(fixtures, work_root):
    _manifest, report = scan_at(fixtures["torch_checkpoint"], work_root)
    inner = of(report, "pickle_opcode_scan", "data.pkl")
    assert len(inner) == 1 and inner[0].status == "passed"
    outer = of(report, "weight_coverage", "pytorch_model.bin")
    assert len(outer) == 1 and outer[0].status == "passed"
    assert any(path.endswith("data.pkl") for path in outer[0].details["inner_pickle"])
    assert not any(f.severity == "critical" for f in report.findings)


def test_npy_float_dtype_is_not_object(tmp_path, work_root):
    path = write(tmp_path / "f32" / "weights.npy", npy_bytes("<f4", (2,), struct.pack("<2f", 1.0, 2.0)))
    _manifest, report = scan_at(path.parent, work_root)
    npy = of(report, "npy_object_dtype", "weights.npy")[0]
    assert npy.status == "passed"
    assert not any(f.check_id == "npy_object_dtype" for f in report.findings)
    assert of(report, "pickle_opcode_scan", "weights.npy") == []


def test_auto_map_is_warning(tmp_path, work_root):
    folder = tmp_path / "mapped"
    folder.mkdir()
    cfg = dict(generate.CONFIG, auto_map={"AutoModel": "modeling_x.XModel"})
    (folder / "config.json").write_text(json.dumps(cfg))
    _manifest, report = scan_at(folder, work_root)
    check = of(report, "custom_code_present")[0]
    assert check.status == "failed" and check.severity == "warning"
    findings = [f for f in report.findings if f.check_id == "custom_code_present"]
    assert len(findings) == 1 and findings[0].severity == "warning"
    assert findings[0].evidence["auto_map"]["AutoModel"] == "modeling_x.XModel"


def test_python_file_is_warning(tmp_path, work_root):
    folder = tmp_path / "code"
    folder.mkdir()
    (folder / "modeling.py").write_text("class X: pass\n")
    (folder / "model.safetensors").write_bytes(generate.safetensors_bytes({"w": [2]}))
    _manifest, report = scan_at(folder, work_root)
    findings = [f for f in report.findings if f.check_id == "custom_code_present"]
    assert len(findings) == 1 and findings[0].severity == "warning"
    assert findings[0].evidence["file"].endswith("modeling.py")


def test_truncated_then_os_system_both_reported(tmp_path, work_root):
    folder = tmp_path / "both"
    folder.mkdir()
    write(folder / "0-trunc.pkl", b"\x80\x02cos\nsys")
    write(folder / "1-system.pkl", global_reduce("os", "system"))
    _manifest, report = scan_at(folder, work_root)
    trunc = of(report, "pickle_opcode_scan", "0-trunc.pkl")
    assert len(trunc) == 1 and trunc[0].status == "error"
    system = [f for f in report.findings if f.evidence.get("name") == "system"]
    assert len(system) == 1
    assert system[0].severity == "critical"
    assert system[0].evidence["module"] == "os"
    assert system[0].evidence["file"].endswith("1-system.pkl")
    assert of(report, "pickle_opcode_scan", "1-system.pkl")[0].status == "passed"


def test_exception_on_one_file_does_not_skip_the_other(monkeypatch, tmp_path, work_root):
    folder = tmp_path / "boom"
    folder.mkdir()
    write(folder / "a.pkl", pickle.dumps({"a": 1}, protocol=4))
    write(folder / "b.pkl", global_reduce("os", "system"))
    real = __import__(
        "hashvault.inspectors.static.pickle_scan", fromlist=["analyze_pickle_file"]
    ).analyze_pickle_file

    def boom(path, **kwargs):
        if path.name == "a.pkl":
            raise RuntimeError("scanner blew up")
        return real(path, **kwargs)

    monkeypatch.setattr("hashvault.inspectors.static.scanner.analyze_pickle_file", boom)
    _manifest, report = scan_at(folder, work_root)
    broken = of(report, "pickle_opcode_scan", "a.pkl")
    assert len(broken) == 1 and broken[0].status == "error"
    assert "scanner blew up" in broken[0].reason
    assert any(f.evidence.get("module") == "os" and f.evidence.get("file", "").endswith("b.pkl")
               for f in report.findings)


def test_unsupported_weight_is_skipped_not_passed(fixtures, work_root):
    _manifest, report = scan_at(fixtures["gguf"], work_root)
    skipped = of(report, "weight_coverage", "model.gguf")
    assert len(skipped) == 1
    assert skipped[0].status == "skipped"
    assert skipped[0].reason == "unsupported_format"
    assert skipped[0].status != "passed"


def test_joblib_zlib_dict_passes(tmp_path, work_root):
    blob = zlib.compress(pickle.dumps({"a": 1}, protocol=4))
    path = write(tmp_path / "job" / "model.joblib", blob)
    _manifest, report = scan_at(path.parent, work_root)
    scan = of(report, "pickle_opcode_scan", "model.joblib")
    assert scan[0].status == "passed"
    assert scan[0].details["compression"] == "zlib"
    assert not any(f.severity == "critical" for f in report.findings)


def test_severity_is_taken_from_policy(tmp_path, work_root):
    path = write(tmp_path / "sev" / "model.pkl", global_reduce("os", "system"))
    req = ScanRequest(artifact=str(path.parent))
    policy = load_policy("strict")
    policy.static.severities.pickle_dangerous_callable = "warning"
    manifest, _intake = run_intake(req, policy, work_root=work_root)
    report = scan_static(manifest, policy)
    finding = next(f for f in report.findings if f.check_id == "pickle_dangerous_callable")
    assert finding.severity == "warning"
    assert of(report, "pickle_dangerous_callable", "model.pkl")[0].severity == "warning"


def _findings(payload):
    return [item for report in payload["reports"] for item in report["findings"]]


def test_cli_scan_os_system_exits_30(tmp_path, work_root):
    path = write(tmp_path / "cli-evil.pkl", global_reduce("os", "system"))
    result = runner.invoke(app, ["scan", str(path), "--work-dir", str(work_root), "--out", str(tmp_path / "out")])
    assert result.exit_code == 30, result.stdout
    payload = json.loads(result.stdout)
    assert payload["verdict"]["classification"] == "Blocked"
    assert payload["verdict"]["rule_id"] == "rule_critical"
    findings = _findings(payload)
    assert findings[0]["evidence"]["module"] == "os"
    assert findings[0]["evidence"]["name"] == "system"
    assert result.exit_code != 0


def test_cli_scan_clean_model_exits_20(fixtures, work_root, tmp_path):
    result = runner.invoke(app, [
        "scan", str(fixtures["full_model"]),
        "--base", "Qwen/Qwen2.5-0.5B",
        "--work-dir", str(work_root),
        "--out", str(tmp_path / "out"),
    ])
    assert result.exit_code == 20, result.stdout
    payload = json.loads(result.stdout)
    assert payload["verdict"]["classification"] == "Undetermined"
    assert payload["verdict"]["rule_id"] == "rule_insufficient_evidence"
    assert "Undetermined" in payload["verdict"]["reason"]
    assert "behavioural inspector has not run" in payload["verdict"]["reason"]
    assert _findings(payload) == []
    assert result.exit_code != 0
