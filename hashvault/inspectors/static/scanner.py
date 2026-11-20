"""Static scanner: pickle opcodes, safetensors layout, object-dtype npy, custom code.

The scanner reads an ArtifactManifest and the staged files. It does not walk
the caller's original path and it does not deserialize.
"""

import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from hashvault import __version__
from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.manifest import ArtifactManifest, ManifestEntry
from hashvault.inspectors.static.npy import read_npy_header
from hashvault.inspectors.static.pickle_scan import PickleAnalysis, analyze_pickle_file, walk_pickle
from hashvault.inspectors.static.safetensors import analyze_safetensors
from hashvault.policy import Policy, load_policy

INSPECTOR = "static"
_WEIGHT_ROLES = frozenset({"weights", "adapter_weights"})
_PICKLE_FORMATS = frozenset({"pickle", "joblib"})


class InspectorReport(BaseModel):
    inspector: str = INSPECTOR
    version: str
    checks: list[CheckResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


class _Bucket:
    def __init__(self):
        self.checks: list[CheckResult] = []
        self.findings: list[Finding] = []

    def check(self, **kwargs) -> None:
        self.checks.append(CheckResult(**kwargs))

    def finding(self, **kwargs) -> None:
        self.findings.append(Finding(inspector=INSPECTOR, **kwargs))


def _staged_file(manifest: ArtifactManifest, entry: ManifestEntry) -> Path:
    root = Path(manifest.work_dir).resolve()
    path = (root / entry.staged_path).resolve()
    if not path.is_relative_to(root):
        raise OSError(f"staged path escapes the work dir: {entry.staged_path}")
    if not path.is_file():
        raise OSError(f"staged file is missing: {entry.staged_path}")
    return path


def _callable_dicts(analysis: PickleAnalysis) -> list[dict]:
    return [item.as_dict() for item in analysis.callables]


def _emit_pickle(bucket: _Bucket, entry: ManifestEntry, analysis: PickleAnalysis, policy: Policy, started: float) -> None:
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    sev = policy.static.severities
    callables = _callable_dicts(analysis)
    base = {
        "path": entry.path,
        "protocol": analysis.protocol,
        "opcode_count": analysis.opcode_count,
        "callables": callables,
        "trailing_after_stop": analysis.trailing_after_stop,
        "compression": analysis.compression,
    }
    if analysis.error:
        bucket.check(
            check_id="pickle_opcode_scan",
            status="error",
            duration_ms=elapsed,
            reason=analysis.error,
            details=base,
        )
    else:
        bucket.check(
            check_id="pickle_opcode_scan",
            status="passed",
            duration_ms=elapsed,
            details=base,
        )

    if analysis.dangerous:
        bucket.check(
            check_id="pickle_dangerous_callable",
            status="failed",
            duration_ms=elapsed,
            severity=sev.pickle_dangerous_callable,
            reason="pickle references a callable that can run code or touch the system",
            details={"path": entry.path, "callables": [c.as_dict() for c in analysis.dangerous]},
        )
        for item in analysis.dangerous:
            bucket.finding(
                check_id="pickle_dangerous_callable",
                severity=sev.pickle_dangerous_callable,
                message=f"pickle references dangerous callable {item.module}.{item.name}",
                location=entry.path,
                evidence={
                    "module": item.module,
                    "name": item.name,
                    "opcode": item.opcode,
                    "file": entry.path,
                    "position": item.position,
                    "opcodes": item.opcodes,
                },
            )
    elif analysis.error:
        bucket.check(
            check_id="pickle_dangerous_callable",
            status="error",
            duration_ms=elapsed,
            reason="pickle opcode scan did not complete",
            details={"path": entry.path},
        )

    if not analysis.dangerous and not analysis.error:
        bucket.check(
            check_id="pickle_dangerous_callable",
            status="passed",
            duration_ms=elapsed,
            details={"path": entry.path, "callables": callables},
        )

    if analysis.unknown:
        bucket.check(
            check_id="pickle_unknown_global",
            status="failed",
            duration_ms=elapsed,
            severity=sev.pickle_unknown_global,
            reason="pickle references a global that is not on the safe or dangerous list",
            details={"path": entry.path, "callables": [c.as_dict() for c in analysis.unknown]},
        )
        for item in analysis.unknown:
            label = f"{item.module}.{item.name}" if item.module and item.name else (item.name or item.opcode)
            bucket.finding(
                check_id="pickle_unknown_global",
                severity=sev.pickle_unknown_global,
                message=f"pickle references unknown global {label}",
                location=entry.path,
                evidence={
                    "module": item.module,
                    "name": item.name,
                    "opcode": item.opcode,
                    "file": entry.path,
                    "position": item.position,
                    "resolved": item.resolved,
                },
            )
    elif not analysis.error:
        bucket.check(
            check_id="pickle_unknown_global",
            status="passed",
            duration_ms=elapsed,
            details={"path": entry.path, "callables": []},
        )


def _scan_pickle(bucket: _Bucket, manifest: ArtifactManifest, entry: ManifestEntry, policy: Policy) -> None:
    started = time.perf_counter()
    analysis = analyze_pickle_file(
        _staged_file(manifest, entry),
        max_bytes=policy.intake.limits.max_total_bytes,
        allow_compressed=entry.detected_format == "joblib",
    )
    _emit_pickle(bucket, entry, analysis, policy, started)


def _scan_safetensors(bucket: _Bucket, manifest: ArtifactManifest, entry: ManifestEntry, policy: Policy) -> None:
    started = time.perf_counter()
    analysis = analyze_safetensors(
        _staged_file(manifest, entry),
        max_header_bytes=policy.intake.limits.max_safetensors_header_bytes,
    )
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    sev = policy.static.severities
    structure = analysis.structure
    bucket.check(
        check_id="safetensors_structure",
        status=structure.status,
        duration_ms=elapsed,
        severity=sev.safetensors_structure if structure.status == "failed" else None,
        reason=structure.reason,
        details={"path": entry.path, **structure.evidence},
    )
    if structure.status == "failed":
        bucket.finding(
            check_id="safetensors_structure",
            severity=sev.safetensors_structure,
            message=f"safetensors structure: {structure.reason}",
            location=entry.path,
            evidence={"file": entry.path, **structure.evidence},
        )
    trailing = analysis.trailing
    bucket.check(
        check_id="safetensors_trailing_bytes",
        status=trailing.status,
        duration_ms=elapsed,
        severity=sev.safetensors_trailing_bytes if trailing.status == "failed" else None,
        reason=trailing.reason,
        details={"path": entry.path, **trailing.evidence},
    )
    if trailing.status == "failed":
        bucket.finding(
            check_id="safetensors_trailing_bytes",
            severity=sev.safetensors_trailing_bytes,
            message=f"safetensors trailing bytes: {trailing.reason}",
            location=entry.path,
            evidence={"file": entry.path, **trailing.evidence},
        )


def _scan_npy(bucket: _Bucket, manifest: ArtifactManifest, entry: ManifestEntry, policy: Policy) -> None:
    started = time.perf_counter()
    path = _staged_file(manifest, entry)
    max_header = policy.intake.limits.max_safetensors_header_bytes
    with open(path, "rb") as fh:
        header = read_npy_header(fh, max_header_bytes=max_header)
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        sev = policy.static.severities
        if header.error:
            bucket.check(
                check_id="npy_object_dtype",
                status="error",
                duration_ms=elapsed,
                reason=header.error,
                details={"path": entry.path},
            )
            return
        if header.is_object:
            bucket.check(
                check_id="npy_object_dtype",
                status="failed",
                duration_ms=elapsed,
                severity=sev.npy_object_dtype,
                reason="NumPy object dtype embeds a pickle",
                details={"path": entry.path, "descr": header.descr, "data_offset": header.data_offset},
            )
            bucket.finding(
                check_id="npy_object_dtype",
                severity=sev.npy_object_dtype,
                message="NumPy dtype is object; the file embeds a pickle",
                location=entry.path,
                evidence={
                    "file": entry.path,
                    "descr": header.descr,
                    "data_offset": header.data_offset,
                },
            )
            tail_started = time.perf_counter()
            analysis = walk_pickle(fh)
            _emit_pickle(bucket, entry, analysis, policy, tail_started)
            return
        bucket.check(
            check_id="npy_object_dtype",
            status="passed",
            duration_ms=elapsed,
            details={"path": entry.path, "descr": header.descr, "object_dtype": False},
        )


def _scan_torch_zip(bucket: _Bucket, entry: ManifestEntry, entries: list[ManifestEntry]) -> None:
    inners = [
        child.path for child in entries
        if child.parent == entry.path and child.path.rsplit("/", 1)[-1] == "data.pkl"
    ]
    if inners:
        bucket.check(
            check_id="weight_coverage",
            status="passed",
            details={"path": entry.path, "detected_format": "torch_zip", "inner_pickle": inners},
        )
        return
    bucket.check(
        check_id="weight_coverage",
        status="error",
        reason="torch_zip contains no data.pkl",
        details={"path": entry.path, "detected_format": "torch_zip"},
    )


def _error_check_id(entry: ManifestEntry) -> str:
    if entry.detected_format in _PICKLE_FORMATS:
        return "pickle_opcode_scan"
    if entry.detected_format == "safetensors":
        return "safetensors_structure"
    if entry.detected_format == "npy":
        return "npy_object_dtype"
    return "weight_coverage"


def _scan_entry(manifest: ArtifactManifest, entry: ManifestEntry, entries: list[ManifestEntry], policy: Policy) -> _Bucket:
    bucket = _Bucket()
    fmt = entry.detected_format
    if fmt in _PICKLE_FORMATS:
        _scan_pickle(bucket, manifest, entry, policy)
    elif fmt == "safetensors":
        _scan_safetensors(bucket, manifest, entry, policy)
    elif fmt == "npy":
        _scan_npy(bucket, manifest, entry, policy)
    elif fmt == "torch_zip":
        _scan_torch_zip(bucket, entry, entries)
    return bucket


def _custom_code(manifest: ArtifactManifest, policy: Policy) -> _Bucket:
    bucket = _Bucket()
    problems = []
    for entry in manifest.entries:
        if entry.detected_format == "python" or entry.role == "code" or entry.extension_format == "python":
            problems.append({"path": entry.path, "reason": "python source"})
    auto_map = manifest.claims.get("auto_map")
    if auto_map:
        source = (manifest.claims.get("claim_sources") or {}).get("config", "config.json")
        problems.append({"path": source, "reason": "auto_map", "auto_map": auto_map})
    sev = policy.static.severities.custom_code_present
    if not problems:
        bucket.check(check_id="custom_code_present", status="passed", details={"files": []})
        return bucket
    bucket.check(
        check_id="custom_code_present",
        status="failed",
        severity=sev,
        reason="custom code present",
        details={"files": problems},
    )
    for problem in problems:
        if problem["reason"] == "auto_map":
            message = "config claims auto_map"
            evidence = {"file": problem["path"], "auto_map": problem["auto_map"]}
        else:
            message = f"python source file {problem['path']}"
            evidence = {"file": problem["path"], "reason": "python source"}
        bucket.finding(
            check_id="custom_code_present",
            severity=sev,
            message=message,
            location=problem["path"],
            evidence=evidence,
        )
    return bucket


def _checked_paths(checks: list[CheckResult]) -> set[str]:
    found = set()
    for check in checks:
        path = check.details.get("path")
        if isinstance(path, str):
            found.add(path)
    return found


def _cover_weights(entries: list[ManifestEntry], checks: list[CheckResult]) -> list[CheckResult]:
    seen = _checked_paths(checks)
    extra = []
    for entry in entries:
        if entry.role not in _WEIGHT_ROLES or entry.path in seen:
            continue
        if entry.detected_format in {"unknown", "unsupported"}:
            extra.append(CheckResult(
                check_id="weight_coverage",
                status="skipped",
                reason="unsupported_format",
                details={"path": entry.path, "detected_format": entry.detected_format},
            ))
        else:
            extra.append(CheckResult(
                check_id="weight_coverage",
                status="error",
                reason="weight entry produced no static check",
                details={"path": entry.path, "detected_format": entry.detected_format},
            ))
    return extra


def _coverage(manifest: ArtifactManifest, checks: list[CheckResult]) -> dict[str, Any]:
    by_path: dict[str, list[str]] = {}
    for check in checks:
        path = check.details.get("path")
        if isinstance(path, str):
            by_path.setdefault(path, []).append(check.check_id)
    formats: dict[str, int] = {}
    weights = []
    for entry in manifest.entries:
        formats[entry.detected_format] = formats.get(entry.detected_format, 0) + 1
        if entry.role in _WEIGHT_ROLES:
            weights.append({
                "path": entry.path,
                "detected_format": entry.detected_format,
                "role": entry.role,
                "checks": by_path.get(entry.path, []),
            })
    return {
        "entries_total": len(manifest.entries),
        "weight_entries": weights,
        "formats": formats,
        "limitations": [
            "Opcodes are disassembled with pickletools and never executed.",
            "The callable denylist is not a complete gadget catalog; unknown globals are warnings, not passes.",
            "A pickle stream is scanned until the first STOP. Bytes after STOP are an error, not a pass.",
            "Provenance and behavioural inspectors are not part of this scanner.",
        ],
    }


def scan_static(manifest: ArtifactManifest, policy: Policy | None = None) -> InspectorReport:
    """Scan staged manifest entries. One file's exception does not stop the rest."""
    policy = policy or load_policy("strict")
    entries = list(manifest.entries)
    checks: list[CheckResult] = []
    findings: list[Finding] = []
    for entry in entries:
        try:
            bucket = _scan_entry(manifest, entry, entries, policy)
        except Exception as exc:
            bucket = _Bucket()
            bucket.check(
                check_id=_error_check_id(entry),
                status="error",
                reason=f"{type(exc).__name__}: {exc}",
                details={"path": entry.path},
            )
        checks.extend(bucket.checks)
        findings.extend(bucket.findings)
    try:
        custom = _custom_code(manifest, policy)
    except Exception as exc:
        custom = _Bucket()
        custom.check(check_id="custom_code_present", status="error", reason=f"{type(exc).__name__}: {exc}")
    checks.extend(custom.checks)
    findings.extend(custom.findings)
    checks.extend(_cover_weights(entries, checks))
    return InspectorReport(
        version=__version__,
        checks=checks,
        findings=findings,
        coverage=_coverage(manifest, checks),
    )
