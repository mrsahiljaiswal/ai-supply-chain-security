import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from hashvault.contracts.checks import CheckResult
from hashvault.contracts.manifest import ArtifactManifest, ManifestEntry
from hashvault.contracts.request import ScanRequest
from hashvault.intake.archive import expand_archive
from hashvault.intake.claims import extract_claims, safetensors_param_count
from hashvault.intake.classify import assign_role, basename, classify
from hashvault.intake.detect import ARCHIVE_FORMATS, detect_format, extension_format, is_compatible
from hashvault.intake.hashing import root_hash
from hashvault.intake.stage import (
    StageError,
    create_work_dir,
    default_work_root,
    new_scan_id,
    stage_hub,
    stage_local,
)
from hashvault.intake.walk import (
    ArchiveCorrupt,
    IntakeState,
    LimitExceeded,
    StagedItem,
    make_read_only,
    make_writable,
)
from hashvault.policy import Policy, load_policy

_TORCH_STORAGE_RE = re.compile(r"(^|/)data/\d+$")


class _Timer:
    def __init__(self):
        self._t = time.perf_counter()

    def lap(self) -> float:
        now = time.perf_counter()
        ms, self._t = (now - self._t) * 1000, now
        return round(ms, 3)


def _detect(item: StagedItem, max_parse: int) -> str:
    member = item.path.rsplit("!/", 1)[-1]
    if item.in_torch_zip and _TORCH_STORAGE_RE.search(member):
        return "torch_storage"
    return detect_format(item.fs_path, member, max_parse)


def _discard_staged(state: IntakeState) -> None:
    for d in (state.artifact_dir, state.expanded_dir, state.work_dir / "download"):
        make_writable(d)
        shutil.rmtree(d, ignore_errors=True)


def _limits_dict(policy: Policy) -> dict[str, int]:
    return policy.intake.limits.model_dump()


def run_intake(
    request: ScanRequest,
    policy: Policy | None = None,
    work_root: Path | None = None,
) -> tuple[ArtifactManifest, list[CheckResult]]:
    policy = policy or load_policy(request.policy_profile)
    limits = policy.intake.limits
    sev = policy.intake.severities
    staged_at = datetime.now(timezone.utc)
    scan_id = new_scan_id(staged_at)
    work_dir = create_work_dir(Path(work_root or default_work_root()), scan_id).resolve()
    state = IntakeState(work_dir=work_dir, limits=limits)
    checks: list[CheckResult] = []
    timer = _Timer()

    hub = not request.is_local
    source = "hf_hub" if hub else ("local_dir" if Path(request.artifact).is_dir() else "local_file")
    source_ref = request.artifact if hub else str(Path(request.artifact).resolve())
    resolved_revision = None

    def manifest(**kw) -> ArtifactManifest:
        base = dict(
            scan_id=scan_id,
            source=source,
            source_ref=source_ref,
            resolved_revision=resolved_revision,
            work_dir=str(work_dir),
            staged_at_utc=staged_at,
            limits_applied=_limits_dict(policy),
        )
        base.update(kw)
        return ArtifactManifest(**base)

    def abort(check_id: str, exc: Exception, limit: str | None = None):
        _discard_staged(state)
        details = {"staged_files_discarded": True, "files_seen": state.file_count,
                   "bytes_seen": state.total_bytes}
        if limit:
            details["limit"] = limit
            details["limit_value"] = getattr(limits, limit)
        checks.append(CheckResult(check_id=check_id, status="error", duration_ms=timer.lap(),
                                  reason=str(exc), details=details))
        return manifest(complete=False), checks

    try:
        if hub:
            resolved_revision = stage_hub(request, state)
        else:
            stage_local(request, state)
    except LimitExceeded as exc:
        return abort("intake.limits", exc, exc.limit)
    except (StageError, OSError) as exc:
        return abort("intake.stage", exc)
    checks.append(CheckResult(check_id="intake.stage", status="passed", duration_ms=timer.lap(),
                              details={"files_staged": len(state.items)}))

    archives = 0
    corrupt: list[dict] = []
    unreadable: list[dict] = []
    try:
        i = 0
        while i < len(state.items):
            item = state.items[i]
            i += 1
            try:
                item.detected_format = _detect(item, limits.max_config_bytes)
            except OSError as exc:
                item.detected_format = "unknown"
                unreadable.append({"path": item.path, "reason": str(exc)})
                continue
            if item.detected_format in ARCHIVE_FORMATS:
                archives += 1
                try:
                    expand_archive(item, state)
                except ArchiveCorrupt as exc:
                    corrupt.append({"path": item.path, "reason": str(exc)})
    except LimitExceeded as exc:
        return abort("intake.limits", exc, exc.limit)
    expand_ms = timer.lap()

    checks.append(CheckResult(
        check_id="intake.limits", status="passed",
        details={"files": state.file_count, "total_bytes": state.total_bytes,
                 "max_depth": max((it.depth for it in state.items), default=0)},
    ))

    if source == "local_file" and state.items and state.items[0].detected_format in (
        ARCHIVE_FORMATS - {"torch_zip"}
    ):
        source = "local_archive"

    entries: list[ManifestEntry] = []
    for item in state.items:
        member = item.path.rsplit("!/", 1)[-1]
        fmt = item.detected_format or "unknown"
        entries.append(ManifestEntry(
            path=item.path,
            parent=item.parent,
            depth=item.depth,
            size_bytes=item.size,
            sha256=item.sha256,
            detected_format=fmt,
            extension_format=extension_format(member),
            role=assign_role(item.path, fmt),
            staged_path=state.rel(item.fs_path),
        ))

    checks.append(CheckResult(
        check_id="intake.inventory",
        status="error" if unreadable else "passed",
        reason="unreadable files" if unreadable else None,
        details={"entries": len(entries), "unreadable": unreadable} if unreadable
        else {"entries": len(entries)},
    ))

    if archives == 0:
        checks.append(CheckResult(check_id="intake.archive_expansion", status="not_applicable",
                                  duration_ms=expand_ms))
    elif corrupt:
        checks.append(CheckResult(check_id="intake.archive_expansion", status="error",
                                  duration_ms=expand_ms, reason="corrupt or unreadable archive",
                                  details={"archives": corrupt}))
    else:
        checks.append(CheckResult(check_id="intake.archive_expansion", status="passed",
                                  duration_ms=expand_ms, details={"archives": archives}))

    rejected = state.issues.get("intake.archive_member_rejected", [])
    if rejected:
        checks.append(CheckResult(check_id="intake.archive_member_rejected", status="failed",
                                  severity=sev.archive_member_rejected,
                                  reason="unsafe archive members were not extracted",
                                  details={"members": rejected}))
    else:
        checks.append(CheckResult(check_id="intake.archive_member_rejected",
                                  status="passed" if archives else "not_applicable"))

    special = state.issues.get("intake.special_files", [])
    if special:
        checks.append(CheckResult(check_id="intake.special_files", status="failed",
                                  severity=sev.local_special_file,
                                  reason="symlinks, hardlinks or special files in the source",
                                  details={"items": special}))
    else:
        checks.append(CheckResult(check_id="intake.special_files", status="passed"))

    mismatches = [
        {"path": e.path, "extension_format": e.extension_format, "detected_format": e.detected_format}
        for e in entries
        if e.detected_format != "torch_storage" and not is_compatible(e.extension_format, e.detected_format)
    ]
    checks.append(CheckResult(
        check_id="intake.format_mismatch",
        status="failed" if mismatches else "passed",
        severity=sev.format_mismatch if mismatches else None,
        reason="file extension does not match magic bytes" if mismatches else None,
        details={"files": mismatches} if mismatches else {},
    ))

    unsupported = [{"path": e.path, "extension_format": e.extension_format}
                   for e in entries if e.detected_format == "unsupported"]
    checks.append(CheckResult(
        check_id="intake.unsupported_format",
        status="skipped" if unsupported else "passed",
        reason="unsupported_format" if unsupported else None,
        details={"files": unsupported} if unsupported else {},
    ))

    unknown = [e.path for e in entries if e.detected_format == "unknown"]
    checks.append(CheckResult(
        check_id="intake.unknown_format",
        status="failed" if unknown else "passed",
        severity=sev.unknown_format if unknown else None,
        reason="unknown_format" if unknown else None,
        details={"files": unknown} if unknown else {},
    ))
    timer.lap()

    artifact_type, type_claims = classify((e.path, e.role) for e in entries)
    if request.artifact_type == "auto":
        checks.append(CheckResult(check_id="intake.type_mismatch", status="not_applicable",
                                  details={"detected": artifact_type}))
    elif request.artifact_type != artifact_type:
        checks.append(CheckResult(check_id="intake.type_mismatch", status="failed",
                                  severity=sev.type_mismatch,
                                  reason=f"requested {request.artifact_type}, detected {artifact_type}",
                                  details={"requested": request.artifact_type, "detected": artifact_type}))
    else:
        checks.append(CheckResult(check_id="intake.type_mismatch", status="passed",
                                  details={"detected": artifact_type}))

    by_path = {it.path: it for it in state.items}
    json_entries = [(e.path, e.depth, by_path[e.path].fs_path)
                    for e in entries if e.detected_format == "json"]
    claims, claim_errors = extract_claims(json_entries, limits.max_config_bytes)
    for e in entries:
        if e.detected_format != "json" and basename(e.path) in {"config.json", "adapter_config.json"}:
            claim_errors.append({"path": e.path, "reason": f"not valid JSON (detected {e.detected_format})"})
    claims.update(type_claims)
    python_files = [e.path for e in entries if e.role == "code"]
    claims["custom_code_present"] = bool(python_files or claims.get("auto_map"))
    if python_files:
        claims["python_files"] = python_files

    params = None
    for e in entries:
        if e.detected_format == "safetensors" and e.role in {"weights", "adapter_weights"}:
            n = safetensors_param_count(by_path[e.path].fs_path, limits.max_safetensors_header_bytes)
            if n is not None:
                params = (params or 0) + n

    if claim_errors:
        checks.append(CheckResult(check_id="intake.claims", status="error", duration_ms=timer.lap(),
                                  reason="config could not be read as JSON",
                                  details={"files": claim_errors}))
    elif "claim_sources" in claims:
        checks.append(CheckResult(check_id="intake.claims", status="passed", duration_ms=timer.lap(),
                                  details={"sources": claims["claim_sources"]}))
    else:
        checks.append(CheckResult(check_id="intake.claims", status="not_applicable",
                                  duration_ms=timer.lap(), reason="no config files found"))

    make_read_only(state.artifact_dir)
    make_read_only(state.expanded_dir)

    return manifest(
        artifact_type=artifact_type,
        root_sha256=root_hash((e.path, e.sha256) for e in entries),
        complete=not (corrupt or unreadable),
        entries=entries,
        claims=claims,
        estimated_params=params,
    ), checks
