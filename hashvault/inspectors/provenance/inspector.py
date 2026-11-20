"""Provenance checks: hashes, claims, lookalike names, publisher, hub metadata, attestation.

The inspector reads the manifest and the known-good registry. It does not open weight
files, unpickle anything, or import code from the artifact.
"""

import time
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field

from hashvault import __version__
from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest, parse_hub_id
from hashvault.inspectors.provenance import hub
from hashvault.inspectors.provenance.registry import (
    KnownGoodRegistry,
    RegistryConfig,
    RegistryModel,
    load_registry,
)
from hashvault.policy import Policy, load_policy

INSPECTOR = "provenance"
LOOKALIKE_MIN_SCORE = 90
# A trusted repo's model segment shorter than this is not used for partial matching.
_MIN_SEGMENT_CHARS = 8
_CONFIG_FIELDS = ("model_type", "architectures", "hidden_size", "num_hidden_layers", "vocab_size")


class InspectorReport(BaseModel):
    inspector: str = INSPECTOR
    version: str
    checks: list[CheckResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


def _result(
    check_id: str,
    status: str,
    *,
    reason: str | None = None,
    severity: str | None = None,
    details: dict | None = None,
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        status=status,
        reason=reason,
        severity=severity,
        details=details or {},
    )


def _finding(
    check_id: str,
    severity: str,
    message: str,
    *,
    location: str | None = None,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        inspector=INSPECTOR,
        check_id=check_id,
        severity=severity,
        message=message,
        location=location,
        evidence=evidence or {},
    )


def _basename(path: str) -> str:
    return path.rsplit("!/", 1)[-1].rsplit("/", 1)[-1]


def _norm_sha(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def _severity(policy: Policy, check_id: str) -> str:
    return getattr(policy.provenance.severities, check_id)


def _hub_repo(request: ScanRequest, manifest: ArtifactManifest) -> tuple[str, str | None] | None:
    if manifest.source != "hf_hub" and request.hub_ref is None:
        return None
    parsed = request.hub_ref or parse_hub_id(manifest.source_ref)
    if parsed is None:
        return None
    repo, revision = parsed
    return repo, manifest.resolved_revision or revision


def _entry_named(
    registry: KnownGoodRegistry, name: str, revision: str | None
) -> RegistryModel | None:
    group = [model for model in registry.models if model.name.strip() == name]
    if not group:
        return None
    if revision:
        exact = [model for model in group if model.revision == revision]
        if exact:
            return exact[0]
        generic = [model for model in group if not model.revision]
        return generic[0] if generic else None
    generic = [model for model in group if not model.revision]
    return generic[0] if generic else group[0]


def _artifact_entry(
    request: ScanRequest, manifest: ArtifactManifest, registry: KnownGoodRegistry
) -> RegistryModel | None:
    """Registry row for this artifact's own identity, not the LoRA base weights."""
    candidates: list[tuple[str, str | None]] = []
    if request.claimed_repo and request.claimed_repo.strip():
        candidates.append((request.claimed_repo.strip(), None))
    hub_ref = _hub_repo(request, manifest)
    if hub_ref is not None:
        candidates.append(hub_ref)
    # A LoRA's bytes are the adapter. The claimed base is a different artifact and is
    # checked by provenance_base_claim and provenance_config, not by hash equality.
    if manifest.artifact_type != "lora_adapter" and request.claimed_base_model:
        candidates.append((request.claimed_base_model.strip(), request.claimed_base_revision))
    seen: set[str] = set()
    for name, revision in candidates:
        if name in seen:
            continue
        seen.add(name)
        entry = _entry_named(registry, name, revision)
        if entry is not None:
            return entry
    return None


def _base_entry(request: ScanRequest, registry: KnownGoodRegistry) -> RegistryModel | None:
    if not request.claimed_base_model or not request.claimed_base_model.strip():
        return None
    return _entry_named(registry, request.claimed_base_model.strip(), request.claimed_base_revision)


def _has_hash_reference(entry: RegistryModel) -> bool:
    if _norm_sha(entry.root_sha256):
        return True
    return any(_norm_sha(digest) for digest in entry.files.values())


def _source_name(request: ScanRequest, manifest: ArtifactManifest) -> str | None:
    hub_ref = _hub_repo(request, manifest)
    if hub_ref is not None:
        return hub_ref[0]
    name = Path(manifest.source_ref).name.strip()
    return name or None


def _check_hash(
    request: ScanRequest,
    manifest: ArtifactManifest,
    registry: KnownGoodRegistry,
    policy: Policy,
) -> tuple[CheckResult, list[Finding]]:
    check_id = "provenance_hash_match"
    entry = _artifact_entry(request, manifest, registry)
    if entry is None or not _has_hash_reference(entry):
        return _result(check_id, "skipped", reason="no_known_good_reference", details={
            "matched": entry.name if entry else None,
        }), []
    mismatches: list[dict[str, Any]] = []
    expected_root = _norm_sha(entry.root_sha256)
    actual_root = _norm_sha(manifest.root_sha256)
    if expected_root is not None and expected_root != actual_root:
        mismatches.append({"file": "<root>", "expected": expected_root, "actual": actual_root})
    actual_files = {item.path: _norm_sha(item.sha256) for item in manifest.entries}
    for path, expected in entry.files.items():
        expected_file = _norm_sha(expected)
        if expected_file is None:
            continue
        actual_file = actual_files.get(path)
        if actual_file != expected_file:
            mismatches.append({"file": path, "expected": expected_file, "actual": actual_file})
    if not mismatches:
        return _result(check_id, "passed", details={
            "matched": entry.name,
            "root_sha256": actual_root,
            "files_compared": len(entry.files),
        }), []
    severity = _severity(policy, check_id)
    findings = [
        _finding(
            check_id,
            severity,
            f"hash mismatch for {item['file']}",
            location=item["file"],
            evidence={"matched": entry.name, **item},
        )
        for item in mismatches
    ]
    return _result(
        check_id,
        "failed",
        severity=severity,
        reason="known-good hash mismatch",
        details={"matched": entry.name, "mismatches": mismatches},
    ), findings


def _check_base_claim(
    request: ScanRequest, manifest: ArtifactManifest, policy: Policy
) -> tuple[CheckResult, list[Finding]]:
    check_id = "provenance_base_claim"
    raw = manifest.claims.get("base_model_name_or_path")
    claim = raw.strip() if isinstance(raw, str) and raw.strip() else None
    claimed = request.claimed_base_model.strip() if request.claimed_base_model else None
    is_lora = manifest.artifact_type == "lora_adapter"
    if not is_lora and claim is None:
        return _result(check_id, "not_applicable", reason="no_base_claim"), []
    if claim is None:
        return _result(check_id, "skipped", reason="claim_missing", details={
            "claimed_base_model": claimed,
        }), []
    if claim == claimed:
        return _result(check_id, "passed", details={
            "base_model_name_or_path": claim,
            "claimed_base_model": claimed,
        }), []
    severity = _severity(policy, check_id)
    evidence = {"base_model_name_or_path": claim, "claimed_base_model": claimed}
    location = (manifest.claims.get("claim_sources") or {}).get("adapter_config")
    return _result(
        check_id,
        "failed",
        severity=severity,
        reason="claimed base does not match adapter_config base_model_name_or_path",
        details=evidence,
    ), [
        _finding(
            check_id,
            severity,
            f"adapter claims base {claim!r} but the request claims {claimed!r}",
            location=location,
            evidence=evidence,
        )
    ]


def _specified_config(config: RegistryConfig) -> dict[str, Any]:
    specified: dict[str, Any] = {}
    if config.model_type:
        specified["model_type"] = config.model_type
    if config.architectures:
        specified["architectures"] = list(config.architectures)
    for key in ("hidden_size", "num_hidden_layers", "vocab_size"):
        value = getattr(config, key)
        if value is not None:
            specified[key] = value
    return specified


def _check_config(
    request: ScanRequest,
    manifest: ArtifactManifest,
    registry: KnownGoodRegistry,
    policy: Policy,
) -> tuple[CheckResult, list[Finding]]:
    check_id = "provenance_config"
    # Field comparison is only meaningful for a full model whose claimed base
    # selects a registry config. A LoRA ships adapter_config.json, which has no
    # hidden_size, and that absence is not a config mismatch.
    if manifest.artifact_type == "lora_adapter":
        return _result(check_id, "not_applicable", reason="adapter_has_no_model_config", details={
            "artifact_type": manifest.artifact_type,
        }), []
    if manifest.artifact_type != "full_model":
        return _result(check_id, "not_applicable", reason="not_full_model", details={
            "artifact_type": manifest.artifact_type,
        }), []
    entry = _base_entry(request, registry)
    specified = _specified_config(entry.config) if entry and entry.config else {}
    if not specified:
        return _result(check_id, "skipped", reason="no_reference_config", details={
            "claimed_base_model": request.claimed_base_model,
            "matched": entry.name if entry else None,
        }), []
    diffs = [key for key in _CONFIG_FIELDS if key in specified and manifest.claims.get(key) != specified[key]]
    if not diffs:
        return _result(check_id, "passed", details={"matched": entry.name, "fields": list(specified)}), []
    severity = _severity(policy, check_id)
    evidence = {
        "matched": entry.name,
        "fields": diffs,
        "expected": {key: specified[key] for key in diffs},
        "actual": {key: manifest.claims.get(key) for key in diffs},
    }
    location = (manifest.claims.get("claim_sources") or {}).get("config")
    return _result(
        check_id,
        "failed",
        severity=severity,
        reason="config claims differ from the known-good registry",
        details=evidence,
    ), [
        _finding(
            check_id,
            severity,
            "config differs from the known-good registry: " + ", ".join(diffs),
            location=location,
            evidence=evidence,
        )
    ]


def _score_name(candidate: str, trusted: str) -> tuple[float, str, float]:
    """Best lookalike score, the metric that produced it, and the full-name token_sort_ratio.

    RapidFuzz 3 leaves processor=None, so token_sort_ratio would not split repo ids on
    '/', '-' or '.'. The standard processor is passed explicitly.

    token_sort_ratio("Qwen2.5-0.5B-official", "Qwen/Qwen2.5-0.5B") is about 68, under 90.
    partial_ratio against the trusted repo's model segment catches that suffix squat
    (the segment "Qwen2.5-0.5B" scores 100) without lowering the threshold.
    """
    from rapidfuzz import fuzz, utils

    processor = utils.default_process
    full_sort = float(fuzz.token_sort_ratio(candidate, trusted, processor=processor))
    best = full_sort
    metric = "token_sort_ratio"
    targets = [trusted]
    segment = trusted.rsplit("/", 1)[-1].strip()
    if len(segment) >= _MIN_SEGMENT_CHARS and segment != trusted:
        targets.append(segment)
    for target in targets:
        sort_score = float(fuzz.token_sort_ratio(candidate, target, processor=processor))
        if sort_score > best:
            best, metric = sort_score, "token_sort_ratio"
        if len(candidate) >= len(target) and len(target) >= _MIN_SEGMENT_CHARS:
            partial = float(fuzz.partial_ratio(candidate, target, processor=processor))
            if partial > best:
                best, metric = partial, "partial_ratio"
    return best, metric, full_sort


def _typosquat_candidates(
    request: ScanRequest, manifest: ArtifactManifest
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(kind: str, value: str | None) -> None:
        if not value:
            return
        name = value.strip()
        if not name or name in seen:
            return
        seen.add(name)
        found.append((kind, name))

    add("claimed_repo", request.claimed_repo)
    add("source_name", _source_name(request, manifest))
    return found


def _check_typosquat(
    request: ScanRequest,
    manifest: ArtifactManifest,
    registry: KnownGoodRegistry,
    policy: Policy,
) -> tuple[CheckResult, list[Finding]]:
    check_id = "provenance_typosquat"
    trusted = [name.strip() for name in registry.trusted_names if name and name.strip()]
    if not trusted:
        return _result(check_id, "skipped", reason="no_trusted_names"), []
    trusted_exact = set(trusted)
    hits: list[dict[str, Any]] = []
    for kind, name in _typosquat_candidates(request, manifest):
        if name in trusted_exact:
            continue
        for known in trusted:
            score, metric, full_sort = _score_name(name, known)
            if score >= LOOKALIKE_MIN_SCORE:
                hits.append({
                    "field": kind,
                    "name": name,
                    "trusted_name": known,
                    "score": round(score, 2),
                    "metric": metric,
                    "token_sort_ratio": round(full_sort, 2),
                })
    if not hits:
        return _result(check_id, "passed", details={"trusted_names": trusted}), []
    severity = _severity(policy, check_id)
    findings = [
        _finding(
            check_id,
            severity,
            f"{hit['name']} looks like trusted name {hit['trusted_name']} (score {hit['score']})",
            location=hit["name"],
            evidence=hit,
        )
        for hit in hits
    ]
    return _result(
        check_id,
        "failed",
        severity=severity,
        reason="name is a near match for a trusted name but is not an exact match",
        details={"matches": hits},
    ), findings


def _check_publisher(
    request: ScanRequest,
    manifest: ArtifactManifest,
    registry: KnownGoodRegistry,
    policy: Policy,
) -> tuple[CheckResult, list[Finding]]:
    check_id = "provenance_publisher"
    claimed = request.claimed_publisher.strip() if request.claimed_publisher and request.claimed_publisher.strip() else None
    if not claimed:
        # The user did not pass --publisher. That is not a disagreement with the registry.
        return _result(check_id, "skipped", reason="publisher_not_claimed", details={
            "claimed_publisher": None,
        }), []
    entry = _artifact_entry(request, manifest, registry)
    publisher = entry.publisher.strip() if entry and entry.publisher and entry.publisher.strip() else None
    if not publisher:
        # A claimed publisher with nothing in the registry to compare against is not a pass.
        return _result(check_id, "skipped", reason="publisher_unverified", details={
            "matched": entry.name if entry else None,
            "claimed_publisher": claimed,
            "allow_network": request.allow_network,
        }), []
    evidence = {"matched": entry.name, "expected": publisher, "actual": claimed}
    if claimed == publisher:
        return _result(check_id, "passed", details=evidence), []
    severity = _severity(policy, check_id)
    return _result(
        check_id,
        "failed",
        severity=severity,
        reason="claimed publisher does not match the registry",
        details=evidence,
    ), [
        _finding(
            check_id,
            severity,
            f"claimed publisher {claimed!r} does not match registry publisher {publisher!r}",
            location=entry.name,
            evidence=evidence,
        )
    ]


def _check_hub(
    request: ScanRequest, manifest: ArtifactManifest
) -> tuple[CheckResult, list[Finding]]:
    check_id = "provenance_hub_metadata"
    if not request.allow_network:
        return _result(check_id, "skipped", reason="offline"), []
    ref = _hub_repo(request, manifest)
    if ref is None:
        return _result(check_id, "skipped", reason="not_hub_source"), []
    repo_id, revision = ref
    try:
        meta = hub.fetch_hub_metadata(repo_id, revision)
    except hub.HubLibraryMissing:
        return _result(check_id, "error", reason="huggingface_hub_missing", details={
            "repo_id": repo_id,
        }), []
    except Exception as exc:
        return _result(
            check_id,
            "error",
            reason=f"{type(exc).__name__}: {exc}",
            details={"repo_id": repo_id, "revision": revision},
        ), []
    return _result(check_id, "passed", details={"repo_id": repo_id, "revision": revision, **meta}), []


def _is_signature(path: str) -> bool:
    name = _basename(path)
    return name == "signature" or name.endswith(".sig")


def _check_attestation(manifest: ArtifactManifest) -> tuple[CheckResult, list[Finding]]:
    check_id = "provenance_attestation"
    signed = [entry.path for entry in manifest.entries if _is_signature(entry.path)]
    if signed:
        return _result(
            check_id,
            "skipped",
            reason="unsupported_signature_scheme",
            details={"files": signed},
        ), []
    return _result(check_id, "skipped", reason="no_attestation"), []


def _run(
    check_id: str, fn: Callable[[], tuple[CheckResult, list[Finding]]]
) -> tuple[CheckResult, list[Finding]]:
    started = time.perf_counter()
    try:
        result, findings = fn()
    except Exception as exc:
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        return _result(
            check_id,
            "error",
            reason=f"{type(exc).__name__}: {exc}",
        ).model_copy(update={"duration_ms": elapsed}), []
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    return result.model_copy(update={"duration_ms": elapsed}), findings


def _coverage(
    registry: KnownGoodRegistry,
    path: Path,
    manifest: ArtifactManifest,
    matched: str | None,
) -> dict[str, Any]:
    return {
        "registry": str(path),
        "models": len(registry.models),
        "trusted_names": len(registry.trusted_names),
        "matched_model": matched,
        "artifact_type": manifest.artifact_type,
        "limitations": [
            "This inspector never loads weights, unpickles, or imports artifact code.",
            "A skipped check is a coverage gap, not a pass. An empty registry cannot yield Trusted.",
            "Signature files are recorded and not verified in v1.",
            "Hub metadata is read only when allow_network is set and the source is a Hugging Face repo id.",
            "LoRA bytes are not compared to the claimed base hash; base identity is a separate check.",
            "Lookalike detection uses RapidFuzz token_sort_ratio and partial_ratio against the trusted model segment.",
        ],
    }


def scan_provenance(
    request: ScanRequest,
    manifest: ArtifactManifest,
    policy: Policy | None = None,
    registry_path: str | Path | None = None,
) -> InspectorReport:
    """Run every provenance check. One check crashing does not stop the others."""
    policy = policy or load_policy(request.policy_profile)
    registry, path = load_registry(registry_path)
    matched = _artifact_entry(request, manifest, registry)
    steps: list[tuple[str, Callable[[], tuple[CheckResult, list[Finding]]]]] = [
        ("provenance_hash_match", lambda: _check_hash(request, manifest, registry, policy)),
        ("provenance_base_claim", lambda: _check_base_claim(request, manifest, policy)),
        ("provenance_config", lambda: _check_config(request, manifest, registry, policy)),
        ("provenance_typosquat", lambda: _check_typosquat(request, manifest, registry, policy)),
        ("provenance_publisher", lambda: _check_publisher(request, manifest, registry, policy)),
        ("provenance_hub_metadata", lambda: _check_hub(request, manifest)),
        ("provenance_attestation", lambda: _check_attestation(manifest)),
    ]
    checks: list[CheckResult] = []
    findings: list[Finding] = []
    for check_id, fn in steps:
        result, found = _run(check_id, fn)
        checks.append(result)
        findings.extend(found)
    return InspectorReport(
        version=__version__,
        checks=checks,
        findings=findings,
        coverage=_coverage(registry, path, manifest, matched.name if matched else None),
    )
