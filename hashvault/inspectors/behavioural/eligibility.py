"""Decide whether the behavioural inspector may try to run a model.

This runs on the host and does not open weight files. Eligible means the
scan is allowed to try. It does not mean the artifact can generate text.
"""

from dataclasses import dataclass
from pathlib import Path

from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest
from hashvault.inspectors.provenance.registry import RegistryError, RegistryModel, load_registry
from hashvault.policy import Policy

_WEIGHT_ROLES = frozenset({"weights", "adapter_weights"})


@dataclass(frozen=True)
class Eligibility:
    eligible: bool
    reason: str | None = None
    base_dir: Path | None = None
    artifact_dir: Path | None = None


def _static_critical(static_report) -> bool:
    return any(getattr(finding, "severity", None) == "critical" for finding in static_report.findings)


def _static_incomplete(static_report) -> bool:
    return any(getattr(check, "status", None) == "error" for check in static_report.checks)


def _weight_entries(manifest: ArtifactManifest):
    return [entry for entry in manifest.entries if entry.role in _WEIGHT_ROLES]


def _safe_weight_path(manifest: ArtifactManifest) -> bool:
    weights = _weight_entries(manifest)
    if not weights:
        return False
    return all(entry.detected_format == "safetensors" for entry in weights)


def _base_entry(models: list[RegistryModel], name: str, revision: str | None) -> RegistryModel | None:
    group = [model for model in models if model.name.strip() == name]
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


def _has_root(entry: RegistryModel) -> bool:
    return bool(entry.root_sha256 and str(entry.root_sha256).strip())


def _directory(path: str | Path | None) -> Path | None:
    if path is None:
        return None
    text = str(path).strip()
    if not text:
        return None
    candidate = Path(text)
    if candidate.is_dir():
        return candidate.resolve()
    return None


def _artifact_dir(manifest: ArtifactManifest) -> Path:
    return Path(manifest.work_dir) / "artifact"


def check_eligibility(
    request: ScanRequest,
    manifest: ArtifactManifest,
    static_report,
    policy: Policy,
    *,
    registry_path: str | Path | None = None,
    base_dir: str | Path | None = None,
) -> Eligibility:
    """Return eligible, or the first skip reason in the fixed order.

    Skip reasons, in order: static_critical, static_incomplete,
    no_safe_load_path, base_unverified, base_weights_missing,
    exceeds_resource_profile.
    """
    artifact_dir = _artifact_dir(manifest)
    if _static_critical(static_report):
        return Eligibility(False, "static_critical", artifact_dir=artifact_dir)
    if _static_incomplete(static_report):
        return Eligibility(False, "static_incomplete", artifact_dir=artifact_dir)
    if not _safe_weight_path(manifest):
        return Eligibility(False, "no_safe_load_path", artifact_dir=artifact_dir)

    claimed = request.claimed_base_model.strip() if request.claimed_base_model else ""
    if not claimed:
        return Eligibility(False, "base_unverified", artifact_dir=artifact_dir)
    try:
        registry, _path = load_registry(registry_path)
    except RegistryError:
        return Eligibility(False, "base_unverified", artifact_dir=artifact_dir)
    entry = _base_entry(registry.models, claimed, request.claimed_base_revision)
    if entry is None or not _has_root(entry):
        return Eligibility(False, "base_unverified", artifact_dir=artifact_dir)

    resolved = _directory(entry.local_path) or _directory(base_dir)
    if resolved is None:
        return Eligibility(False, "base_weights_missing", artifact_dir=artifact_dir)

    limit = policy.behavioural.max_estimated_params
    if manifest.estimated_params is not None and manifest.estimated_params > limit:
        return Eligibility(False, "exceeds_resource_profile", artifact_dir=artifact_dir)

    return Eligibility(True, base_dir=resolved, artifact_dir=artifact_dir)
