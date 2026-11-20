import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from hashvault.contracts.checks import Severity

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB


class PolicyError(ValueError):
    pass


class IntakeLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_total_bytes: int = Field(4 * GiB, gt=0)
    max_file_count: int = Field(10_000, gt=0)
    max_archive_depth: int = Field(5, ge=0)
    max_compression_ratio: int = Field(100, gt=0)
    compression_ratio_min_bytes: int = Field(1 * MiB, ge=0)
    max_safetensors_header_bytes: int = Field(100 * MiB, gt=0)
    max_path_bytes: int = Field(4096, gt=0)
    max_config_bytes: int = Field(64 * MiB, gt=0)


class IntakeSeverities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_mismatch: Severity = "warning"
    unknown_format: Severity = "warning"
    archive_member_rejected: Severity = "critical"
    local_special_file: Severity = "warning"
    type_mismatch: Severity = "warning"


class IntakePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limits: IntakeLimits = Field(default_factory=IntakeLimits)
    severities: IntakeSeverities = Field(default_factory=IntakeSeverities)


class StaticSeverities(BaseModel):
    """Default severities for static checks. The scanner does not hard-code these."""

    model_config = ConfigDict(extra="forbid")

    pickle_dangerous_callable: Severity = "critical"
    pickle_unknown_global: Severity = "warning"
    safetensors_structure: Severity = "critical"
    safetensors_trailing_bytes: Severity = "critical"
    npy_object_dtype: Severity = "critical"
    custom_code_present: Severity = "warning"


class StaticPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severities: StaticSeverities = Field(default_factory=StaticSeverities)


class ProvenanceSeverities(BaseModel):
    """Default severities for provenance checks. The inspector does not hard-code these."""

    model_config = ConfigDict(extra="forbid")

    provenance_hash_match: Severity = "critical"
    provenance_base_claim: Severity = "warning"
    provenance_config: Severity = "warning"
    provenance_typosquat: Severity = "warning"
    provenance_publisher: Severity = "warning"
    provenance_hub_metadata: Severity = "warning"
    provenance_attestation: Severity = "info"


class ProvenancePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severities: ProvenanceSeverities = Field(default_factory=ProvenanceSeverities)


class Policy(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = "strict"
    intake: IntakePolicy = Field(default_factory=IntakePolicy)
    static: StaticPolicy = Field(default_factory=StaticPolicy)
    provenance: ProvenancePolicy = Field(default_factory=ProvenancePolicy)


BUILTIN_PROFILES = {"strict"}


def policy_dirs() -> list[Path]:
    dirs = []
    if env := os.environ.get("HASHVAULT_POLICY_DIR"):
        dirs.append(Path(env))
    dirs.append(Path(__file__).resolve().parent.parent / "policies")
    dirs.append(Path.cwd() / "policies")
    return dirs


def resolve_policy_path(profile: str) -> Path | None:
    candidate = Path(profile)
    if candidate.suffix in {".yaml", ".yml"}:
        if candidate.is_file():
            return candidate
        raise PolicyError(f"policy file not found: {profile}")
    if not profile.replace("-", "").replace("_", "").isalnum():
        raise PolicyError(f"invalid policy profile name: {profile!r}")
    for d in policy_dirs():
        for ext in (".yaml", ".yml"):
            p = d / f"{profile}{ext}"
            if p.is_file():
                return p
    if profile in BUILTIN_PROFILES:
        return None
    raise PolicyError(f"unknown policy profile: {profile!r}")


def load_policy(profile: str = "strict") -> Policy:
    path = resolve_policy_path(profile)
    if path is None:
        return Policy(name=profile)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy {path} must be a mapping")
    data.setdefault("name", path.stem)
    try:
        return Policy.model_validate(data)
    except ValueError as exc:
        raise PolicyError(f"invalid policy {path}: {exc}") from exc
