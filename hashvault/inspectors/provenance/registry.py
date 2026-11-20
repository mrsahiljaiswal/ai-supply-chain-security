"""Local known-good registry. A missing or empty registry is not a pass."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from hashvault.policy import policy_dirs


class RegistryError(Exception):
    """The registry file is missing or not a valid known-good document."""


class RegistryConfig(BaseModel):
    """Reference config.json fields. Null means the field is not constrained."""

    model_config = ConfigDict(extra="ignore")

    model_type: str | None = None
    architectures: list[str] = Field(default_factory=list)
    hidden_size: int | None = None
    num_hidden_layers: int | None = None
    vocab_size: int | None = None


class RegistryModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    revision: str | None = None
    publisher: str | None = None
    root_sha256: str | None = None
    files: dict[str, str] = Field(default_factory=dict)
    config: RegistryConfig | None = None


class KnownGoodRegistry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    models: list[RegistryModel] = Field(default_factory=list)
    trusted_names: list[str] = Field(default_factory=list)


def default_registry_path() -> Path:
    """First policies/known-good.yaml on the policy search path."""
    for directory in policy_dirs():
        candidate = directory / "known-good.yaml"
        if candidate.is_file():
            return candidate
    return Path(__file__).resolve().parents[3] / "policies" / "known-good.yaml"


def load_registry(path: str | Path | None = None) -> tuple[KnownGoodRegistry, Path]:
    """Load a YAML registry. Raises RegistryError; does not treat a bad file as empty."""
    resolved = Path(path) if path is not None else default_registry_path()
    if not resolved.is_file():
        raise RegistryError(f"known-good registry not found: {resolved}")
    try:
        data = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RegistryError(f"cannot read registry {resolved}: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError(f"registry {resolved} must be a mapping")
    try:
        return KnownGoodRegistry.model_validate(data), resolved
    except ValueError as exc:
        raise RegistryError(f"invalid registry {resolved}: {exc}") from exc
