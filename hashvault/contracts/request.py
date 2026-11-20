import os
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from hashvault.policy import PolicyError, resolve_policy_path

RequestedArtifactType = Literal["full_model", "lora_adapter", "auto"]

HUB_ID_RE = re.compile(
    r"^(?:hf://)?(?P<repo>[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:@(?P<revision>[A-Za-z0-9._/-]+))?$"
)


def parse_hub_id(ref: str) -> tuple[str, str | None] | None:
    m = HUB_ID_RE.match(ref)
    if not m:
        return None
    return m.group("repo"), m.group("revision")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    artifact: str = Field(min_length=1)
    artifact_type: RequestedArtifactType = "auto"
    claimed_base_model: str | None = None
    claimed_base_revision: str | None = None
    claimed_base_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    claimed_publisher: str | None = None
    claimed_repo: str | None = None
    policy_profile: str = "strict"
    allow_network: bool = False
    output_dir: Path | None = None

    @field_validator("claimed_base_sha256")
    @classmethod
    def _lower_sha(cls, v: str | None) -> str | None:
        return v.lower() if v else v

    @field_validator("policy_profile")
    @classmethod
    def _known_policy(cls, v: str) -> str:
        try:
            resolve_policy_path(v)
        except PolicyError as exc:
            raise ValueError(str(exc)) from exc
        return v

    @property
    def is_local(self) -> bool:
        return os.path.lexists(self.artifact)

    @property
    def hub_ref(self) -> tuple[str, str | None] | None:
        if self.is_local:
            return None
        return parse_hub_id(self.artifact)

    @model_validator(mode="after")
    def _validate(self) -> "ScanRequest":
        if self.artifact_type == "lora_adapter" and not self.claimed_base_model:
            raise ValueError("a LoRA adapter scan requires --base (claimed_base_model)")
        if self.is_local:
            p = Path(self.artifact)
            if not os.access(p, os.R_OK):
                raise ValueError(f"artifact is not readable: {self.artifact}")
            if p.is_dir() and not os.access(p, os.X_OK):
                raise ValueError(f"artifact directory is not listable: {self.artifact}")
        elif parse_hub_id(self.artifact):
            if not self.allow_network:
                raise ValueError(
                    f"{self.artifact!r} is not a local path; hub repo ids require --allow-network"
                )
        else:
            raise ValueError(f"artifact path does not exist: {self.artifact}")
        return self
