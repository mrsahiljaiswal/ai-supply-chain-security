from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

DetectedFormat = Literal[
    "safetensors", "pickle", "torch_zip", "torch_storage", "zip", "tar", "gzip", "bz2",
    "xz", "npy", "joblib", "json", "yaml", "python", "text", "unsupported", "unknown",
]
Role = Literal["weights", "adapter_weights", "config", "tokenizer", "code", "archive", "other"]
Source = Literal["local_dir", "local_file", "local_archive", "hf_hub"]
DetectedArtifactType = Literal["full_model", "lora_adapter", "unknown"]


class ManifestEntry(BaseModel):
    path: str
    parent: str | None = None
    depth: int = 0
    size_bytes: int
    sha256: str
    detected_format: DetectedFormat
    extension_format: str | None = None
    role: Role
    staged_path: str


class ArtifactManifest(BaseModel):
    scan_id: str
    source: Source
    source_ref: str
    resolved_revision: str | None = None
    artifact_type: DetectedArtifactType = "unknown"
    root_sha256: str | None = None
    complete: bool = True
    work_dir: str
    entries: list[ManifestEntry] = Field(default_factory=list)
    claims: dict[str, Any] = Field(default_factory=dict)
    estimated_params: int | None = None
    staged_at_utc: datetime
    limits_applied: dict[str, int] = Field(default_factory=dict)
