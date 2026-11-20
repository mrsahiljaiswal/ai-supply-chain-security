import json
import math
import struct
from pathlib import Path
from typing import Any

from hashvault.intake.classify import basename

CONFIG_CLAIMS = ("model_type", "architectures", "hidden_size", "num_hidden_layers", "vocab_size", "auto_map")
ADAPTER_CLAIMS = {
    "base_model_name_or_path": "base_model_name_or_path",
    "r": "lora_r",
    "target_modules": "lora_target_modules",
    "peft_type": "peft_type",
    "lora_alpha": "lora_alpha",
}


class ClaimError(Exception):
    pass


def read_json_text(path: Path, max_bytes: int) -> dict[str, Any]:
    size = path.stat().st_size
    if size > max_bytes:
        raise ClaimError(f"{path.name}: {size} bytes exceeds config read cap {max_bytes}")
    try:
        data = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ClaimError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ClaimError("top-level JSON value is not an object")
    return data


def _pick(entries: list[tuple[str, int, Path]], name: str) -> tuple[str, Path, int] | None:
    matches = sorted((depth, path, fs) for path, depth, fs in entries if basename(path) == name)
    if not matches:
        return None
    depth, path, fs = matches[0]
    return path, fs, len(matches)


def extract_claims(
    entries: list[tuple[str, int, Path]], max_bytes: int
) -> tuple[dict[str, Any], list[dict]]:
    """entries: (manifest path, depth, staged fs path) for JSON-format files."""
    claims: dict[str, Any] = {}
    sources: dict[str, str] = {}
    errors: list[dict] = []

    picked = _pick(entries, "config.json")
    if picked:
        path, fs, count = picked
        try:
            cfg = read_json_text(fs, max_bytes)
            for key in CONFIG_CLAIMS:
                if key in cfg:
                    claims[key] = cfg[key]
            if "torch_dtype" in cfg:
                claims["torch_dtype"] = cfg["torch_dtype"]
            sources["config"] = path
            if count > 1:
                claims["multiple_config_files"] = count
        except ClaimError as exc:
            errors.append({"path": path, "reason": str(exc)})

    picked = _pick(entries, "adapter_config.json")
    if picked:
        path, fs, count = picked
        try:
            cfg = read_json_text(fs, max_bytes)
            for key, claim in ADAPTER_CLAIMS.items():
                if key in cfg:
                    claims[claim] = cfg[key]
            sources["adapter_config"] = path
            if count > 1:
                claims["multiple_adapter_config_files"] = count
        except ClaimError as exc:
            errors.append({"path": path, "reason": str(exc)})

    if sources:
        claims["claim_sources"] = sources
    return claims, errors


def safetensors_param_count(path: Path, max_header_bytes: int) -> int | None:
    size = path.stat().st_size
    with open(path, "rb") as f:
        head = f.read(8)
        if len(head) < 8:
            return None
        (n,) = struct.unpack("<Q", head)
        if n > max_header_bytes or n > size - 8:
            return None
        raw = f.read(n)
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(header, dict):
        return None
    total = 0
    for key, meta in header.items():
        if key == "__metadata__":
            continue
        shape = meta.get("shape") if isinstance(meta, dict) else None
        if not isinstance(shape, list) or not all(
            isinstance(d, int) and not isinstance(d, bool) and d >= 0 for d in shape
        ):
            return None
        total += math.prod(shape)
    return total
