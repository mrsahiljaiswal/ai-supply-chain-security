import re
from collections.abc import Iterable

from hashvault.intake.detect import ARCHIVE_FORMATS, WEIGHT_FORMATS

_TOKENIZER_RE = re.compile(
    r"^(tokenizer(_config)?\.json|tokenizer\.model|special_tokens_map\.json|added_tokens\.json"
    r"|vocab\.(json|txt)|merges\.txt|spiece\.model|sentencepiece\.bpe\.model)$"
)
_CONFIG_NAMES = {
    "config.json",
    "adapter_config.json",
    "generation_config.json",
    "model.safetensors.index.json",
    "pytorch_model.bin.index.json",
    "preprocessor_config.json",
}
_SHARD_RE = re.compile(r"^(model|pytorch_model)(-\d+-of-\d+)?\.(safetensors|bin)$")
_ADAPTER_WEIGHTS = {"adapter_model.safetensors", "adapter_model.bin"}


def basename(path: str) -> str:
    return path.rsplit("!/", 1)[-1].rsplit("/", 1)[-1]


def assign_role(path: str, detected: str) -> str:
    name = basename(path)
    if detected == "torch_storage":
        return "other"
    if _TOKENIZER_RE.match(name):
        return "tokenizer"
    if name in _CONFIG_NAMES or (detected in {"json", "yaml"} and name.endswith("config.json")):
        return "config"
    if detected == "python":
        return "code"
    if detected in WEIGHT_FORMATS:
        return "adapter_weights" if name.startswith("adapter_model") else "weights"
    if detected in ARCHIVE_FORMATS:
        return "archive"
    return "other"


def classify(entries: Iterable[tuple[str, str]]) -> tuple[str, dict]:
    """entries: (path, role) pairs. Returns (artifact_type, extra_claims)."""
    names = set()
    roles = set()
    for path, role in entries:
        names.add(basename(path))
        roles.add(role)
    if "adapter_config.json" in names and names & _ADAPTER_WEIGHTS:
        return "lora_adapter", {}
    has_config = "config.json" in names
    has_shards = any(_SHARD_RE.match(n) for n in names)
    if has_config and (has_shards or "weights" in roles):
        return "full_model", {}
    if "weights" in roles:
        return "full_model", {"config_missing": True}
    return "unknown", {}
