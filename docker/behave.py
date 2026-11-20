"""Entrypoint for the hashvault-behave image.

This file is not imported by the host scanner. It may import torch and
transformers when the image is built. It loads safetensors, or calls
torch.load with weights_only=True. Pickle files are refused. Artifact
Python files are never imported. trust_remote_code is false.

The process reads /work/job.json and writes /work/behavioural-output.json.
Any failure exits non-zero.
"""

import json
import sys
from pathlib import Path

JOB_PATH = Path("/work/job.json")
OUTPUT_PATH = Path("/work/behavioural-output.json")
ARTIFACT_DIR = Path("/artifact")
BASE_DIR = Path("/base")
MAX_NEW_TOKENS = 16

_PICKLE_SUFFIXES = {".pkl", ".pickle"}
_TORCH_SUFFIXES = {".bin", ".pt", ".pth", ".ckpt"}


def _write_error(message: str) -> None:
    try:
        OUTPUT_PATH.write_text(
            json.dumps({"error": message}, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError:
        sys.stderr.write(message + "\n")


def _pickle_magic(path: Path) -> bool:
    try:
        head = path.read_bytes()[:2]
    except OSError:
        return False
    return len(head) >= 2 and head[0] == 0x80 and head[1] <= 5


def _refuse_unsafe(directory: Path) -> None:
    """Refuse pickle weights. Do not import Python that shipped with the artifact."""
    if not directory.is_dir():
        raise RuntimeError(f"weight directory is missing: {directory}")
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix == ".py":
            continue
        if suffix in _PICKLE_SUFFIXES or (suffix in _TORCH_SUFFIXES and _pickle_magic(path)):
            raise RuntimeError(f"refusing pickle weight file: {path.name}")


def _safetensors_files(directory: Path) -> list[Path]:
    return sorted(path for path in directory.rglob("*.safetensors") if path.is_file())


def _torch_files(directory: Path) -> list[Path]:
    return sorted(
        path for path in directory.rglob("*")
        if path.is_file() and path.suffix.lower() in _TORCH_SUFFIXES and not _pickle_magic(path)
    )


def _load_safetensors(directory: Path):
    files = _safetensors_files(directory)
    if not files:
        return None
    from safetensors.torch import load_file

    tensors = {}
    for path in files:
        tensors.update(load_file(str(path)))
    return tensors


def _load_torch_file(path: Path):
    if _pickle_magic(path) or path.suffix.lower() in _PICKLE_SUFFIXES:
        raise RuntimeError(f"refusing pickle weight file: {path.name}")
    import torch

    return torch.load(str(path), weights_only=True)


def _load_model(directory: Path):
    _refuse_unsafe(directory)
    if _safetensors_files(directory):
        _load_safetensors(directory)
    elif _torch_files(directory):
        for path in _torch_files(directory):
            _load_torch_file(path)
    else:
        raise RuntimeError(f"no safetensors weights in {directory}")
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        str(directory),
        local_files_only=True,
        trust_remote_code=False,
    )
    model = AutoModelForCausalLM.from_pretrained(
        str(directory),
        local_files_only=True,
        trust_remote_code=False,
        use_safetensors=True,
    )
    model.eval()
    if tokenizer.pad_token_id is None and tokenizer.eos_token_id is not None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer, torch


def _generate_one(model, tokenizer, torch, prompt: str) -> tuple[str, list[list[float]]]:
    inputs = tokenizer(prompt, return_tensors="pt")
    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            return_dict_in_generate=True,
            output_scores=True,
            pad_token_id=tokenizer.pad_token_id,
        )
    prompt_width = inputs["input_ids"].shape[-1]
    new_tokens = output.sequences[0][prompt_width:]
    text = tokenizer.decode(new_tokens, skip_special_tokens=True)
    distributions: list[list[float]] = []
    for scores in output.scores or []:
        probabilities = torch.softmax(scores[0].float(), dim=-1)
        distributions.append(probabilities.tolist())
    return text, distributions


def _run_model(directory: Path, prompts: list[dict]) -> list[dict]:
    model, tokenizer, torch = _load_model(directory)
    rows = []
    for item in prompts:
        text, distributions = _generate_one(model, tokenizer, torch, item["prompt"])
        rows.append({"id": item["id"], "text": text, "token_logprobs": distributions})
    return rows


def main() -> int:
    try:
        job = json.loads(JOB_PATH.read_text(encoding="utf-8"))
        prompts = job.get("prompts")
        if not isinstance(prompts, list) or not prompts:
            raise RuntimeError("job.json has no prompts")
        for item in prompts:
            if not isinstance(item, dict) or "id" not in item or "prompt" not in item:
                raise RuntimeError("prompt is missing id or text")
        payload = {
            "base": _run_model(BASE_DIR, prompts),
            "candidate": _run_model(ARTIFACT_DIR, prompts),
        }
        OUTPUT_PATH.write_text(
            json.dumps(payload, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        _write_error(f"{type(exc).__name__}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
