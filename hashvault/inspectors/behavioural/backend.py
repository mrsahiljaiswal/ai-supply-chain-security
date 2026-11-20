"""Model execution backends. The host process does not load weights.

ScriptedBackend replays outputs supplied by a test. DockerBackend is the only
path a scan uses to execute a model, and only inside hashvault-behave:local.
If docker is missing or the container fails, this module returns an error.
It does not fall back to loading weights on the host.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

IMAGE = "hashvault-behave:local"
DOCKER_TIMEOUT_SECONDS = 300


@dataclass
class GenerateResult:
    """Paired generations, or an error the inspector records as status=error.

    On success, ``base`` and ``candidate`` are lists of
    ``{id, text, token_logprobs}``. ``token_logprobs`` is a list of float
    distributions, one per generated token.
    """

    status: str
    reason: str | None = None
    base: list[dict[str, Any]] = field(default_factory=list)
    candidate: list[dict[str, Any]] = field(default_factory=list)


class BehaviourBackend(Protocol):
    def generate(
        self,
        prompts: Sequence[Mapping[str, Any]],
        artifact_dir: Path,
        base_dir: Path,
    ) -> GenerateResult:
        """Run every prompt on the base model and the candidate."""


def docker_run_command(artifact_dir: Path, base_dir: Path, work_dir: Path, *, image: str = IMAGE) -> list[str]:
    """The container invocation. The image entrypoint is docker/behave.py."""
    artifact = Path(artifact_dir).resolve()
    base = Path(base_dir).resolve()
    work = Path(work_dir).resolve()
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--cpus", "1",
        "--memory", "2g",
        "--read-only",
        "--mount", f"type=bind,src={artifact},dst=/artifact,readonly",
        "--mount", f"type=bind,src={base},dst=/base,readonly",
        "--mount", f"type=bind,src={work},dst=/work",
        image,
    ]


class ScriptedBackend:
    """Replay predetermined outputs. No model weights are opened.

    Selected only when HASHVAULT_BEHAVIOURAL_BACKEND=scripted. That hook is for
    tests. It is not a way to bless an untrusted file: without a script of
    outputs the result is an error, not a pass.
    """

    def __init__(
        self,
        base: Sequence[Mapping[str, Any]] | None = None,
        candidate: Sequence[Mapping[str, Any]] | None = None,
        *,
        error: str | None = None,
    ):
        self._base = [dict(item) for item in (base or [])]
        self._candidate = [dict(item) for item in (candidate or [])]
        self._error = error

    @classmethod
    def from_env(cls) -> "ScriptedBackend":
        raw = os.environ.get("HASHVAULT_BEHAVIOURAL_SCRIPT")
        if not raw:
            return cls(error="scripted_outputs_missing")
        path = Path(raw)
        if not path.is_file():
            return cls(error="scripted_outputs_missing")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls(error="scripted_outputs_missing")
        if not isinstance(data, dict):
            return cls(error="scripted_outputs_missing")
        base = data.get("base")
        candidate = data.get("candidate")
        if not isinstance(base, list) or not isinstance(candidate, list):
            return cls(error="scripted_outputs_missing")
        return cls(base=base, candidate=candidate)

    def generate(
        self,
        prompts: Sequence[Mapping[str, Any]],
        artifact_dir: Path,
        base_dir: Path,
    ) -> GenerateResult:
        del prompts, artifact_dir, base_dir
        if self._error:
            return GenerateResult(status="error", reason=self._error)
        return GenerateResult(status="ok", base=list(self._base), candidate=list(self._candidate))


class DockerBackend:
    """Run hashvault-behave:local. Never loads weights in this process."""

    def __init__(self, work_dir: Path, *, image: str = IMAGE):
        self.work_dir = Path(work_dir)
        self.image = image

    def generate(
        self,
        prompts: Sequence[Mapping[str, Any]],
        artifact_dir: Path,
        base_dir: Path,
    ) -> GenerateResult:
        if shutil.which("docker") is None:
            return GenerateResult(status="error", reason="docker_unavailable")
        behave = self.work_dir / "behavioural"
        behave.mkdir(parents=True, exist_ok=True)
        # The image user is not the host user. The scratch dir has to be writable.
        os.chmod(behave, 0o777)
        job = {"prompts": [dict(prompt) for prompt in prompts]}
        (behave / "job.json").write_text(
            json.dumps(job, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        command = docker_run_command(artifact_dir, base_dir, behave, image=self.image)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=DOCKER_TIMEOUT_SECONDS,
                check=False,
            )
        except FileNotFoundError:
            return GenerateResult(status="error", reason="docker_unavailable")
        except (subprocess.TimeoutExpired, OSError):
            return GenerateResult(status="error", reason="docker_failed")
        if completed.returncode != 0:
            return GenerateResult(status="error", reason="docker_failed")
        output_path = behave / "behavioural-output.json"
        if not output_path.is_file():
            return GenerateResult(status="error", reason="docker_failed")
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return GenerateResult(status="error", reason="docker_failed")
        if not isinstance(payload, dict) or payload.get("error"):
            return GenerateResult(status="error", reason="docker_failed")
        base = payload.get("base")
        candidate = payload.get("candidate")
        if not isinstance(base, list) or not isinstance(candidate, list):
            return GenerateResult(status="error", reason="docker_failed")
        return GenerateResult(status="ok", base=base, candidate=candidate)
