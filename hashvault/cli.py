import json
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
import yaml
from pydantic import ValidationError

from hashvault.contracts.checks import CheckResult
from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest
from hashvault.intake.pipeline import run_intake
from hashvault.policy import PolicyError, load_policy

EXIT_USAGE = 2
EXIT_UNDETERMINED = 20

app = typer.Typer(add_completion=False, no_args_is_help=True, help="HashVault model artifact scanner")


def _fail_usage(message: str) -> None:
    typer.echo(f"hashvault: error: {message}", err=True)
    raise typer.Exit(EXIT_USAGE)


def _format_validation(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err["loc"])
        msg = err["msg"].removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(parts)


def build_request(request_file: Path | None, overrides: dict[str, Any]) -> ScanRequest:
    data: dict[str, Any] = {}
    if request_file is not None:
        try:
            loaded = yaml.safe_load(request_file.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            _fail_usage(f"cannot read request file {request_file}: {exc}")
        if not isinstance(loaded, dict):
            _fail_usage(f"request file {request_file} must be a YAML mapping")
        data.update(loaded)
    data.update({k: v for k, v in overrides.items() if v is not None})
    if "artifact" not in data:
        _fail_usage("missing artifact path (positional argument or 'artifact' in --request)")
    try:
        return ScanRequest.model_validate(data)
    except ValidationError as exc:
        _fail_usage(_format_validation(exc))


def _execute(
    artifact, base, base_revision, base_sha256, publisher, repo, artifact_type, policy,
    allow_network, out, work_dir, request_file,
) -> tuple[ScanRequest, ArtifactManifest, list[CheckResult]]:
    req = build_request(request_file, {
        "artifact": artifact,
        "claimed_base_model": base,
        "claimed_base_revision": base_revision,
        "claimed_base_sha256": base_sha256,
        "claimed_publisher": publisher,
        "claimed_repo": repo,
        "artifact_type": artifact_type,
        "policy_profile": policy,
        "allow_network": True if allow_network else None,
        "output_dir": out,
    })
    try:
        pol = load_policy(req.policy_profile)
    except PolicyError as exc:
        _fail_usage(str(exc))
    manifest, checks = run_intake(req, pol, work_root=work_dir)
    if manifest.artifact_type == "lora_adapter" and not req.claimed_base_model:
        _fail_usage("artifact was detected as a LoRA adapter; --base (claimed base model) is required")
    return req, manifest, checks


def _emit(req: ScanRequest, manifest: ArtifactManifest, checks: list[CheckResult], extra: dict | None = None):
    payload = {
        "request": json.loads(req.model_dump_json()),
        "manifest": json.loads(manifest.model_dump_json()),
        "checks": [json.loads(c.model_dump_json()) for c in checks],
    }
    if extra:
        payload.update(extra)
    text = json.dumps(payload, indent=2)
    if req.output_dir:
        out = Path(req.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{manifest.scan_id}.intake.json").write_text(text + "\n", encoding="utf-8")
    sys.stdout.write(text + "\n")


ArtifactArg = Annotated[Optional[str], typer.Argument(help="Local dir/file/archive, or org/name@rev")]
BaseOpt = Annotated[Optional[str], typer.Option("--base", help="Claimed base model id")]
BaseRevOpt = Annotated[Optional[str], typer.Option("--base-revision")]
BaseShaOpt = Annotated[Optional[str], typer.Option("--base-sha256")]
PublisherOpt = Annotated[Optional[str], typer.Option("--publisher")]
RepoOpt = Annotated[Optional[str], typer.Option("--repo")]
TypeOpt = Annotated[Optional[str], typer.Option("--type", help="full_model | lora_adapter | auto")]
PolicyOpt = Annotated[Optional[str], typer.Option("--policy", help="Profile name or YAML path")]
NetOpt = Annotated[bool, typer.Option("--allow-network", help="Permit Hugging Face hub access")]
OutOpt = Annotated[Optional[Path], typer.Option("--out", help="Directory for the JSON output")]
WorkOpt = Annotated[Optional[Path], typer.Option("--work-dir", help="Quarantine root (default ./work)")]
RequestOpt = Annotated[Optional[Path], typer.Option("--request", help="YAML scan request file")]


@app.command()
def intake(
    artifact: ArtifactArg = None,
    base: BaseOpt = None,
    base_revision: BaseRevOpt = None,
    base_sha256: BaseShaOpt = None,
    publisher: PublisherOpt = None,
    repo: RepoOpt = None,
    artifact_type: TypeOpt = None,
    policy: PolicyOpt = None,
    allow_network: NetOpt = False,
    out: OutOpt = None,
    work_dir: WorkOpt = None,
    request: RequestOpt = None,
) -> None:
    """Stage, inventory, hash and classify an artifact; print the manifest and intake checks."""
    req, manifest, checks = _execute(artifact, base, base_revision, base_sha256, publisher, repo,
                                     artifact_type, policy, allow_network, out, work_dir, request)
    _emit(req, manifest, checks)


@app.command()
def scan(
    artifact: ArtifactArg = None,
    base: BaseOpt = None,
    base_revision: BaseRevOpt = None,
    base_sha256: BaseShaOpt = None,
    publisher: PublisherOpt = None,
    repo: RepoOpt = None,
    artifact_type: TypeOpt = None,
    policy: PolicyOpt = None,
    allow_network: NetOpt = False,
    out: OutOpt = None,
    work_dir: WorkOpt = None,
    request: RequestOpt = None,
) -> None:
    """Full scan. Only intake is implemented; exits 20 (Undetermined) until inspectors exist."""
    req, manifest, checks = _execute(artifact, base, base_revision, base_sha256, publisher, repo,
                                     artifact_type, policy, allow_network, out, work_dir, request)
    _emit(req, manifest, checks, {
        "verdict": "Undetermined",
        "note": "static, provenance and behavioural inspectors are not yet implemented",
    })
    typer.echo("hashvault: inspectors not yet implemented; verdict Undetermined", err=True)
    raise typer.Exit(EXIT_UNDETERMINED)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
