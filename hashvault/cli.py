import json
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
import yaml
from pydantic import ValidationError

from hashvault import __version__
from hashvault.contracts.checks import CheckResult
from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest
from hashvault.inspectors.behavioural import InspectorReport as BehaviouralReport
from hashvault.inspectors.behavioural import scan_behavioural
from hashvault.inspectors.behavioural.probes import CHECK_IDS as BEHAVIOURAL_CHECKS
from hashvault.inspectors.provenance import InspectorReport as ProvenanceReport
from hashvault.inspectors.provenance import RegistryError, scan_provenance
from hashvault.inspectors.static import InspectorReport, scan_static
from hashvault.intake.pipeline import run_intake
from hashvault.policy import PolicyError, load_policy
from hashvault.verdict import decide, render_bundle

EXIT_USAGE = 2

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


def _emit(
    req: ScanRequest,
    manifest: ArtifactManifest,
    checks: list[CheckResult],
    extra: dict | None = None,
    kind: str = "intake",
):
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
        (out / f"{manifest.scan_id}.{kind}.json").write_text(text + "\n", encoding="utf-8")
    sys.stdout.write(text + "\n")


def _write_bundle(req: ScanRequest, scan_id: str, text: str) -> Path:
    """Write the evidence bundle. ``--out`` is a directory, or a .json file path."""
    if req.output_dir:
        out = Path(req.output_dir)
        if out.suffix == ".json":
            out.parent.mkdir(parents=True, exist_ok=True)
            dest = out
        else:
            out.mkdir(parents=True, exist_ok=True)
            dest = out / f"hashvault-report-{scan_id}.json"
    else:
        dest = Path.cwd() / f"hashvault-report-{scan_id}.json"
    dest.write_text(text, encoding="utf-8")
    return dest


def _static_failure(exc: Exception) -> InspectorReport:
    return InspectorReport(
        version=__version__,
        checks=[CheckResult(
            check_id="weight_coverage",
            status="error",
            reason=f"{type(exc).__name__}: {exc}",
        )],
        findings=[],
        coverage={"scanner_error": f"{type(exc).__name__}: {exc}"},
    )


def _provenance_failure(exc: Exception) -> ProvenanceReport:
    return ProvenanceReport(
        version=__version__,
        checks=[CheckResult(check_id="provenance_hash_match", status="error", reason=str(exc))],
        findings=[],
        coverage={"registry_error": str(exc)},
    )


def _behavioural_failure(exc: Exception) -> BehaviouralReport:
    reason = f"{type(exc).__name__}: {exc}"
    return BehaviouralReport(
        version=__version__,
        checks=[CheckResult(check_id=check_id, status="error", reason=reason) for check_id in BEHAVIOURAL_CHECKS],
        findings=[],
        coverage={"scanner_error": reason},
    )


ArtifactArg = Annotated[Optional[str], typer.Argument(help="Local dir/file/archive, or org/name@rev")]
BaseOpt = Annotated[Optional[str], typer.Option("--base", help="Claimed base model id")]
BaseRevOpt = Annotated[Optional[str], typer.Option("--base-revision")]
BaseShaOpt = Annotated[Optional[str], typer.Option("--base-sha256")]
PublisherOpt = Annotated[Optional[str], typer.Option("--publisher")]
RepoOpt = Annotated[Optional[str], typer.Option("--repo")]
TypeOpt = Annotated[Optional[str], typer.Option("--type", help="full_model | lora_adapter | auto")]
PolicyOpt = Annotated[Optional[str], typer.Option("--policy", help="Profile name or YAML path")]
NetOpt = Annotated[bool, typer.Option("--allow-network", help="Permit Hugging Face hub access")]
OutOpt = Annotated[Optional[Path], typer.Option("--out", help="Directory or .json path for the evidence bundle")]
WorkOpt = Annotated[Optional[Path], typer.Option("--work-dir", help="Quarantine root (default ./work)")]
RequestOpt = Annotated[Optional[Path], typer.Option("--request", help="YAML scan request file")]
RegistryOpt = Annotated[Optional[Path], typer.Option("--registry", help="Known-good registry YAML")]
BaseDirOpt = Annotated[Optional[Path], typer.Option("--base-dir", help="Local directory of base-model weights")]


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
    registry: RegistryOpt = None,
    base_dir: BaseDirOpt = None,
) -> None:
    """Run intake, static, provenance, and behavioural eligibility, then the verdict.

    Weights are loaded only inside the behavioural container, and only after
    eligibility. A skip or a container error does not reach Trusted. The verdict
    engine chooses the exit code.
    """
    req, manifest, checks = _execute(artifact, base, base_revision, base_sha256, publisher, repo,
                                     artifact_type, policy, allow_network, out, work_dir, request)
    try:
        pol = load_policy(req.policy_profile)
    except PolicyError as exc:
        _fail_usage(str(exc))
    try:
        static_report = scan_static(manifest, pol)
    except Exception as exc:
        static_report = _static_failure(exc)
    try:
        prov_report = scan_provenance(req, manifest, pol, registry_path=registry)
    except RegistryError as exc:
        if not any(finding.severity == "critical" for finding in static_report.findings):
            _fail_usage(str(exc))
        prov_report = _provenance_failure(exc)
    except Exception as exc:
        prov_report = _provenance_failure(exc)
    try:
        behavioural_report = scan_behavioural(
            req,
            manifest,
            static_report,
            pol,
            registry_path=str(registry) if registry else None,
            base_dir=str(base_dir) if base_dir else None,
        )
    except Exception as exc:
        behavioural_report = _behavioural_failure(exc)
    bundle = decide(req, manifest, checks, [static_report, prov_report, behavioural_report], pol)
    text = render_bundle(bundle)
    _write_bundle(req, manifest.scan_id, text)
    sys.stdout.write(text)
    verdict = bundle.verdict
    typer.echo(
        f"hashvault: {verdict.classification} {verdict.rule_id}: {verdict.reason}",
        err=True,
    )
    raise typer.Exit(verdict.exit_code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
