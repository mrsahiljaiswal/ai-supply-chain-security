"""Host orchestrator for the behavioural inspector.

Eligibility runs here, before any backend. The backend is Docker unless a
test sets HASHVAULT_BEHAVIOURAL_BACKEND=scripted. That variable is not a way
to bless an untrusted file.
"""

import os
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from hashvault import __version__
from hashvault.contracts.checks import CheckResult, Finding
from hashvault.contracts.manifest import ArtifactManifest
from hashvault.contracts.request import ScanRequest
from hashvault.inspectors.behavioural.backend import (
    BehaviourBackend,
    DockerBackend,
    GenerateResult,
    ScriptedBackend,
)
from hashvault.inspectors.behavioural.eligibility import Eligibility, check_eligibility
from hashvault.inspectors.behavioural.probes import CHECK_IDS, evaluate_probes, load_probe_bank
from hashvault.policy import Policy, load_policy

INSPECTOR = "behavioural"


class InspectorReport(BaseModel):
    inspector: str = INSPECTOR
    version: str
    checks: list[CheckResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


def _blank_checks(status: str, reason: str) -> list[CheckResult]:
    return [CheckResult(check_id=check_id, status=status, reason=reason) for check_id in CHECK_IDS]


def _report(checks: list[CheckResult], findings: list[Finding], coverage: dict[str, Any]) -> InspectorReport:
    return InspectorReport(
        version=__version__,
        checks=checks,
        findings=findings,
        coverage=coverage,
    )


def _skipped(decision: Eligibility) -> InspectorReport:
    return _report(
        _blank_checks("skipped", decision.reason or "skipped"),
        [],
        {
            "eligible": False,
            "reason": decision.reason,
            "limitations": [
                "Eligibility failed closed before any weight file was opened.",
                "A skipped behavioural report is not coverage and is not an error.",
            ],
        },
    )


def _errored(reason: str, *, eligible: bool, backend: str) -> InspectorReport:
    return _report(
        _blank_checks("error", reason),
        [],
        {
            "eligible": eligible,
            "reason": reason,
            "backend": backend,
            "limitations": [
                "The model was not scored. An error is not a pass.",
                "Weights are not loaded on the host when the container cannot run.",
            ],
        },
    )


def _select_backend(manifest: ArtifactManifest, backend: BehaviourBackend | None) -> tuple[BehaviourBackend, str]:
    if backend is not None:
        name = "scripted" if isinstance(backend, ScriptedBackend) else "docker"
        return backend, name
    if os.environ.get("HASHVAULT_BEHAVIOURAL_BACKEND") == "scripted":
        return ScriptedBackend.from_env(), "scripted"
    return DockerBackend(manifest.work_dir), "docker"


def scan_behavioural(
    request: ScanRequest,
    manifest: ArtifactManifest,
    static_report,
    policy: Policy | None = None,
    *,
    registry_path: str | None = None,
    base_dir: str | None = None,
    backend: BehaviourBackend | None = None,
) -> InspectorReport:
    """Run eligibility, then the backend, then the pure probe checks.

    A skip has status=skipped and no finding. A backend error has status=error
    and does not load weights on the host.
    """
    policy = policy or load_policy(request.policy_profile)
    decision = check_eligibility(
        request,
        manifest,
        static_report,
        policy,
        registry_path=registry_path,
        base_dir=base_dir,
    )
    if not decision.eligible:
        return _skipped(decision)
    selected, backend_name = _select_backend(manifest, backend)
    try:
        bank = load_probe_bank()
    except (OSError, ValueError) as exc:
        return _errored(f"probe_bank: {exc}", eligible=True, backend=backend_name)
    if decision.artifact_dir is None or decision.base_dir is None:
        return _errored("base_weights_missing", eligible=False, backend=backend_name)
    started = time.perf_counter()
    try:
        result: GenerateResult = selected.generate(
            bank.as_jobs(),
            Path(decision.artifact_dir),
            Path(decision.base_dir),
        )
    except Exception as exc:
        return _errored(f"{type(exc).__name__}: {exc}", eligible=True, backend=backend_name)
    if result.status != "ok":
        return _errored(result.reason or "docker_failed", eligible=True, backend=backend_name)
    try:
        checks, findings = evaluate_probes(bank, result.base, result.candidate, policy)
    except Exception as exc:
        return _errored(f"{type(exc).__name__}: {exc}", eligible=True, backend=backend_name)
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    checks = [check.model_copy(update={"duration_ms": elapsed}) for check in checks]
    prompt_ids = [probe.id for probe in bank.probes]
    return _report(
        checks,
        findings,
        {
            "eligible": True,
            "reason": None,
            "backend": backend_name,
            "base_dir": str(decision.base_dir) if decision.base_dir else None,
            "prompt_ids": prompt_ids,
            "limitations": [
                "A pass is not a claim that the model has no backdoor.",
                "The probe bank is fixed. Trigger search is not part of v1.",
                "Weights are loaded only inside the behavioural container.",
            ],
        },
    )
