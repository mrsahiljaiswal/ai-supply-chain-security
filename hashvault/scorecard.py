"""Corpus scorecard: detection rate, false-positive rate, and scan time.

Invocations come from the command table in the corpus README. A row that is
absent from that table falls back to a sidecar ``scan.yaml`` in the artifact
directory. Flags that the README does not list are not added, except
``--registry`` (always the corpus registry), ``--work-dir``, and ``--out``
(quarantine and bundle paths; they do not change checks).
"""

from __future__ import annotations

import csv
import json
import os
import re
import shlex
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo

from typer import Exit as TyperExit

CALCUTTA = ZoneInfo("Asia/Kolkata")
CLOCK_LABEL = "+05:30 (Asia/Calcutta, UTC+5:30)"

_COMMAND_ROW = re.compile(
    r"^\|\s*`(?P<label>[^`]+)`\s*\|\s*`python3 -m hashvault scan (?P<args>[^`]+)`\s*\|\s*$",
    re.MULTILINE,
)

_VALUE_FLAGS = {
    "--base": "base",
    "--base-revision": "base_revision",
    "--base-sha256": "base_sha256",
    "--publisher": "publisher",
    "--repo": "repo",
    "--type": "artifact_type",
    "--policy": "policy",
    "--out": "out",
    "--work-dir": "work_dir",
    "--request": "request",
    "--registry": "registry",
    "--base-dir": "base_dir",
}

_MANIFEST_COLUMNS = {
    "name",
    "path",
    "label",
    "attack",
    "expected_check",
    "expected_severity",
    "notes",
}


class ScoreError(Exception):
    """The corpus cannot be scored as written."""


@dataclass
class Outcome:
    """One corpus row after a scan, or a fake row for the metric tests."""

    name: str
    label: str
    exit_code: int
    expected_check: str
    check_ids: list[str]
    finding_severities: list[str]
    duration_ms: float
    notes: str = ""
    path: str = ""
    classification: str | None = None
    rule_id: str | None = None
    invocation: str = ""
    scanned_at: datetime | None = None
    extra_notes: str = ""
    observed_check_ids: list[str] = field(default_factory=list)


def expected_ids(text: str | None) -> list[str]:
    """Split a manifest ``expected_check`` cell. ``none`` and blanks contribute nothing."""
    if not text:
        return []
    found = []
    for part in text.split(";"):
        item = part.strip()
        if item and item != "none":
            found.append(item)
    return found


def is_strict_detection(outcome: Outcome) -> bool:
    """Non-zero exit and every expected check id present in findings or checks.

    A non-zero exit for some other check is a miss. ``provenance_config`` counts
    only when that id is actually present, even if ``provenance_hash_match`` is
    what blocked the artifact.
    """
    if outcome.label != "suspicious" or outcome.exit_code == 0:
        return False
    wanted = expected_ids(outcome.expected_check)
    if not wanted:
        return False
    have = set(outcome.check_ids)
    return all(item in have for item in wanted)


def is_caught(outcome: Outcome) -> bool:
    """Suspicious row whose scan exit code is non-zero, whatever the check was."""
    return outcome.label == "suspicious" and outcome.exit_code != 0


def is_false_positive(outcome: Outcome) -> bool:
    """Clean row that exits 30 or 10, or has a warning or critical finding.

    Exit 20 with only skipped coverage gaps is not a false positive.
    """
    if outcome.label != "clean":
        return False
    if outcome.exit_code in (10, 30):
        return True
    return any(severity in ("warning", "critical") for severity in outcome.finding_severities)


def detection_note(outcome: Outcome) -> str:
    """Explain a strict miss, and the config-mismatch overlap when it applies."""
    wanted = expected_ids(outcome.expected_check)
    have = set(outcome.check_ids)
    if "provenance_config" in wanted and "provenance_hash_match" in have:
        if "provenance_config" in have:
            return (
                "expected_check is provenance_config. provenance_hash_match is also present; "
                "this row is a strict detection only because provenance_config is present."
            )
        return (
            "expected_check is provenance_config. provenance_hash_match is present and the exit "
            "code is non-zero, but provenance_config is absent, so this row is a strict miss."
        )
    if outcome.label == "suspicious" and is_caught(outcome) and not is_strict_detection(outcome):
        missing = [item for item in wanted if item not in have]
        listed = ", ".join(missing) if missing else "(none listed)"
        return f"non-zero exit without expected check {listed}; counted as a miss, not a detection."
    return ""


def compute_metrics(outcomes: list[Outcome]) -> dict[str, Any]:
    """Detection rate, caught rate, false-positive rate, and scan time."""
    suspicious = [item for item in outcomes if item.label == "suspicious"]
    clean = [item for item in outcomes if item.label == "clean"]
    detected = [item for item in suspicious if is_strict_detection(item)]
    caught = [item for item in suspicious if is_caught(item)]
    false_positives = [item for item in clean if is_false_positive(item)]
    per_artifact = {item.name: round(float(item.duration_ms), 3) for item in outcomes}
    total = round(sum(per_artifact.values()), 3)
    return {
        "detection_rate": _rate(len(detected), len(suspicious)),
        "caught_rate": _rate(len(caught), len(suspicious)),
        "false_positive_rate": _rate(len(false_positives), len(clean)),
        "suspicious": len(suspicious),
        "suspicious_detected": len(detected),
        "suspicious_caught": len(caught),
        "clean": len(clean),
        "clean_false_positives": len(false_positives),
        "scan_time_ms": {
            "total": total,
            "per_artifact": per_artifact,
        },
    }


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def parse_scan_argv(args: list[str]) -> dict[str, Any]:
    """Parse the arguments that follow ``hashvault scan`` in the corpus README."""
    parsed: dict[str, Any] = {}
    index = 0
    positional: list[str] = []
    while index < len(args):
        token = args[index]
        if token == "--allow-network":
            parsed["allow_network"] = True
            index += 1
            continue
        if token in _VALUE_FLAGS:
            if index + 1 >= len(args):
                raise ScoreError(f"corpus README command is missing a value for {token}")
            parsed[_VALUE_FLAGS[token]] = args[index + 1]
            index += 2
            continue
        if token.startswith("-"):
            raise ScoreError(f"corpus README command has an unsupported flag: {token}")
        positional.append(token)
        index += 1
    if len(positional) > 1:
        raise ScoreError(f"corpus README command has extra positional arguments: {positional}")
    if positional:
        parsed["artifact"] = positional[0]
    return parsed


def invocations_from_readme(readme: str) -> dict[str, dict[str, Any]]:
    """Map each artifact path in the README command table to its scan flags."""
    found: dict[str, dict[str, Any]] = {}
    for match in _COMMAND_ROW.finditer(readme):
        parsed = parse_scan_argv(shlex.split(match.group("args")))
        if parsed.get("artifact"):
            key = _norm(parsed["artifact"])
        elif parsed.get("request"):
            key = _norm(str(Path(parsed["request"]).parent))
        else:
            raise ScoreError(f"corpus README command names no artifact: {match.group('args')}")
        found[key] = parsed
    if not found:
        raise ScoreError("corpus README has no scan command table")
    return found


def _norm(path: str) -> str:
    return path.strip().replace("\\", "/").rstrip("/")


def _load_manifest(path: Path) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScoreError(f"cannot read manifest {path}: {exc}") from exc
    reader = csv.DictReader(text.splitlines())
    fieldnames = set(reader.fieldnames or [])
    missing = _MANIFEST_COLUMNS - fieldnames
    if missing:
        listed = ", ".join(sorted(missing))
        raise ScoreError(f"manifest {path} is missing columns: {listed}")
    rows = []
    for row in reader:
        label = (row.get("label") or "").strip()
        if label not in {"clean", "suspicious"}:
            raise ScoreError(f"manifest row {row.get('name')!r} has label {label!r}")
        rows.append(row)
    if not rows:
        raise ScoreError(f"manifest {path} has no rows")
    return rows


def _invocation_text(parsed: dict[str, Any]) -> str:
    parts = ["hashvault scan"]
    if parsed.get("artifact"):
        parts.append(str(parsed["artifact"]))
    for flag, key in (
        ("--request", "request"),
        ("--base", "base"),
        ("--base-revision", "base_revision"),
        ("--base-sha256", "base_sha256"),
        ("--publisher", "publisher"),
        ("--repo", "repo"),
        ("--type", "artifact_type"),
        ("--policy", "policy"),
        ("--registry", "registry"),
        ("--base-dir", "base_dir"),
    ):
        if parsed.get(key):
            parts.extend([flag, str(parsed[key])])
    if parsed.get("allow_network"):
        parts.append("--allow-network")
    return " ".join(parts)


def _observed(bundle: Any) -> tuple[list[str], list[str]]:
    check_ids: list[str] = []
    seen: set[str] = set()
    severities: list[str] = []

    def add(check_id: str) -> None:
        if check_id not in seen:
            seen.add(check_id)
            check_ids.append(check_id)

    for check in bundle.intake_checks:
        add(check.check_id)
    for report in bundle.reports:
        for check in report.checks:
            add(check.check_id)
        for finding in report.findings:
            add(finding.check_id)
            severities.append(finding.severity)
    return check_ids, severities


def _scan_kwargs(parsed: dict[str, Any], work_dir: Path, out_dir: Path, registry: Path) -> dict[str, Any]:
    def as_path(key: str, default: Path | None = None) -> Path | None:
        value = parsed.get(key)
        if value:
            return Path(value)
        return default

    return {
        "artifact": parsed.get("artifact"),
        "base": parsed.get("base"),
        "base_revision": parsed.get("base_revision"),
        "base_sha256": parsed.get("base_sha256"),
        "publisher": parsed.get("publisher"),
        "repo": parsed.get("repo"),
        "artifact_type": parsed.get("artifact_type"),
        "policy": parsed.get("policy"),
        "allow_network": bool(parsed.get("allow_network")),
        "out": as_path("out", out_dir),
        "work_dir": as_path("work_dir", work_dir),
        "request": as_path("request"),
        "registry": registry,
        "base_dir": as_path("base_dir"),
    }


def _require_paths(parsed: dict[str, Any], repo_root: Path) -> None:
    artifact = parsed.get("artifact")
    if artifact and not (repo_root / artifact).exists():
        raise ScoreError(f"artifact path from the corpus README does not exist: {artifact}")
    request = parsed.get("request")
    if request and not (repo_root / request).exists():
        raise ScoreError(f"request path from the corpus README does not exist: {request}")


def _row_invocation(manifest_path: str, parsed_table: dict[str, dict[str, Any]], repo_root: Path) -> dict[str, Any]:
    key = _norm(manifest_path)
    if key in parsed_table:
        return dict(parsed_table[key])
    sidecar = repo_root / manifest_path / "scan.yaml"
    if sidecar.is_file():
        return {"request": str(Path(manifest_path) / "scan.yaml")}
    raise ScoreError(
        f"no README scan command for {manifest_path} and no sidecar scan.yaml; "
        "refusing to invent --base or --repo"
    )


def score_corpus(corpus_dir: Path, scan: Callable[..., Any]) -> dict[str, Any]:
    """Scan each manifest row and write ``scorecard.json`` and ``scorecard.md``."""
    corpus_dir = corpus_dir.resolve()
    manifest_path = corpus_dir / "manifest.csv"
    readme_path = corpus_dir / "README.md"
    registry_path = corpus_dir / "registry.yaml"
    if not manifest_path.is_file():
        raise ScoreError(f"corpus manifest not found: {manifest_path}")
    if not readme_path.is_file():
        raise ScoreError(f"corpus README not found: {readme_path}")
    if not registry_path.is_file():
        raise ScoreError(f"corpus registry not found: {registry_path}")
    rows = _load_manifest(manifest_path)
    invocations = invocations_from_readme(readme_path.read_text(encoding="utf-8"))
    repo_root = corpus_dir.parent
    original = Path.cwd()
    outcomes: list[Outcome] = []
    os.chdir(repo_root)
    try:
        with tempfile.TemporaryDirectory(prefix="hashvault-score-") as temporary:
            temp_root = Path(temporary)
            for index, row in enumerate(rows):
                parsed = _row_invocation(row["path"], invocations, repo_root)
                if not parsed.get("registry"):
                    parsed["registry"] = str(registry_path)
                work_dir = temp_root / f"work-{index}"
                out_dir = temp_root / f"out-{index}"
                _require_paths(parsed, repo_root)
                kwargs = _scan_kwargs(parsed, work_dir, out_dir, registry_path)
                started = time.perf_counter()
                bundle = None
                try:
                    output = scan(**kwargs)
                except TyperExit as exc:
                    exit_code = 0 if exc.exit_code is None else int(exc.exit_code)
                else:
                    bundle = output.bundle
                    exit_code = int(output.exit_code)
                elapsed = (time.perf_counter() - started) * 1000
                check_ids: list[str] = []
                severities: list[str] = []
                classification = None
                rule_id = None
                if bundle is not None:
                    check_ids, severities = _observed(bundle)
                    classification = bundle.verdict.classification
                    rule_id = bundle.verdict.rule_id
                outcome = Outcome(
                    name=(row.get("name") or "").strip(),
                    label=(row.get("label") or "").strip(),
                    exit_code=exit_code,
                    expected_check=(row.get("expected_check") or "").strip(),
                    check_ids=check_ids,
                    finding_severities=severities,
                    duration_ms=elapsed,
                    path=(row.get("path") or "").strip(),
                    classification=classification,
                    rule_id=rule_id,
                    invocation=_invocation_text(parsed),
                    scanned_at=datetime.now(timezone.utc),
                    extra_notes=(row.get("notes") or "").strip(),
                )
                outcome.notes = _join_notes(detection_note(outcome), outcome.extra_notes)
                outcome.observed_check_ids = list(check_ids)
                outcomes.append(outcome)
    finally:
        os.chdir(original)
    generated_at = datetime.now(timezone.utc)
    card = build_scorecard(
        outcomes,
        generated_at=generated_at,
        corpus=_display_path(corpus_dir, original),
    )
    json_path = corpus_dir / "scorecard.json"
    md_path = corpus_dir / "scorecard.md"
    json_path.write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(card), encoding="utf-8")
    card["scorecard_json"] = _display_path(json_path, original)
    card["scorecard_md"] = _display_path(md_path, original)
    return card


def _join_notes(*parts: str) -> str:
    return " ".join(part for part in parts if part)


def _display_path(path: Path, base: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(base.resolve()))
    except ValueError:
        return str(resolved)


def _clock(when: datetime | None) -> str:
    if when is None:
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    local = when.astimezone(CALCUTTA)
    return local.strftime("%Y-%m-%d %H:%M:%S ") + CLOCK_LABEL


def build_scorecard(
    outcomes: list[Outcome],
    *,
    generated_at: datetime,
    corpus: str,
) -> dict[str, Any]:
    """Assemble the scorecard document from outcomes. Does not run scans."""
    metrics = compute_metrics(outcomes)
    document_rows = []
    for outcome in outcomes:
        document_rows.append({
            "name": outcome.name,
            "path": outcome.path,
            "label": outcome.label,
            "expected_check": outcome.expected_check,
            "exit_code": outcome.exit_code,
            "classification": outcome.classification,
            "rule_id": outcome.rule_id,
            "strict_detection": is_strict_detection(outcome),
            "caught": is_caught(outcome),
            "false_positive": is_false_positive(outcome),
            "scan_time_ms": round(float(outcome.duration_ms), 3),
            "scanned_at": _clock(outcome.scanned_at),
            "invocation": outcome.invocation,
            "observed_check_ids": list(outcome.observed_check_ids or outcome.check_ids),
            "notes": outcome.notes,
        })
    return {
        "timezone": "Asia/Calcutta",
        "timezone_iana": "Asia/Kolkata",
        "utc_offset": "+05:30",
        "generated_at": _clock(generated_at),
        "corpus": corpus,
        "metrics": metrics,
        "rows": document_rows,
    }


def render_markdown(card: dict[str, Any]) -> str:
    """Scorecard markdown. Clock times are Asia/Calcutta (UTC+5:30)."""
    metrics = card["metrics"]
    scan_time = metrics["scan_time_ms"]
    lines = [
        "# Corpus scorecard",
        "",
        f"Generated {card['generated_at']}.",
        "",
        "Clock times in this file are Asia/Calcutta (UTC+5:30).",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        "| Detection rate (strict) | "
        f"{_fmt_rate(metrics['detection_rate'], metrics['suspicious_detected'], metrics['suspicious'])} |",
        "| Caught rate (exit non-zero) | "
        f"{_fmt_rate(metrics['caught_rate'], metrics['suspicious_caught'], metrics['suspicious'])} |",
        "| False-positive rate | "
        f"{_fmt_rate(metrics['false_positive_rate'], metrics['clean_false_positives'], metrics['clean'])} |",
        f"| Scan time | {scan_time['total']:.3f} ms |",
        "",
        "Strict detection rate is the number of suspicious rows whose exit code is non-zero "
        "and whose findings or checks include every expected check id, divided by the number "
        "of suspicious rows. A suspicious row that exits non-zero for a different reason is a "
        "miss, not a detection. Caught rate is the number of suspicious rows with a non-zero "
        "exit code, divided by the number of suspicious rows.",
        "",
        "False-positive rate is the number of clean rows that exit 30 or 10, or that have any "
        "finding with severity warning or critical, divided by the number of clean rows. "
        "Exit 20 with only skipped coverage gaps is not a false positive.",
        "",
        "Scan time is the wall time around each scan call, in milliseconds, plus the total.",
        "",
        "## Artifacts",
        "",
        "| Artifact | Label | Exit | Verdict | Strict | Caught | False positive | Scan time (ms) | Scanned at | Expected check |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    notes: list[str] = []
    for row in card["rows"]:
        verdict = row.get("classification") or ""
        if row.get("rule_id"):
            verdict = f"{verdict} {row['rule_id']}".strip()
        lines.append(
            "| {name} | {label} | {exit_code} | {verdict} | {strict} | {caught} | {fp} | {ms:.3f} | {when} | {expected} |".format(
                name=_cell(row["name"]),
                label=_cell(row["label"]),
                exit_code=_cell(row["exit_code"]),
                verdict=_cell(verdict),
                strict="yes" if row["strict_detection"] else "no",
                caught="yes" if row["caught"] else "no",
                fp="yes" if row["false_positive"] else "no",
                ms=row["scan_time_ms"],
                when=_cell(row.get("scanned_at") or ""),
                expected=_cell(row.get("expected_check") or ""),
            )
        )
        if row.get("notes"):
            notes.append(f"- **{_cell(row['name'])}**: {_cell(row['notes'])}")
    lines.extend(["", "## Notes", ""])
    if notes:
        lines.extend(notes)
    else:
        lines.append("No row notes.")
    lines.append("")
    return "\n".join(lines)


def _fmt_rate(rate: float, numerator: int, denominator: int) -> str:
    return f"{rate:.3f} ({numerator}/{denominator})"


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def format_summary(card: dict[str, Any]) -> str:
    """Short stdout summary of the three rates and where the files went."""
    metrics = card["metrics"]
    lines = [
        "detection rate "
        f"{_fmt_rate(metrics['detection_rate'], metrics['suspicious_detected'], metrics['suspicious'])}",
        "caught rate "
        f"{_fmt_rate(metrics['caught_rate'], metrics['suspicious_caught'], metrics['suspicious'])}",
        "false-positive rate "
        f"{_fmt_rate(metrics['false_positive_rate'], metrics['clean_false_positives'], metrics['clean'])}",
        f"scan time {metrics['scan_time_ms']['total']:.3f} ms",
        f"wrote {card.get('scorecard_json', 'scorecard.json')}",
        f"wrote {card.get('scorecard_md', 'scorecard.md')}",
    ]
    return "\n".join(lines)
