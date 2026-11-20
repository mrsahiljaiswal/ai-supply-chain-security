"""Corpus scorecard rates. The metric test does not scan; the corpus test does."""

import json
from pathlib import Path

from typer.testing import CliRunner

from hashvault.cli import app
from hashvault.scorecard import (
    Outcome,
    compute_metrics,
    detection_note,
    invocations_from_readme,
    is_false_positive,
    is_strict_detection,
)

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def _outcome(**kwargs) -> Outcome:
    data = dict(
        name="row",
        label="suspicious",
        exit_code=30,
        expected_check="pickle_dangerous_callable",
        check_ids=["pickle_dangerous_callable"],
        finding_severities=["critical"],
        duration_ms=10,
    )
    data.update(kwargs)
    return Outcome(**data)


def test_metrics_rates_are_pinned():
    # 1 of 2 suspicious rows has the expected check. 1 of 2 clean rows is warned.
    outcomes = [
        _outcome(name="hit", duration_ms=10),
        _outcome(
            name="miss",
            expected_check="provenance_config",
            check_ids=["provenance_hash_match"],
            finding_severities=["critical"],
            duration_ms=10,
        ),
        _outcome(
            name="clean-warn",
            label="clean",
            exit_code=10,
            expected_check="none",
            check_ids=[],
            finding_severities=["warning"],
            duration_ms=5,
        ),
        _outcome(
            name="clean-gap",
            label="clean",
            exit_code=20,
            expected_check="none",
            check_ids=["provenance_publisher"],
            finding_severities=[],
            duration_ms=5,
        ),
    ]
    metrics = compute_metrics(outcomes)
    assert metrics["detection_rate"] == 0.5
    assert metrics["suspicious_detected"] == 1
    assert metrics["suspicious"] == 2
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["clean_false_positives"] == 1
    assert metrics["clean"] == 2
    assert metrics["caught_rate"] == 1.0
    assert metrics["scan_time_ms"]["total"] == 30
    assert metrics["scan_time_ms"]["per_artifact"] == {
        "hit": 10,
        "miss": 10,
        "clean-warn": 5,
        "clean-gap": 5,
    }
    assert is_strict_detection(outcomes[1]) is False
    assert "strict miss" in detection_note(outcomes[1])
    assert is_false_positive(outcomes[3]) is False
    both = _outcome(
        name="config-mismatch",
        expected_check="provenance_config",
        check_ids=["provenance_hash_match", "provenance_config"],
        finding_severities=["critical", "warning"],
    )
    assert is_strict_detection(both) is True
    assert "provenance_config is present" in detection_note(both)
    partial = _outcome(
        expected_check="intake.format_mismatch;pickle_dangerous_callable",
        check_ids=["pickle_dangerous_callable"],
    )
    assert is_strict_detection(partial) is False
    complete = _outcome(
        expected_check="intake.format_mismatch;pickle_dangerous_callable",
        check_ids=["intake.format_mismatch", "pickle_dangerous_callable"],
    )
    assert is_strict_detection(complete) is True
    assert is_strict_detection(_outcome(exit_code=0)) is False
    assert is_false_positive(_outcome(
        label="clean", exit_code=30, expected_check="none", check_ids=[], finding_severities=[],
    )) is True
    assert is_false_positive(_outcome(
        label="clean", exit_code=20, expected_check="none", check_ids=[],
        finding_severities=["critical"],
    )) is True


def test_readme_invocations_do_not_invent_flags():
    found = invocations_from_readme((ROOT / "corpus" / "README.md").read_text(encoding="utf-8"))
    lookalike = found["corpus/suspicious/lookalike-name"]
    assert lookalike["repo"] == "acme/tiny-bose"
    assert "base" not in lookalike
    assert "request" not in lookalike
    mismatch = found["corpus/suspicious/hash-mismatch"]
    assert mismatch["request"] == "corpus/suspicious/hash-mismatch/scan.yaml"
    assert "base" not in mismatch
    assert "artifact" not in mismatch
    full = found["corpus/clean/tiny-full-model"]
    assert full["base"] == "acme/tiny-base"
    assert full["repo"] == "acme/tiny-base"
    lora = found["corpus/clean/tiny-lora"]
    assert lora["base"] == "acme/tiny-base"
    assert "repo" not in lora
    config = found["corpus/suspicious/config-mismatch"]
    assert config["base"] == "acme/tiny-base"
    assert config["repo"] == "acme/tiny-base"


def test_score_real_corpus_writes_scorecard():
    result = runner.invoke(app, ["score", str(ROOT / "corpus")])
    assert result.exit_code == 0, result.stdout + result.stderr
    document_path = ROOT / "corpus" / "scorecard.json"
    markdown_path = ROOT / "corpus" / "scorecard.md"
    assert document_path.is_file()
    assert markdown_path.is_file()
    document = json.loads(document_path.read_text(encoding="utf-8"))
    assert document["metrics"]["detection_rate"] > 0
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "Asia/Calcutta" in markdown
    assert "+05:30" in markdown
    assert "detection rate" in result.stdout
