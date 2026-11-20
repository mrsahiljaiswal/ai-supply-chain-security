"""Verdict engine. The only module that classifies an artifact."""

from hashvault.verdict.engine import canonical_bundle_sha256, decide, decide_verdict, render_bundle
from hashvault.verdict.models import EvidenceBundle, InspectorReport, ManifestSummary, Verdict

__all__ = [
    "EvidenceBundle",
    "InspectorReport",
    "ManifestSummary",
    "Verdict",
    "canonical_bundle_sha256",
    "decide",
    "decide_verdict",
    "render_bundle",
]
