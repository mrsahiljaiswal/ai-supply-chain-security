"""Behavioural inspector. Decision logic stays on the host. Weights load only in the backend."""

from hashvault.inspectors.behavioural.eligibility import Eligibility, check_eligibility
from hashvault.inspectors.behavioural.inspector import InspectorReport, scan_behavioural
from hashvault.inspectors.behavioural.probes import ProbeBank, evaluate_probes, load_probe_bank

__all__ = [
    "Eligibility",
    "InspectorReport",
    "ProbeBank",
    "check_eligibility",
    "evaluate_probes",
    "load_probe_bank",
    "scan_behavioural",
]
