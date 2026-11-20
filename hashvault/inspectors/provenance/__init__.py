"""Host-side provenance inspector.

Never loads weights, never unpickles, and never imports artifact code.
Inputs are a ScanRequest, an ArtifactManifest, and a local known-good registry.
"""

from hashvault.inspectors.provenance.inspector import (
    INSPECTOR,
    InspectorReport,
    scan_provenance,
)
from hashvault.inspectors.provenance.registry import RegistryError, load_registry

__all__ = [
    "INSPECTOR",
    "InspectorReport",
    "RegistryError",
    "load_registry",
    "scan_provenance",
]
