"""Host-side static inspector. Never deserializes and never imports an artifact."""

from hashvault.inspectors.static.scanner import InspectorReport, scan_static

__all__ = ["InspectorReport", "scan_static"]
