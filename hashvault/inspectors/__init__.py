"""HashVault inspectors.

Static and provenance run on the host and never deserialize an artifact.
The behavioural inspector is the only component that may load weights, and
only inside its container.
"""
