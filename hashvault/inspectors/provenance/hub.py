"""Hugging Face metadata read. Imported only when a check decides to call the network."""

from typing import Any


class HubLibraryMissing(Exception):
    """huggingface_hub is not installed. The hub check fails closed."""


def fetch_hub_metadata(repo_id: str, revision: str | None = None) -> dict[str, Any]:
    """Read author, sha, and private from the Hub. This performs network I/O.

    Tests must mock this function or huggingface_hub. Do not call it against the network.
    """
    try:
        import huggingface_hub
    except ImportError as exc:
        raise HubLibraryMissing("huggingface_hub_missing") from exc
    info = huggingface_hub.HfApi().model_info(repo_id, revision=revision)
    card = getattr(info, "card_data", None)
    if card is not None and not isinstance(card, dict):
        to_dict = getattr(card, "to_dict", None)
        card = to_dict() if callable(to_dict) else None
    return {
        "author": getattr(info, "author", None),
        "sha": getattr(info, "sha", None),
        "private": getattr(info, "private", None),
        "card_data": card,
    }
