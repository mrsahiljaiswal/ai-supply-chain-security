import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

from hashvault.contracts.request import ScanRequest
from hashvault.intake.walk import IntakeState, LimitExceeded, make_writable, stage_local_tree


class StageError(Exception):
    pass


def new_scan_id(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"hv-{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"


def default_work_root() -> Path:
    return Path(os.environ.get("HASHVAULT_WORK_DIR", "work"))


def create_work_dir(work_root: Path, scan_id: str) -> Path:
    work_dir = work_root / scan_id
    (work_dir / "artifact").mkdir(parents=True, exist_ok=False)
    return work_dir


def stage_local(request: ScanRequest, state: IntakeState) -> Path:
    src = Path(request.artifact).resolve()
    stage_local_tree(src, state)
    return src


def stage_hub(request: ScanRequest, state: IntakeState) -> str:
    ref = request.hub_ref
    if ref is None:
        raise StageError(f"not a hub repo id: {request.artifact}")
    repo_id, revision = ref
    try:
        from huggingface_hub import HfApi, snapshot_download
    except ImportError as exc:
        raise StageError("huggingface_hub is not installed; pip install 'hashvault[hub]'") from exc

    api = HfApi()
    try:
        info = api.model_info(repo_id, revision=revision, files_metadata=True)
    except Exception as exc:
        raise StageError(f"cannot resolve {repo_id}@{revision or 'main'}: {exc}") from exc
    resolved = info.sha
    siblings = info.siblings or []
    if len(siblings) > state.limits.max_file_count:
        raise LimitExceeded("max_file_count", f"repo lists {len(siblings)} files")
    declared = sum((s.size or 0) for s in siblings)
    if declared > state.limits.max_total_bytes:
        raise LimitExceeded("max_total_bytes", f"repo declares {declared} bytes")

    download_dir = state.work_dir / "download"
    try:
        snapshot_download(repo_id=repo_id, revision=resolved, local_dir=download_dir)
    except Exception as exc:
        raise StageError(f"download of {repo_id}@{resolved} failed: {exc}") from exc
    shutil.rmtree(download_dir / ".cache", ignore_errors=True)
    stage_local_tree(download_dir, state)
    shutil.rmtree(download_dir, ignore_errors=True)
    return resolved


def remove_work_dir(work_dir: Path) -> None:
    make_writable(work_dir)
    shutil.rmtree(work_dir, ignore_errors=True)
