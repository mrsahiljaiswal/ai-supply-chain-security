import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))

import generate  # noqa: E402

from hashvault.contracts.request import ScanRequest  # noqa: E402
from hashvault.intake.pipeline import run_intake  # noqa: E402


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory) -> dict[str, Path]:
    return generate.build_all(tmp_path_factory.mktemp("fixtures"))


@pytest.fixture
def work_root(tmp_path) -> Path:
    return tmp_path / "work"


@pytest.fixture
def intake(work_root):
    def _run(artifact, **kw):
        req = ScanRequest(artifact=str(artifact), **kw)
        manifest, checks = run_intake(req, work_root=work_root)
        return manifest, {c.check_id: c for c in checks}

    return _run
