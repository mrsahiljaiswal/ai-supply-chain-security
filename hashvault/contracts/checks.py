from typing import Any, Literal

from pydantic import BaseModel, Field

CheckStatus = Literal["passed", "failed", "error", "skipped", "not_applicable"]
Severity = Literal["info", "warning", "critical"]


class Finding(BaseModel):
    inspector: str
    check_id: str
    severity: Severity
    message: str
    location: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class CheckResult(BaseModel):
    check_id: str
    status: CheckStatus
    duration_ms: float = 0.0
    reason: str | None = None
    severity: Severity | None = None
    details: dict[str, Any] = Field(default_factory=dict)
