"""Legacy result model; contextual service models live separately."""

from dataclasses import dataclass
from typing import Optional
import uuid
from datetime import datetime, timezone


@dataclass
class VerificationResult:
    """A model-assisted assessment, not a proof of exploitability."""
    verdict: str  # VALID, INVALID, NEEDS_REVIEW (or ERROR for failed batch input)
    reasoning: str
    confidence: str = "low"
    report_id: Optional[str] = None
    timestamp: Optional[str] = None
    poc: Optional[str] = None

    def __post_init__(self):
        if self.verdict not in {"VALID", "INVALID", "NEEDS_REVIEW", "ERROR"}:
            raise ValueError("Unknown verification verdict")
        if not self.report_id:
            self.report_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
