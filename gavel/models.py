"""Data models for Gavel"""

from dataclasses import dataclass
from typing import Optional
import uuid
from datetime import datetime


@dataclass
class VerificationResult:
    """Result of vulnerability verification"""
    verdict: str  # "VALID" or "INVALID"
    reasoning: str
    confidence: str = "high"
    report_id: Optional[str] = None
    timestamp: Optional[str] = None
    poc: Optional[str] = None

    def __post_init__(self):
        if not self.report_id:
            self.report_id = str(uuid.uuid4())[:8]
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
