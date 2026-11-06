"""Gavel - AI-Powered Vulnerability Report Verification Tool"""

__version__ = "0.5.0"
__author__ = "Gavel Team"
__description__ = "Self-hosted contextual vulnerability triage"

from gavel.models import VerificationResult
from gavel.core import verify_report

__all__ = ["verify_report", "VerificationResult", "__version__"]
