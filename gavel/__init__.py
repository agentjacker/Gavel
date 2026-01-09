"""Gavel - AI-Powered Vulnerability Report Verification Tool"""

__version__ = "0.1.0"
__author__ = "Gavel Team"
__description__ = "AI-powered vulnerability report verification tool"

from gavel.models import VerificationResult
from gavel.core import verify_report

__all__ = ["verify_report", "VerificationResult", "__version__"]
