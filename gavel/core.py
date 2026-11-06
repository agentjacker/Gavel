"""Legacy stateless verification. The company-context service is a separate path."""

from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime, timezone
import os
import shutil
import uuid

from gavel.models import VerificationResult
from gavel.tools.grep import search_codebase
from gavel.tools.github import clone_or_pull_repo
from gavel.utils.security import sanitize_input, detect_prompt_injection
from gavel.utils.parser import extract_vulnerability_details


def _review(reason: str) -> VerificationResult:
    return VerificationResult(verdict="NEEDS_REVIEW", reasoning=reason, confidence="low")


def verify_report(report: str, codebase_path: str, model: str = "opus-4.5",
                  generate_poc: bool = False, verbose: bool = False) -> VerificationResult:
    """Assess report data without executing it; absence of evidence stays unresolved."""
    if not isinstance(report, str) or not report.strip():
        return _review("A nonempty vulnerability report is required for assessment.")
    if len(report) > 100000:
        return _review("The report exceeds the legacy assessment budget and needs review without silent truncation.")
    suspicious, _ = detect_prompt_injection(report, aggressive=True)
    if suspicious:
        # This detector is an uncalibrated review signal, never proof the claim is
        # invalid. Legitimate prompt-injection reports remain reviewable findings.
        return _review("The report contains instruction-like content and needs review. This does not disprove its security claim.")
    report = sanitize_input(report, max_length=100000)
    downloaded = False
    local_path = None
    try:
        if "://" in codebase_path or codebase_path.startswith("git@"):
            local_path = clone_or_pull_repo(codebase_path, verbose=verbose)
            downloaded = True
        else:
            local_path = Path(codebase_path).resolve(strict=True)
            if not local_path.is_dir():
                raise ValueError("Codebase path must be a directory")
        details = extract_vulnerability_details(report)
        evidence = search_codebase(str(local_path), details, verbose=verbose)
        if not evidence:
            return _review("No relevant repository evidence was retrieved. Missing context cannot establish that the claim is invalid.")
        # Preserve source structure and line numbers for an auditable assessment.
        code_context = "\n\n".join(
            "FILE: " + str(Path(name).relative_to(local_path)) + "\n" +
            "\n".join(f"{index}: {line}" for index, line in enumerate(content.splitlines(), 1))
            for name, content in evidence.items()
        )
        if len(code_context) + len(report) > 180000:
            return _review("Relevant evidence exceeds the legacy context budget; review is required rather than omitting controls.")
        if os.getenv("OPENROUTER_API_KEY"):
            from gavel.ai.openrouter import verify_with_openrouter
            return verify_with_openrouter(report, code_context, model, generate_poc, verbose)
        if os.getenv("ANTHROPIC_API_KEY"):
            from gavel.ai.anthropic import verify_with_anthropic
            return verify_with_anthropic(report, code_context, model, generate_poc, verbose)
        raise ValueError("Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY to use legacy AI verification")
    finally:
        if downloaded and local_path is not None:
            shutil.rmtree(local_path, ignore_errors=True)


def batch_verify_reports(report_files: List[str], codebase_path: str, model: str = "opus-4.5",
                         generate_poc: bool = False, verbose: bool = False) -> List[Dict[str, Any]]:
    results = []
    for report_file in report_files:
        try:
            with open(report_file, "r", encoding="utf-8") as stream:
                content = stream.read(100001)
            result = verify_report(content, codebase_path, model, generate_poc, verbose)
            results.append({
                "file": report_file, "verdict": result.verdict, "reasoning": result.reasoning,
                "confidence": result.confidence, "report_id": result.report_id,
                "timestamp": result.timestamp, **({"poc": result.poc} if result.poc else {}),
            })
        except Exception:
            results.append({
                "file": report_file, "verdict": "ERROR", "reasoning": "Assessment failed; the security claim remains unresolved.",
                "confidence": "low", "report_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            })
    return results
