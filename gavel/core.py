"""Core verification logic for Gavel"""

from typing import Optional, List, Dict, Any
from pathlib import Path
import os

from gavel.models import VerificationResult
from gavel.tools.grep import search_codebase
from gavel.tools.optimizer import optimize_code_for_tokens
from gavel.tools.github import clone_or_pull_repo
from gavel.utils.security import sanitize_input, detect_prompt_injection, sanitize_ai_output
from gavel.utils.parser import extract_vulnerability_details


def verify_report(
    report: str,
    codebase_path: str,
    model: str = "opus-4.5",
    generate_poc: bool = False,
    verbose: bool = False
) -> VerificationResult:
    """
    Verify a vulnerability report against a codebase

    Args:
        report: The vulnerability report content
        codebase_path: Path to codebase (local or GitHub URL)
        model: AI model to use ("opus-4.5" or "sonnet-4.5")
        generate_poc: Whether to generate a PoC
        verbose: Enable verbose logging

    Returns:
        VerificationResult with verdict and reasoning
    """
    # Sanitize inputs for security
    report = sanitize_input(report)

    # Detect prompt injection attempts
    is_suspicious, reason = detect_prompt_injection(report, aggressive=True)
    if is_suspicious:
        if verbose:
            print(f"[WARNING] Prompt injection detected: {reason}")
        # Return INVALID verdict for suspicious inputs instead of processing
        return VerificationResult(
            verdict="INVALID",
            reasoning=f"Report rejected due to potential security issue. This report contains patterns associated with prompt injection attacks and cannot be processed safely.",
            confidence="high"
        )

    # Determine if it's a GitHub URL or local path
    if codebase_path.startswith("http://") or codebase_path.startswith("https://"):
        if verbose:
            print(f"Cloning/pulling repository: {codebase_path}")
        local_path = clone_or_pull_repo(codebase_path, verbose=verbose)
    else:
        local_path = Path(codebase_path).resolve()
        if not local_path.exists():
            raise ValueError(f"Codebase path does not exist: {codebase_path}")

    # Extract key details from vulnerability report
    vuln_details = extract_vulnerability_details(report)

    if verbose:
        print(f"Extracted vulnerability details: {vuln_details.get('type', 'unknown')}")

    # Search codebase for relevant code
    relevant_code = search_codebase(
        codebase_path=str(local_path),
        vulnerability_details=vuln_details,
        verbose=verbose
    )

    if verbose:
        print(f"Found {len(relevant_code)} relevant code sections")

    # Optimize code to reduce tokens
    optimized_code = optimize_code_for_tokens(relevant_code, verbose=verbose)

    if verbose:
        print(f"Optimized code for token efficiency")

    # Choose AI provider based on model and available API keys
    use_anthropic = os.getenv("ANTHROPIC_API_KEY") and model in ["opus-4.5", "sonnet-4.5"]
    use_openrouter = os.getenv("OPENROUTER_API_KEY")

    # Import here to avoid circular dependency
    from gavel.ai.anthropic import verify_with_anthropic
    from gavel.ai.openrouter import verify_with_openrouter

    # Prefer Anthropic for direct API, fallback to OpenRouter
    if use_anthropic and not use_openrouter:
        if verbose:
            print("Using Anthropic API")
        result = verify_with_anthropic(
            report=report,
            code_context=optimized_code,
            model=model,
            generate_poc=generate_poc,
            verbose=verbose
        )
    elif use_openrouter:
        if verbose:
            print("Using OpenRouter API")
        result = verify_with_openrouter(
            report=report,
            code_context=optimized_code,
            model=model,
            generate_poc=generate_poc,
            verbose=verbose
        )
    else:
        raise ValueError(
            "No API key found. Please set ANTHROPIC_API_KEY or OPENROUTER_API_KEY in .env"
        )

    return result


def batch_verify_reports(
    report_files: List[str],
    codebase_path: str,
    model: str = "opus-4.5",
    generate_poc: bool = False,
    verbose: bool = False
) -> List[Dict[str, Any]]:
    """
    Verify multiple vulnerability reports in batch

    Args:
        report_files: List of paths to report files
        codebase_path: Path to codebase (local or GitHub URL)
        model: AI model to use
        generate_poc: Whether to generate PoCs
        verbose: Enable verbose logging

    Returns:
        List of verification results as dictionaries
    """
    results = []

    for report_file in report_files:
        if verbose:
            print(f"\nProcessing: {report_file}")

        try:
            # Read report
            with open(report_file, "r", encoding="utf-8") as f:
                report_content = f.read()

            # Verify
            result = verify_report(
                report=report_content,
                codebase_path=codebase_path,
                model=model,
                generate_poc=generate_poc,
                verbose=verbose
            )

            # Convert to dict
            result_dict = {
                "file": report_file,
                "verdict": result.verdict,
                "reasoning": result.reasoning,
                "confidence": result.confidence,
                "report_id": result.report_id,
                "timestamp": result.timestamp,
            }

            if result.poc:
                result_dict["poc"] = result.poc

            results.append(result_dict)

        except Exception as e:
            if verbose:
                print(f"Error processing {report_file}: {e}")

            results.append({
                "file": report_file,
                "verdict": "ERROR",
                "reasoning": f"Failed to process: {str(e)}",
                "confidence": "low",
                "report_id": str(uuid.uuid4())[:8],
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })

    return results
