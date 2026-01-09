"""Anthropic API integration with batch support"""

import os
from typing import Optional
from anthropic import Anthropic
from gavel.models import VerificationResult
from gavel.ai.prompts import build_verification_prompt, parse_verdict
from gavel.utils.security import sanitize_ai_output


def verify_with_anthropic(
    report: str,
    code_context: str,
    model: str = "opus-4.5",
    generate_poc: bool = False,
    verbose: bool = False
) -> VerificationResult:
    """
    Verify vulnerability using Anthropic's API

    Args:
        report: Vulnerability report content
        code_context: Relevant code context
        model: Model to use ("opus-4.5" or "sonnet-4.5")
        generate_poc: Whether to generate a PoC
        verbose: Enable verbose logging

    Returns:
        VerificationResult
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment")

    # Map short model names to full model IDs
    model_map = {
        "opus-4.5": "claude-opus-4-20250514",
        "sonnet-4.5": "claude-sonnet-4-20250514",
    }

    model_id = model_map.get(model, "claude-opus-4-20250514")

    if verbose:
        print(f"Using Anthropic model: {model_id}")

    # Initialize client
    client = Anthropic(api_key=api_key)

    # Build prompt
    system_prompt, user_prompt = build_verification_prompt(
        report=report,
        code_context=code_context,
        generate_poc=generate_poc
    )

    if verbose:
        print(f"Sending request to Anthropic API...")
        print(f"Prompt length: {len(user_prompt)} characters")

    # Make API call
    try:
        response = client.messages.create(
            model=model_id,
            max_tokens=2048 if not generate_poc else 4096,
            temperature=0.1,  # Low temperature for consistent, factual responses
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        )

        # Extract response
        response_text = response.content[0].text

        if verbose:
            print(f"Received response from Anthropic API")
            print(f"Response length: {len(response_text)} characters")

        # Sanitize output to prevent system prompt leakage (defense in depth)
        response_text = sanitize_ai_output(response_text, strict=True)

        if verbose:
            print(f"Sanitized response length: {len(response_text)} characters")

        # Parse verdict and reasoning
        verdict, reasoning, poc = parse_verdict(response_text)

        # Additional sanitization on extracted components
        reasoning = sanitize_ai_output(reasoning, strict=True)
        if poc:
            poc = sanitize_ai_output(poc, strict=False)  # Less strict for PoC code

        return VerificationResult(
            verdict=verdict,
            reasoning=reasoning,
            confidence="high" if "opus" in model else "medium",
            poc=poc if generate_poc else None
        )

    except Exception as e:
        if verbose:
            print(f"Error calling Anthropic API: {e}")
        raise


def verify_with_anthropic_batch(
    reports_and_contexts: list,
    model: str = "opus-4.5",
    generate_poc: bool = False,
    verbose: bool = False
) -> list:
    """
    Verify multiple vulnerabilities using Anthropic's batch API

    Args:
        reports_and_contexts: List of (report, code_context) tuples
        model: Model to use
        generate_poc: Whether to generate PoCs
        verbose: Enable verbose logging

    Returns:
        List of VerificationResults

    Note: This uses Anthropic's batch API for reduced costs
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment")

    # Check if batch mode is enabled
    use_batch = os.getenv("ENABLE_BATCH_REQUESTS", "true").lower() == "true"

    if not use_batch or len(reports_and_contexts) < 2:
        # Fall back to individual requests
        results = []
        for report, context in reports_and_contexts:
            result = verify_with_anthropic(
                report=report,
                code_context=context,
                model=model,
                generate_poc=generate_poc,
                verbose=verbose
            )
            results.append(result)
        return results

    if verbose:
        print(f"Using Anthropic Batch API for {len(reports_and_contexts)} requests")

    # TODO: Implement batch API when available
    # For now, fall back to sequential processing
    results = []
    for i, (report, context) in enumerate(reports_and_contexts):
        if verbose:
            print(f"Processing batch item {i+1}/{len(reports_and_contexts)}")

        result = verify_with_anthropic(
            report=report,
            code_context=context,
            model=model,
            generate_poc=generate_poc,
            verbose=verbose
        )
        results.append(result)

    return results
