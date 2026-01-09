"""OpenRouter API integration"""

import os
import requests
from typing import Optional
from gavel.models import VerificationResult
from gavel.ai.prompts import build_verification_prompt, parse_verdict
from gavel.utils.security import sanitize_ai_output


def verify_with_openrouter(
    report: str,
    code_context: str,
    model: str = "opus-4.5",
    generate_poc: bool = False,
    verbose: bool = False
) -> VerificationResult:
    """
    Verify vulnerability using OpenRouter API

    Args:
        report: Vulnerability report content
        code_context: Relevant code context
        model: Model to use ("opus-4.5" or "sonnet-4.5")
        generate_poc: Whether to generate a PoC
        verbose: Enable verbose logging

    Returns:
        VerificationResult
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY not found in environment")

    # Map short model names to OpenRouter model IDs
    model_map = {
        "opus-4.5": "anthropic/claude-opus-4.5:beta",
        "sonnet-4.5": "anthropic/claude-sonnet-4.5:beta",
    }

    model_id = model_map.get(model, "anthropic/claude-opus-4.5:beta")

    if verbose:
        print(f"Using OpenRouter model: {model_id}")

    # Build prompt
    system_prompt, user_prompt = build_verification_prompt(
        report=report,
        code_context=code_context,
        generate_poc=generate_poc
    )

    # Combine system and user prompts for OpenRouter
    full_prompt = f"{system_prompt}\n\n{user_prompt}"

    # Enforce maximum prompt size to prevent 400 errors
    MAX_PROMPT_SIZE = 200000  # ~50k tokens (safe limit for most models)
    if len(full_prompt) > MAX_PROMPT_SIZE:
        if verbose:
            print(f"Warning: Prompt too large ({len(full_prompt)} chars), truncating to {MAX_PROMPT_SIZE} chars")

        # Truncate code context while preserving system prompt and report
        available_space = MAX_PROMPT_SIZE - len(system_prompt) - len(report) - 1000  # Buffer
        if available_space > 0:
            truncated_context = code_context[:available_space] + "\n\n... (code context truncated due to size limits)"
            _, user_prompt = build_verification_prompt(
                report=report,
                code_context=truncated_context,
                generate_poc=generate_poc
            )
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
        else:
            # If even that's too large, just use the report without code context
            _, user_prompt = build_verification_prompt(
                report=report,
                code_context="",
                generate_poc=generate_poc
            )
            full_prompt = f"{system_prompt}\n\n{user_prompt}"

    if verbose:
        print(f"Sending request to OpenRouter API...")
        print(f"Prompt length: {len(full_prompt)} characters")

    # Make API call
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/yourusername/gavel",  # Update with actual repo
        "X-Title": "Gavel",
    }

    payload = {
        "model": model_id,
        "messages": [
            {
                "role": "user",
                "content": full_prompt
            }
        ],
        "max_tokens": 2048 if not generate_poc else 4096,
        "temperature": 0.1,
    }

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=120
        )

        response.raise_for_status()
        result = response.json()

        # Extract response
        if "choices" not in result or len(result["choices"]) == 0:
            raise ValueError(f"Invalid response from OpenRouter: {result}")

        response_text = result["choices"][0]["message"]["content"]

        if verbose:
            print(f"Received response from OpenRouter API")
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

    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"Error calling OpenRouter API: {e}")
        raise
    except Exception as e:
        if verbose:
            print(f"Error processing OpenRouter response: {e}")
        raise
