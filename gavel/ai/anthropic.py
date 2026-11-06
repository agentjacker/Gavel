"""Anthropic adapter for legacy, read-only model assessments."""

import os
from gavel.models import VerificationResult
from gavel.ai.prompts import build_verification_prompt, parse_verdict
from gavel.utils.security import sanitize_ai_output


def verify_with_anthropic(report: str, code_context: str, model: str = "opus-4.5",
                          generate_poc: bool = False, verbose: bool = False) -> VerificationResult:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment")
    if not code_context.strip() or len(report) + len(code_context) > 180000:
        return VerificationResult("NEEDS_REVIEW", "Repository evidence is missing or exceeds the assessment budget.")
    from anthropic import Anthropic
    model_map = {"opus-4.5": "claude-opus-4-5-20251101", "sonnet-4.5": "claude-sonnet-4-5-20250929"}
    model_id = os.getenv("GAVEL_ANTHROPIC_MODEL") or model_map.get(model, model)
    system, user = build_verification_prompt(report, code_context, generate_poc)
    response = Anthropic(api_key=api_key, timeout=120).messages.create(
        model=model_id, max_tokens=4096 if generate_poc else 2048, temperature=0.1,
        system=system, messages=[{"role": "user", "content": user}],
    )
    if response.stop_reason != "end_turn":
        return VerificationResult("NEEDS_REVIEW", "The model response was incomplete; the claim remains unresolved.")
    text = "\n".join(block.text for block in response.content if block.type == "text")
    verdict, reasoning, poc = parse_verdict(text)
    return VerificationResult(
        verdict=verdict, reasoning=sanitize_ai_output(reasoning, strict=True), confidence="low",
        poc=sanitize_ai_output(poc, strict=False) if poc and generate_poc else None,
    )


def verify_with_anthropic_batch(reports_and_contexts: list, model: str = "opus-4.5",
                                generate_poc: bool = False, verbose: bool = False) -> list:
    """Compatibility helper: sequential requests, with no unimplemented batch claim."""
    return [verify_with_anthropic(report, context, model, generate_poc, verbose)
            for report, context in reports_and_contexts]
