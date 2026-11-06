"""OpenRouter adapter for legacy, read-only model assessments."""

import os
import requests
from gavel.models import VerificationResult
from gavel.ai.prompts import build_verification_prompt, parse_verdict
from gavel.utils.security import sanitize_ai_output


def verify_with_openrouter(report: str, code_context: str, model: str = "opus-4.5",
                           generate_poc: bool = False, verbose: bool = False) -> VerificationResult:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY not found in environment")
    if not code_context.strip() or len(report) + len(code_context) > 180000:
        return VerificationResult("NEEDS_REVIEW", "Repository evidence is missing or exceeds the assessment budget.")
    model_map = {"opus-4.5": "anthropic/claude-opus-4.5", "sonnet-4.5": "anthropic/claude-sonnet-4.5"}
    model_id = os.getenv("GAVEL_OPENROUTER_MODEL") or model_map.get(model, model)
    system, user = build_verification_prompt(report, code_context, generate_poc)
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "X-Title": "Gavel"},
        json={"model": model_id, "messages": [
            {"role": "system", "content": system}, {"role": "user", "content": user},
        ], "max_tokens": 4096 if generate_poc else 2048, "temperature": 0.1},
        timeout=120, allow_redirects=False,
    )
    response.raise_for_status()
    payload = response.json()
    choices = payload.get("choices", [])
    if not choices or choices[0].get("finish_reason") != "stop":
        return VerificationResult("NEEDS_REVIEW", "The model response was incomplete; the claim remains unresolved.")
    text = choices[0].get("message", {}).get("content")
    verdict, reasoning, poc = parse_verdict(text)
    return VerificationResult(
        verdict=verdict, reasoning=sanitize_ai_output(reasoning, strict=True), confidence="low",
        poc=sanitize_ai_output(poc, strict=False) if poc and generate_poc else None,
    )
