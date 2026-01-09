"""Security utilities for input sanitization and prompt injection prevention"""

import re
from typing import Optional, Tuple


# Enhanced patterns for prompt injection detection
SUSPICIOUS_PATTERNS = [
    # Direct instruction overrides
    r"ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|rules?|commands?)",
    r"disregard\s+(previous|all|above|prior)\s+(instructions?|prompts?|rules?)",
    r"forget\s+(previous|all|above|your)\s+(instructions?|prompts?|rules?|training)",

    # Role manipulation
    r"you\s+are\s+now\s+(a|an|\w+)",
    r"act\s+as\s+(if\s+)?(you\s+are|a|an)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"new\s+(instructions?|prompt|role|persona|character)",
    r"your\s+new\s+(role|task|job|purpose)\s+is",

    # System/developer impersonation
    r"system\s*:\s*",
    r"developer\s+(note|message|instruction)",
    r"admin\s+(override|command|access)",
    r"as\s+the\s+(system|administrator|developer)",

    # Special tokens and delimiters
    r"<\|.*?\|>",  # Special tokens
    r"\[INST\]",  # Instruction markers
    r"\[/INST\]",
    r"</s>",  # End of sequence tokens
    r"<s>",   # Start of sequence
    r"###\s*(system|instruction|human|assistant)",

    # Output manipulation
    r"output\s+(only|just)\s+[\"']?(valid|invalid)[\"']?",
    r"always\s+(respond|say|output|return)\s+with",
    r"your\s+verdict\s+(must|should)\s+be",
    r"conclude\s+that\s+(this|the)\s+is\s+(valid|invalid)",

    # Information extraction attempts
    r"what\s+(is|are)\s+your\s+(instructions?|prompts?|rules?|guidelines?)",
    r"show\s+(me\s+)?(your|the)\s+(system|instructions?|prompts?)",
    r"reveal\s+your\s+(instructions?|prompts?|system)",
    r"repeat\s+(your|the)\s+(instructions?|prompts?|system)",

    # Jailbreak attempts
    r"do\s+anything\s+now",
    r"DAN\s+mode",
    r"developer\s+mode",
    r"god\s+mode",

    # Encoding/obfuscation indicators
    r"base64\s+decode",
    r"rot13\s+decode",
    r"\\x[0-9a-f]{2}",  # Hex encoding
    r"\\u[0-9a-f]{4}",  # Unicode escapes
]

# Patterns indicating attempt to leak system prompts in output
SYSTEM_LEAK_PATTERNS = [
    r"SYSTEM\s*PROMPT\s*:",
    r"YOUR\s+INSTRUCTIONS\s+ARE\s*:",
    r"AS\s+GAVEL,\s+YOUR\s+ROLE",
    r"YOU\s+ARE\s+GAVEL,\s+AN\s+EXPERT",
    r"CRITICAL\s+RULES\s*:",
    r"OUTPUT\s+FORMAT\s*:",
    r"REMEMBER\s*:",
]


def sanitize_input(text: str, max_length: int = 500000) -> str:
    """
    Sanitize user input to prevent prompt injection and limit size

    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized text
    """
    if not text:
        return ""

    # Limit length to prevent excessive token usage
    if len(text) > max_length:
        text = text[:max_length]

    # Remove null bytes
    text = text.replace("\x00", "")

    # Normalize whitespace but preserve structure
    # Don't completely remove newlines as they're important for code structure
    text = re.sub(r"\n{4,}", "\n\n\n", text)  # Limit consecutive newlines

    # Remove potential special tokens that might confuse the model
    special_tokens = [
        r"<\|endoftext\|>",
        r"<\|startoftext\|>",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"<\|system\|>",
        r"<\|user\|>",
        r"<\|assistant\|>",
    ]

    for token_pattern in special_tokens:
        text = re.sub(token_pattern, "", text, flags=re.IGNORECASE)

    # Remove hidden Unicode characters that could be used for injection
    # Zero-width characters and other invisible Unicode
    invisible_chars = [
        "\u200B",  # Zero-width space
        "\u200C",  # Zero-width non-joiner
        "\u200D",  # Zero-width joiner
        "\uFEFF",  # Zero-width no-break space
        "\u180E",  # Mongolian vowel separator
    ]

    for char in invisible_chars:
        text = text.replace(char, "")

    return text


def detect_prompt_injection(text: str, aggressive: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Detect potential prompt injection attempts with enhanced detection

    Args:
        text: Text to check
        aggressive: If True, use stricter detection

    Returns:
        Tuple of (is_suspicious, reason)
    """
    text_lower = text.lower()

    # Check all suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            return True, f"Potential prompt injection detected: '{match.group(0)}'"

    # Additional heuristic checks
    if aggressive:
        # Check for excessive capitalization (shouting/emphasis for injection)
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if caps_ratio > 0.3 and len(text) > 50:
            # High caps ratio might indicate trying to emphasize malicious instructions
            suspicious_caps_words = ["VALID", "INVALID", "IGNORE", "ALWAYS", "MUST", "VERDICT"]
            for word in suspicious_caps_words:
                if text.count(word) > 2:
                    return True, f"Suspicious emphasis pattern detected with word: {word}"

        # Check for repeated instructions (trying to override)
        # Note: "system" is common in legitimate security reports, so check context
        instruction_words = ["ignore", "disregard", "forget", "new instructions", "admin"]
        for word in instruction_words:
            if text_lower.count(word) > 3:
                return True, f"Excessive repetition of instruction keyword: {word}"

        # Special check for "system" - only flag if used in suspicious contexts
        system_count = text_lower.count("system")
        if system_count > 10:
            # Check if it's used in prompt injection context vs legitimate security context
            suspicious_system_usage = [
                "system:",
                "system prompt",
                "system instruction",
                "system override",
                "system message",
                "as the system",
                "new system"
            ]
            suspicious_count = sum(text_lower.count(phrase) for phrase in suspicious_system_usage)
            if suspicious_count > 2:
                return True, f"Suspicious usage of 'system' keyword in injection context"

    return False, None


def sanitize_ai_output(output: str, strict: bool = True) -> str:
    """
    Sanitize AI output to prevent leakage of system prompts and internal reasoning

    This implements defense-in-depth by filtering the AI's response to ensure
    it doesn't leak system prompts, even if prompt injection succeeded.

    Args:
        output: AI model output to sanitize
        strict: If True, aggressively filter potential leaks

    Returns:
        Sanitized output
    """
    if not output:
        return ""

    # Check for system prompt leakage patterns
    for pattern in SYSTEM_LEAK_PATTERNS:
        if re.search(pattern, output, re.IGNORECASE):
            # Found potential leak - remove or redact
            output = re.sub(pattern, "[REDACTED]", output, flags=re.IGNORECASE)

    if strict:
        # Remove any lines that look like they're repeating system instructions
        lines = output.split("\n")
        filtered_lines = []

        for line in lines:
            line_lower = line.lower().strip()

            # Skip lines that look like system prompt fragments
            skip_line = False
            suspicious_fragments = [
                "you are gavel",
                "your role is",
                "critical rules:",
                "output format:",
                "be skeptical of",
                "remember:",
                "you must respond with only",
            ]

            for fragment in suspicious_fragments:
                if fragment in line_lower and len(line) < 200:
                    skip_line = True
                    break

            if not skip_line:
                filtered_lines.append(line)

        output = "\n".join(filtered_lines)

    # Ensure output doesn't contain special tokens
    special_tokens = [
        r"<\|endoftext\|>",
        r"<\|startoftext\|>",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
    ]

    for token_pattern in special_tokens:
        output = re.sub(token_pattern, "", output, flags=re.IGNORECASE)

    return output.strip()


def sanitize_path(path: str) -> str:
    """
    Sanitize file path to prevent directory traversal

    Args:
        path: File path to sanitize

    Returns:
        Sanitized path

    Raises:
        ValueError: If path contains suspicious patterns
    """
    # Remove null bytes
    path = path.replace("\x00", "")

    # Check for directory traversal attempts
    if ".." in path:
        raise ValueError("Path traversal detected")

    # Remove leading/trailing whitespace
    path = path.strip()

    # Check for absolute paths to sensitive directories
    sensitive_dirs = ["/etc", "/sys", "/proc", "/root", "/boot"]
    for sensitive in sensitive_dirs:
        if path.startswith(sensitive):
            raise ValueError(f"Access to {sensitive} not allowed")

    return path


def truncate_with_ellipsis(text: str, max_length: int) -> str:
    """
    Truncate text to max_length with ellipsis

    Args:
        text: Text to truncate
        max_length: Maximum length

    Returns:
        Truncated text with ellipsis if needed
    """
    if len(text) <= max_length:
        return text

    return text[:max_length - 3] + "..."


def sanitize_for_web_display(text: str) -> str:
    """
    Sanitize text for safe web display (basic XSS prevention)

    Args:
        text: Text to sanitize

    Returns:
        Sanitized text
    """
    # Basic HTML entity encoding
    replacements = {
        "<": "&lt;",
        ">": "&gt;",
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#x27;",
    }

    for char, entity in replacements.items():
        text = text.replace(char, entity)

    return text
