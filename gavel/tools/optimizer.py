"""Token optimization utilities to reduce API costs"""

import re
from typing import Dict, List


def optimize_code_for_tokens(code_dict: Dict[str, str], verbose: bool = False) -> str:
    """
    Optimize code to reduce token count while preserving readability

    Optimizations applied:
    - Remove blank lines (multiple newlines -> single)
    - Compress comments (remove extra spaces while preserving meaning)
    - Skip import statements unless crucial
    - Focus on function implementations
    - Remove trailing whitespace

    Args:
        code_dict: Dictionary mapping file paths to code content
        verbose: Enable verbose logging

    Returns:
        Optimized code as single string with file markers
    """
    optimized_parts = []
    total_original_lines = 0
    total_optimized_lines = 0

    for file_path, content in code_dict.items():
        original_lines = len(content.split("\n"))
        total_original_lines += original_lines

        # Optimize the code
        optimized = _optimize_single_file(content)

        optimized_lines = len(optimized.split("\n"))
        total_optimized_lines += optimized_lines

        # Add file marker
        file_marker = f"\n{'='*60}\n"
        file_marker += f"FILE: {file_path}\n"
        file_marker += f"{'='*60}\n"

        optimized_parts.append(file_marker + optimized)

    if verbose:
        reduction = ((total_original_lines - total_optimized_lines) / total_original_lines * 100) if total_original_lines > 0 else 0
        print(f"Token optimization: {total_original_lines} -> {total_optimized_lines} lines ({reduction:.1f}% reduction)")

    return "\n".join(optimized_parts)


def _optimize_single_file(content: str) -> str:
    """Optimize a single file's content"""
    lines = content.split("\n")
    optimized_lines = []

    in_function = False
    import_section_done = False
    consecutive_blank_lines = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip empty lines after first blank
        if not stripped:
            consecutive_blank_lines += 1
            if consecutive_blank_lines <= 1:  # Keep only one blank line
                optimized_lines.append("")
            continue
        else:
            consecutive_blank_lines = 0

        # Detect if we're in a function
        if _is_function_definition(stripped):
            in_function = True
            import_section_done = True

        # Skip imports unless we're specifically looking at them
        if not import_section_done and _is_import_line(stripped):
            # Skip most imports, keep critical ones
            if _is_critical_import(stripped):
                optimized_lines.append(line.rstrip())
            continue

        # Mark end of import section
        if not _is_import_line(stripped) and not _is_comment_line(stripped):
            import_section_done = True

        # Optimize comments
        if _is_comment_line(stripped):
            optimized_comment = _optimize_comment(line)
            if optimized_comment:  # Only keep non-empty comments
                optimized_lines.append(optimized_comment)
            continue

        # Keep code lines (remove trailing whitespace)
        optimized_lines.append(line.rstrip())

    return "\n".join(optimized_lines)


def _is_function_definition(line: str) -> bool:
    """Check if line is a function definition"""
    patterns = [
        r"^\s*def\s+\w+",  # Python
        r"^\s*function\s+\w+",  # JavaScript
        r"^\s*(public|private|protected)?\s*\w+\s+\w+\s*\(",  # Java/C++
        r"^\s*fn\s+\w+",  # Rust
        r"^\s*func\s+\w+",  # Go
    ]

    for pattern in patterns:
        if re.match(pattern, line):
            return True

    return False


def _is_import_line(line: str) -> bool:
    """Check if line is an import statement"""
    patterns = [
        r"^\s*import\s+",
        r"^\s*from\s+.*\s+import\s+",
        r"^\s*require\s*\(",
        r"^\s*#include\s+",
        r"^\s*using\s+",
        r"^\s*use\s+",
    ]

    for pattern in patterns:
        if re.match(pattern, line):
            return True

    return False


def _is_critical_import(line: str) -> bool:
    """
    Determine if an import is critical (relates to security, crypto, etc.)
    """
    critical_keywords = [
        "crypto", "security", "auth", "password", "hash", "encrypt",
        "validate", "sanitize", "sql", "database", "exec", "eval"
    ]

    line_lower = line.lower()
    return any(keyword in line_lower for keyword in critical_keywords)


def _is_comment_line(line: str) -> bool:
    """Check if line is a comment"""
    stripped = line.strip()

    # Single-line comments
    if stripped.startswith("#"):  # Python, Shell
        return True
    if stripped.startswith("//"):  # C++, Java, JS
        return True
    if stripped.startswith("/*") or stripped.startswith("*"):  # Multi-line C-style
        return True

    return False


def _optimize_comment(line: str) -> str:
    """
    Optimize comment by removing extra spaces while preserving meaning

    Examples:
        "# This is a comment" -> "#This is a comment"
        "//  Check for   errors  " -> "//Check for errors"
    """
    # Get the comment marker and content
    stripped = line.strip()

    if stripped.startswith("#"):
        marker = "#"
        content = stripped[1:]
    elif stripped.startswith("//"):
        marker = "//"
        content = stripped[2:]
    elif stripped.startswith("/*"):
        return stripped  # Keep multi-line comments as-is for structure
    elif stripped.startswith("*"):
        return stripped  # Keep multi-line comments as-is
    else:
        return line

    # Compress multiple spaces to single space
    content = re.sub(r"\s+", " ", content.strip())

    # Skip very short or generic comments
    generic_comments = [
        "todo", "fixme", "hack", "note", "xxx",
        "end", "start", "begin"
    ]

    content_lower = content.lower()
    if len(content) < 10 or any(content_lower == gc for gc in generic_comments):
        return ""  # Skip generic/short comments

    return marker + content


def extract_functions_only(content: str, function_names: List[str]) -> str:
    """
    Extract only specific functions from code

    Args:
        content: Full file content
        function_names: List of function names to extract

    Returns:
        Code containing only specified functions
    """
    if not function_names:
        return content

    lines = content.split("\n")
    extracted = []
    current_function = None
    function_lines = []
    indent_level = 0

    for line in lines:
        stripped = line.strip()

        # Check if this is a function definition we want
        for func_name in function_names:
            if re.search(rf"\b{re.escape(func_name)}\s*\(", line):
                current_function = func_name
                function_lines = [line]
                indent_level = len(line) - len(line.lstrip())
                break

        # If we're collecting a function
        if current_function:
            if line != function_lines[0]:  # Don't add the def line twice
                function_lines.append(line)

            # Check if function has ended (dedent back to original level or less)
            line_indent = len(line) - len(line.lstrip()) if stripped else indent_level + 1

            if stripped and line_indent <= indent_level and len(function_lines) > 1:
                # Function ended
                extracted.append("\n".join(function_lines))
                extracted.append("")  # Blank line between functions
                current_function = None
                function_lines = []

    # Add last function if still collecting
    if function_lines:
        extracted.append("\n".join(function_lines))

    return "\n".join(extracted) if extracted else content


def estimate_tokens(text: str) -> int:
    """
    Rough estimate of token count
    Approximation: ~4 characters per token for code

    Args:
        text: Text to estimate

    Returns:
        Estimated token count
    """
    return len(text) // 4
