"""Efficient code grepping and search utilities"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
import subprocess


# File extensions to search (code files only)
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cpp", ".c", ".h", ".hpp",
    ".go", ".rs", ".php", ".rb", ".swift", ".kt", ".scala", ".sol", ".vy",
    ".sh", ".bash"
}

# Files to always ignore (lock files, configs, etc.)
IGNORE_FILES = {
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "Cargo.lock",
    "Gemfile.lock", "poetry.lock", "composer.lock"
}

# Directories to ignore
IGNORE_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".next", "out", "target", "vendor", ".idea",
    ".vscode", "coverage", ".pytest_cache", ".mypy_cache"
}


def search_codebase(
    codebase_path: str,
    vulnerability_details: Dict,
    verbose: bool = False
) -> Dict[str, str]:
    """
    Search codebase for code relevant to vulnerability report

    Args:
        codebase_path: Path to codebase root
        vulnerability_details: Extracted vulnerability details
        verbose: Enable verbose logging

    Returns:
        Dictionary mapping file paths to relevant code sections
    """
    relevant_code = {}

    # Build search terms from vulnerability details
    search_terms = _build_search_terms(vulnerability_details)

    if verbose:
        print(f"Search terms: {search_terms[:5]}...")  # Show first 5

    # First, try to find explicitly mentioned files
    mentioned_files = vulnerability_details.get("affected_files", [])
    for file_name in mentioned_files:
        file_path = _find_file_in_codebase(codebase_path, file_name)
        if file_path:
            content = _read_file_safe(file_path)
            if content:
                relevant_code[file_path] = content
                if verbose:
                    print(f"Found mentioned file: {file_path}")

    # Search for functions mentioned in report
    mentioned_functions = vulnerability_details.get("affected_functions", [])
    for function_name in mentioned_functions:
        matches = _search_for_function(codebase_path, function_name)
        for file_path, code in matches.items():
            if file_path not in relevant_code:
                relevant_code[file_path] = code
                if verbose:
                    print(f"Found function '{function_name}' in: {file_path}")

    # If we haven't found enough context, do keyword search
    if len(relevant_code) < 3:
        keyword_matches = _search_by_keywords(
            codebase_path,
            search_terms,
            max_files=10
        )
        for file_path, code in keyword_matches.items():
            if file_path not in relevant_code:
                relevant_code[file_path] = code
                if verbose:
                    print(f"Found via keyword search: {file_path}")

    return relevant_code


def _build_search_terms(vulnerability_details: Dict) -> List[str]:
    """Build list of search terms from vulnerability details"""
    terms = []

    # Add function names
    terms.extend(vulnerability_details.get("affected_functions", []))

    # Add keywords
    terms.extend(vulnerability_details.get("keywords", []))

    # Add vulnerability type keywords
    vuln_type = vulnerability_details.get("type", "")
    if vuln_type:
        # Add related terms based on vuln type
        type_keywords = {
            "SQL Injection": ["query", "execute", "sql", "database", "select"],
            "XSS": ["innerHTML", "outerHTML", "document.write", "eval"],
            "Command Injection": ["exec", "system", "shell", "subprocess", "spawn"],
            "Path Traversal": ["path", "file", "read", "open", "readFile"],
            "RCE": ["eval", "exec", "system", "shell"],
        }

        for key, keywords in type_keywords.items():
            if key.lower() in vuln_type.lower():
                terms.extend(keywords)
                break

    # Remove duplicates and filter short terms
    terms = list(set([t for t in terms if len(t) > 2]))

    return terms


def _find_file_in_codebase(codebase_path: str, file_name: str) -> Optional[str]:
    """Find a file by name in the codebase"""
    codebase = Path(codebase_path)

    # Try exact match first
    exact_path = codebase / file_name
    if exact_path.exists() and exact_path.is_file():
        return str(exact_path)

    # Search recursively
    for root, dirs, files in os.walk(codebase):
        # Remove ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            if file == Path(file_name).name:
                return os.path.join(root, file)

    return None


def _search_for_function(codebase_path: str, function_name: str) -> Dict[str, str]:
    """Search for function definition in codebase"""
    matches = {}
    codebase = Path(codebase_path)

    # Function definition patterns for different languages
    patterns = [
        rf"def\s+{re.escape(function_name)}\s*\(",  # Python
        rf"function\s+{re.escape(function_name)}\s*\(",  # JavaScript
        rf"{re.escape(function_name)}\s*:\s*function",  # JS object method
        rf"(public|private|protected)?\s*\w*\s+{re.escape(function_name)}\s*\(",  # Java/C++/C#
        rf"fn\s+{re.escape(function_name)}\s*\(",  # Rust
        rf"func\s+{re.escape(function_name)}\s*\(",  # Go
    ]

    for root, dirs, files in os.walk(codebase):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            if Path(file).suffix not in CODE_EXTENSIONS:
                continue

            file_path = os.path.join(root, file)
            content = _read_file_safe(file_path)

            if not content:
                continue

            for pattern in patterns:
                if re.search(pattern, content, re.MULTILINE):
                    matches[file_path] = content
                    break

            if len(matches) >= 5:  # Limit to prevent too many matches
                break

    return matches


def _search_by_keywords(
    codebase_path: str,
    keywords: List[str],
    max_files: int = 5  # Reduced from 10
) -> Dict[str, str]:
    """Search codebase by keywords using grep-like functionality"""
    matches = {}
    codebase = Path(codebase_path)

    # Try using ripgrep if available (much faster)
    if _has_ripgrep():
        return _ripgrep_search(codebase_path, keywords, max_files)

    # Fallback to Python-based search
    for root, dirs, files in os.walk(codebase):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            # Skip non-code files and ignored files
            if Path(file).suffix not in CODE_EXTENSIONS:
                continue
            if file in IGNORE_FILES:
                continue

            file_path = os.path.join(root, file)
            content = _read_file_safe(file_path)

            if not content:
                continue

            # Check if any keyword appears in the file
            content_lower = content.lower()
            for keyword in keywords:
                if keyword.lower() in content_lower:
                    matches[file_path] = content
                    break

            if len(matches) >= max_files:
                return matches

    return matches


def _has_ripgrep() -> bool:
    """Check if ripgrep is available"""
    try:
        subprocess.run(
            ["rg", "--version"],
            capture_output=True,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _ripgrep_search(
    codebase_path: str,
    keywords: List[str],
    max_files: int = 5  # Reduced from 10
) -> Dict[str, str]:
    """Use ripgrep for fast searching"""
    matches = {}

    # Build file type filters to exclude lock files and configs
    exclude_patterns = [
        "*lock*", "*.lock", "*.log", "package.json", "*.toml",
        "*.json", "*.yaml", "*.yml", "*.md"
    ]

    for keyword in keywords[:3]:  # Limit keywords to prevent too many results
        try:
            rg_args = [
                "rg",
                "-l",  # Files with matches only
                "--max-count", "1",
                "-i",  # Case insensitive
            ]

            # Add exclude patterns
            for pattern in exclude_patterns:
                rg_args.extend(["-g", f"!{pattern}"])

            rg_args.extend([keyword, codebase_path])

            result = subprocess.run(
                rg_args,
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                file_paths = result.stdout.strip().split("\n")
                for file_path in file_paths[:max_files]:
                    if file_path and file_path not in matches:
                        content = _read_file_safe(file_path)
                        if content:
                            matches[file_path] = content

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            continue

        if len(matches) >= max_files:
            break

    return matches


def _read_file_safe(file_path: str, max_size_mb: int = 1, max_lines: int = 500) -> Optional[str]:
    """
    Safely read file with size and line limits

    Args:
        file_path: Path to file
        max_size_mb: Maximum file size in MB
        max_lines: Maximum number of lines to read

    Returns:
        File content or None if too large/unreadable
    """
    try:
        # Skip ignored files
        file_name = os.path.basename(file_path)
        if file_name in IGNORE_FILES:
            return None

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > max_size_mb * 1024 * 1024:
            return None

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            # Read only up to max_lines
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    lines.append(f"\n... (file truncated after {max_lines} lines)")
                    break
                lines.append(line.rstrip())
            return "\n".join(lines)

    except Exception:
        return None
