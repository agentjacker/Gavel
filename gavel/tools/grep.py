"""Bounded, read-only code retrieval confined to a selected repository.

Reports supply search terms, never paths to open outside this root or commands.
Every read walks directory descriptors with O_NOFOLLOW and rejects special files.
"""

import os
import re
import stat
from pathlib import Path
from typing import Dict, List, Optional

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cpp", ".c", ".h", ".hpp",
    ".go", ".rs", ".php", ".rb", ".swift", ".kt", ".scala", ".sol", ".vy",
    ".sh", ".bash", ".json", ".yaml", ".yml", ".toml", ".tf", ".hcl",
}
IGNORE_FILES = {
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "Cargo.lock",
    "Gemfile.lock", "poetry.lock", "composer.lock",
}
IGNORE_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".next", "out", "target", "vendor", ".idea",
    ".vscode", "coverage", ".pytest_cache", ".mypy_cache",
}
MAX_SCAN_FILES = 5000
MAX_RESULTS = 12


def _root(codebase_path: str) -> Path:
    selected = Path(codebase_path)
    if selected.is_symlink():
        raise ValueError("Codebase root cannot be a symbolic link")
    root = selected.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Codebase must be a directory")
    return root


def _eligible(path: Path) -> bool:
    return (
        path.name not in IGNORE_FILES
        and not path.name.startswith(".env")
        and (path.suffix.lower() in CODE_EXTENSIONS or path.name in {"Dockerfile", "Makefile"})
    )


def _files(codebase_path: str):
    """Enumerate bounded candidate names; the reader rechecks every component."""
    root = _root(codebase_path)
    count = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        count += 1
        if count > MAX_SCAN_FILES:
            return
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS and not Path(current, d).is_symlink())
        for name in sorted(files):
            count += 1
            if count > MAX_SCAN_FILES:
                return
            candidate = Path(current, name)
            if _eligible(candidate) and not candidate.is_symlink():
                yield candidate


def search_codebase(codebase_path: str, vulnerability_details: Dict, verbose: bool = False) -> Dict[str, str]:
    root = str(_root(codebase_path))
    relevant = {}
    for name in vulnerability_details.get("affected_files", [])[:20]:
        candidate = _find_file_in_codebase(root, name)
        if candidate:
            content = _read_file_safe(candidate, codebase_path=root)
            if content:
                relevant[candidate] = content
        if len(relevant) >= MAX_RESULTS:
            return relevant
    for name in vulnerability_details.get("affected_functions", [])[:10]:
        for candidate, content in _search_for_function(root, name).items():
            relevant.setdefault(candidate, content)
            if len(relevant) >= MAX_RESULTS:
                return relevant
    if len(relevant) < 3:
        for candidate, content in _search_by_keywords(root, _build_search_terms(vulnerability_details), 5).items():
            relevant.setdefault(candidate, content)
    return relevant


def _build_search_terms(vulnerability_details: Dict) -> List[str]:
    terms = list(vulnerability_details.get("affected_functions", []))
    terms += vulnerability_details.get("keywords", [])
    kind = (vulnerability_details.get("type") or "").lower()
    for name, words in {
        "sql injection": ["query", "execute", "sql"],
        "xss": ["innerHTML", "document.write"],
        "command injection": ["exec", "system", "subprocess"],
        "path traversal": ["path", "readFile", "open"],
        "rce": ["eval", "exec", "system"],
    }.items():
        if name in kind:
            terms.extend(words)
            break
    return list(dict.fromkeys(t for t in terms if isinstance(t, str) and 2 < len(t) <= 128))[:20]


def _find_file_in_codebase(codebase_path: str, file_name: str) -> Optional[str]:
    if not isinstance(file_name, str) or "\x00" in file_name or "\\" in file_name:
        return None
    relative = Path(file_name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        return None
    if any(part in IGNORE_DIRS for part in relative.parts) or not _eligible(relative):
        return None
    root = _root(codebase_path)
    candidate = root / relative
    # The safe reader, rather than exists(), is the authority for a readable file.
    if _read_file_safe(str(candidate), codebase_path=str(root)) is not None:
        return str(candidate)
    # Qualified paths are exact. A missing path cannot silently bind a same-named file.
    if len(relative.parts) != 1:
        return None
    for candidate in _files(str(root)):
        if candidate.name == relative.name and _read_file_safe(str(candidate), codebase_path=str(root)) is not None:
            return str(candidate)
    return None


def _search_for_function(codebase_path: str, function_name: str) -> Dict[str, str]:
    if not isinstance(function_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", function_name):
        return {}
    name = re.escape(function_name)
    patterns = [rf"\b(?:def|function|fn|func)\s+{name}\s*\(", rf"\b{name}\s*:\s*function", rf"\b\w+\s+{name}\s*\("]
    found = {}
    for candidate in _files(codebase_path):
        content = _read_file_safe(str(candidate), codebase_path=codebase_path)
        if content and any(re.search(pattern, content) for pattern in patterns):
            found[str(candidate)] = content
            if len(found) >= 5:
                break
    return found


def _search_by_keywords(codebase_path: str, keywords: List[str], max_files: int = 5) -> Dict[str, str]:
    # Literal comparisons avoid regular expression or external-command option injection.
    terms = [term.lower() for term in keywords[:20] if isinstance(term, str) and 0 < len(term) <= 128]
    if not terms:
        return {}
    found = {}
    for candidate in _files(codebase_path):
        content = _read_file_safe(str(candidate), codebase_path=codebase_path)
        if content and any(term in content.lower() for term in terms):
            found[str(candidate)] = content
            if len(found) >= min(max_files, MAX_RESULTS):
                break
    return found


def _ripgrep_search(codebase_path: str, keywords: List[str], max_files: int = 5) -> Dict[str, str]:
    """Compatibility alias; safe bounded reads also apply when ripgrep is installed."""
    return _search_by_keywords(codebase_path, keywords, max_files)


def _has_ripgrep() -> bool:
    return False


def _read_file_safe(file_path: str, max_size_mb: int = 1, max_lines: int = 500,
                    codebase_path: Optional[str] = None) -> Optional[str]:
    """Read only regular files without following symlinks, including during races.

    The optional root preserves the old helper signature; all repository searches
    supply the selected root. O_NONBLOCK prevents an attacker-swapped FIFO hanging.
    """
    descriptors = []
    try:
        root = _root(codebase_path or str(Path(file_path).absolute().parent))
        candidate = Path(os.path.abspath(file_path))
        relative = candidate.relative_to(root)
        if not relative.parts or any(part in IGNORE_DIRS for part in relative.parts) or not _eligible(candidate):
            return None
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(str(root), flags)
        descriptors.append(directory)
        for component in relative.parts[:-1]:
            directory = os.open(component, flags, dir_fd=directory)
            descriptors.append(directory)
        descriptor = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        maximum = max_size_mb * 1024 * 1024
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1 or metadata.st_size > maximum:
            return None
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum or b"\x00" in data:
            return None
        text = data.decode("utf-8", errors="strict")
        lines = text.splitlines()
        result = "\n".join(lines[:max_lines])
        if len(lines) > max_lines:
            result += f"\n... (file truncated after {max_lines} lines)"
        return result
    except (OSError, ValueError, UnicodeError):
        return None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
