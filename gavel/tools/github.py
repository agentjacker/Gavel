"""Isolated HTTPS GitHub checkouts for the legacy command-line verifier."""

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional
import subprocess
from urllib.parse import urlsplit


def _is_valid_github_url(url: str) -> bool:
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 for c in url):
        return False
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment:
            return False
        if parsed.username or parsed.password or parsed.port is not None:
            return False
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 2 or parsed.path not in {f"/{parts[0]}/{parts[1]}", f"/{parts[0]}/{parts[1]}/"}:
            return False
        owner, repo = parts
        return bool(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", owner)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo)
            and repo not in {".", "..", ".git"}
        )
    except ValueError:
        return False


def _git_environment() -> dict:
    # Never inherit Git command overrides, alternate object paths, or injected config.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    return environment


def clone_or_pull_repo(repo_url: str, verbose: bool = False) -> Path:
    """Make a fresh checkout; caller owns deletion. No shared or stale cache is used."""
    if not _is_valid_github_url(repo_url):
        raise ValueError("Only HTTPS github.com owner/repository URLs without credentials, queries or refs are supported")
    local_path = Path(tempfile.mkdtemp(prefix="gavel_repo_"))
    try:
        subprocess.run(
            ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "init.templateDir=",
             "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
             "-c", "http.followRedirects=false", "clone", "--depth", "1", "--no-tags",
             "--", repo_url.rstrip("/"), str(local_path)],
            check=True, capture_output=True, text=True, timeout=120, env=_git_environment(),
        )
        return local_path
    except (subprocess.SubprocessError, OSError) as error:
        shutil.rmtree(local_path, ignore_errors=True)
        raise RuntimeError("Unable to obtain a fresh repository snapshot") from error


def _get_repo_name_from_url(url: str) -> str:
    if not _is_valid_github_url(url):
        raise ValueError("Invalid GitHub URL")
    return urlsplit(url).path.strip("/").removesuffix(".git").replace("/", "_")


def get_repo_info(repo_path: Path) -> Optional[dict]:
    if not (repo_path / ".git").is_dir() or (repo_path / ".git").is_symlink():
        return None
    info = {}
    for key, arguments in {
        "branch": ["branch", "--show-current"],
        "commit": ["rev-parse", "HEAD"],
        "remote": ["remote", "get-url", "origin"],
    }.items():
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), *arguments], capture_output=True,
                text=True, check=True, timeout=5, env=_git_environment(),
            )
            info[key] = result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return info or None
