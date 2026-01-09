"""GitHub repository handling utilities"""

import os
import re
import tempfile
from pathlib import Path
from typing import Optional
import subprocess
import hashlib


def clone_or_pull_repo(repo_url: str, verbose: bool = False) -> Path:
    """
    Clone a GitHub repository or pull if already exists

    Args:
        repo_url: GitHub repository URL
        verbose: Enable verbose logging

    Returns:
        Path to local repository

    Raises:
        ValueError: If URL is invalid
        RuntimeError: If git operations fail
    """
    # Validate URL
    if not _is_valid_github_url(repo_url):
        raise ValueError(f"Invalid GitHub URL: {repo_url}")

    # Create a cache directory for repos
    cache_dir = Path(tempfile.gettempdir()) / "gavel_repos"
    cache_dir.mkdir(exist_ok=True)

    # Generate a safe directory name from URL
    repo_name = _get_repo_name_from_url(repo_url)
    repo_hash = hashlib.md5(repo_url.encode()).hexdigest()[:8]
    local_path = cache_dir / f"{repo_name}_{repo_hash}"

    # Check if repo already exists
    if local_path.exists() and (local_path / ".git").exists():
        if verbose:
            print(f"Repository already exists, pulling latest changes...")

        try:
            # Pull latest changes
            subprocess.run(
                ["git", "-C", str(local_path), "pull"],
                check=True,
                capture_output=True,
                text=True,
                timeout=60
            )

            if verbose:
                print(f"Updated repository at {local_path}")

        except subprocess.CalledProcessError as e:
            if verbose:
                print(f"Pull failed, using existing version: {e.stderr}")
            # Continue with existing version if pull fails

    else:
        # Clone repository
        if verbose:
            print(f"Cloning repository: {repo_url}")

        try:
            # Use depth=1 for faster cloning
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(local_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            if verbose:
                print(f"Cloned repository to {local_path}")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to clone repository: {e.stderr}")

    return local_path


def _is_valid_github_url(url: str) -> bool:
    """Check if URL is a valid GitHub repository URL"""
    patterns = [
        r"^https?://github\.com/[\w\-]+/[\w\-]+/?$",
        r"^https?://github\.com/[\w\-]+/[\w\-]+\.git$",
        r"^git@github\.com:[\w\-]+/[\w\-]+\.git$",
    ]

    for pattern in patterns:
        if re.match(pattern, url):
            return True

    return False


def _get_repo_name_from_url(url: str) -> str:
    """Extract repository name from GitHub URL"""
    # Remove .git suffix
    url = url.rstrip("/").replace(".git", "")

    # Extract owner/repo
    match = re.search(r"github\.com[:/]([\w\-]+)/([\w\-]+)", url)
    if match:
        return f"{match.group(1)}_{match.group(2)}"

    # Fallback to hash
    return hashlib.md5(url.encode()).hexdigest()[:16]


def get_repo_info(repo_path: Path) -> Optional[dict]:
    """
    Get information about a git repository

    Args:
        repo_path: Path to repository

    Returns:
        Dictionary with repo info or None
    """
    if not (repo_path / ".git").exists():
        return None

    info = {}

    try:
        # Get current branch
        result = subprocess.run(
            ["git", "-C", str(repo_path), "branch", "--show-current"],
            capture_output=True,
            text=True,
            check=True
        )
        info["branch"] = result.stdout.strip()

        # Get latest commit hash
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        info["commit"] = result.stdout.strip()[:8]

        # Get remote URL
        result = subprocess.run(
            ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True
        )
        info["remote"] = result.stdout.strip()

    except subprocess.CalledProcessError:
        pass

    return info if info else None
