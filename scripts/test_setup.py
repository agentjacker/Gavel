#!/usr/bin/env python3
"""
Test script to verify Gavel installation and configuration
"""

import sys
import os
from pathlib import Path

def check_python_version():
    """Check if Python version is 3.9+"""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 9:
        print("✓ Python version: {}.{}.{}".format(version.major, version.minor, version.micro))
        return True
    else:
        print("✗ Python version: {}.{}.{} (requires 3.9+)".format(version.major, version.minor, version.micro))
        return False


def check_dependencies():
    """Check if required packages are installed"""
    required = [
        "anthropic",
        "openai",
        "requests",
        "click",
        "rich",
        "git",  # GitPython
        "dotenv",  # python-dotenv
    ]

    all_good = True
    for package in required:
        try:
            __import__(package)
            print(f"✓ {package} installed")
        except ImportError:
            print(f"✗ {package} not installed")
            all_good = False

    return all_good


def check_api_keys():
    """Check if API keys are configured"""
    from dotenv import load_dotenv
    load_dotenv()

    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    openrouter_key = os.getenv("OPENROUTER_API_KEY")

    if anthropic_key:
        print(f"✓ ANTHROPIC_API_KEY configured ({anthropic_key[:10]}...)")
        return True
    elif openrouter_key:
        print(f"✓ OPENROUTER_API_KEY configured ({openrouter_key[:10]}...)")
        return True
    else:
        print("✗ No API key found in .env file")
        print("  Please set ANTHROPIC_API_KEY or OPENROUTER_API_KEY")
        return False


def check_gavel_package():
    """Check if Gavel package is importable"""
    try:
        import gavel
        print(f"✓ Gavel package installed (version {gavel.__version__})")
        return True
    except ImportError:
        print("✗ Gavel package not installed")
        print("  Run: pip install -e .")
        return False


def check_git():
    """Check if git is available"""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        version = result.stdout.strip()
        print(f"✓ Git available: {version}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ Git not available")
        print("  Install git to use GitHub repository features")
        return False


def main():
    """Run all checks"""
    print("="*60)
    print("Gavel Setup Verification")
    print("="*60)
    print()

    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("API Keys", check_api_keys),
        ("Gavel Package", check_gavel_package),
        ("Git", check_git),
    ]

    results = []
    for name, check_func in checks:
        print(f"\n{name}:")
        print("-" * 40)
        results.append(check_func())
        print()

    print("="*60)
    if all(results):
        print("✓ All checks passed! Gavel is ready to use.")
        print()
        print("Try running:")
        print("  gavel --help")
    else:
        print("✗ Some checks failed. Please fix the issues above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
