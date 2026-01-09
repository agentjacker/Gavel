"""Tests for vulnerability report parser"""

import pytest
from gavel.utils.parser import extract_vulnerability_details, extract_code_mentions


def test_extract_vulnerability_type():
    """Test extraction of vulnerability type from report"""
    report = """
    This is a SQL Injection vulnerability in the login function.
    The user input is not sanitized.
    """

    details = extract_vulnerability_details(report)
    assert details["type"] in ["SQL Injection", "SQLi"]


def test_extract_severity():
    """Test extraction of severity level"""
    report = """
    Severity: HIGH

    This vulnerability allows remote code execution.
    """

    details = extract_vulnerability_details(report)
    assert details["severity"] == "HIGH"


def test_extract_affected_files():
    """Test extraction of file paths"""
    report = """
    The vulnerability is in src/api/users.py at line 45.
    Also affects src/auth/login.js
    """

    details = extract_vulnerability_details(report)
    assert "src/api/users.py" in details["affected_files"]
    assert "src/auth/login.js" in details["affected_files"]


def test_extract_cwe():
    """Test extraction of CWE identifier"""
    report = """
    This is CWE-89: SQL Injection
    """

    details = extract_vulnerability_details(report)
    assert details["cwe"] == "CWE-89"


def test_extract_code_mentions():
    """Test extraction of code snippets"""
    report = """
    The vulnerable code is:
    ```python
    query = f"SELECT * FROM users WHERE id = {user_id}"
    ```

    This appears in `src/db.py:23`
    """

    mentions = extract_code_mentions(report)
    assert len(mentions) > 0
    assert any("SELECT" in m for m in mentions)


def test_empty_report():
    """Test handling of empty report"""
    details = extract_vulnerability_details("")
    assert details["type"] is None
    assert details["severity"] is None
    assert len(details["affected_files"]) == 0
