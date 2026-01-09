"""Report parsing utilities"""

import re
from typing import Dict, List, Optional
from pathlib import Path
from html.parser import HTMLParser
from io import StringIO


class HTMLTextExtractor(HTMLParser):
    """Extract text content from HTML while preserving structure"""
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.in_code = False
        self.in_pre = False

    def handle_starttag(self, tag, attrs):
        if tag in ('code', 'pre'):
            self.in_code = True
            if tag == 'pre':
                self.in_pre = True
            self.text_parts.append('\n```\n')
        elif tag == 'br':
            self.text_parts.append('\n')
        elif tag in ('p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
            self.text_parts.append('\n\n')

    def handle_endtag(self, tag):
        if tag in ('code', 'pre'):
            self.text_parts.append('\n```\n')
            self.in_code = False
            if tag == 'pre':
                self.in_pre = False
        elif tag in ('p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
            self.text_parts.append('\n')

    def handle_data(self, data):
        # Preserve code formatting, normalize other text
        if self.in_pre or self.in_code:
            self.text_parts.append(data)
        else:
            # Normalize whitespace but preserve paragraphs
            normalized = ' '.join(data.split())
            if normalized:
                self.text_parts.append(normalized)

    def get_text(self):
        text = ''.join(self.text_parts)
        # Clean up excessive newlines
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()


def parse_html_report(content: str) -> str:
    """
    Parse HTML report and extract text content

    Args:
        content: HTML content

    Returns:
        Extracted text content
    """
    extractor = HTMLTextExtractor()
    extractor.feed(content)
    return extractor.get_text()


def parse_report_file(report_path: str) -> str:
    """
    Parse vulnerability report from file (supports .txt, .md, .html)

    Args:
        report_path: Path to report file

    Returns:
        Report content as string
    """
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Parse HTML files to extract text
    if path.suffix.lower() in ['.html', '.htm']:
        content = parse_html_report(content)

    return content


def extract_vulnerability_details(report: str) -> Dict[str, any]:
    """
    Extract key details from vulnerability report

    Args:
        report: Vulnerability report content

    Returns:
        Dictionary with extracted details:
        - type: Vulnerability type (e.g., "SQL Injection", "XSS")
        - severity: Severity level
        - affected_files: List of mentioned files
        - affected_functions: List of mentioned functions
        - keywords: Important keywords for searching
        - cwe: CWE identifier if present
    """
    details = {
        "type": None,
        "severity": None,
        "affected_files": [],
        "affected_functions": [],
        "keywords": [],
        "cwe": None,
        "description": "",
    }

    # Extract vulnerability type
    vuln_types = [
        "SQL Injection", "SQLi",
        "Cross-Site Scripting", "XSS",
        "Command Injection",
        "Path Traversal", "Directory Traversal",
        "Remote Code Execution", "RCE",
        "Server-Side Request Forgery", "SSRF",
        "XML External Entity", "XXE",
        "Deserialization",
        "Authentication Bypass",
        "Authorization Bypass",
        "Information Disclosure",
        "Denial of Service", "DoS",
        "Buffer Overflow",
        "Integer Overflow",
        "Use After Free",
        "Race Condition",
        "CSRF", "Cross-Site Request Forgery",
        "Open Redirect",
        "Insecure Direct Object Reference", "IDOR",
        "Security Misconfiguration",
        "Sensitive Data Exposure",
        "Missing Access Control",
        "Broken Authentication",
        "Broken Access Control",
    ]

    report_lower = report.lower()
    for vuln_type in vuln_types:
        if vuln_type.lower() in report_lower:
            details["type"] = vuln_type
            break

    # Extract severity
    severity_patterns = [
        r"severity[:\s]+(\w+)",
        r"impact[:\s]+(\w+)",
        r"(critical|high|medium|low)\s+severity",
    ]

    for pattern in severity_patterns:
        match = re.search(pattern, report, re.IGNORECASE)
        if match:
            details["severity"] = match.group(1).upper()
            break

    # Extract file paths
    file_patterns = [
        r"[\w\/\-\.]+\.(?:js|py|java|cpp|c|h|go|rs|php|rb|ts|tsx|jsx|sol|vy)",
        r"(?:in|at|file)\s+[\"\']?([\w\/\-\.]+\.[\w]+)[\"\']?",
    ]

    for pattern in file_patterns:
        matches = re.findall(pattern, report, re.IGNORECASE)
        if isinstance(matches[0] if matches else None, tuple):
            details["affected_files"].extend([m[0] for m in matches if m])
        else:
            details["affected_files"].extend(matches)

    # Extract function names
    function_patterns = [
        r"function\s+(\w+)",
        r"def\s+(\w+)",
        r"(\w+)\s*\(",
        r"method\s+(\w+)",
        r"in\s+(?:the\s+)?(\w+)\s+function",
    ]

    for pattern in function_patterns:
        matches = re.findall(pattern, report)
        details["affected_functions"].extend(matches)

    # Remove duplicates and common noise
    details["affected_files"] = list(set(details["affected_files"]))
    details["affected_functions"] = list(set([
        f for f in details["affected_functions"]
        if len(f) > 2 and f not in ["the", "and", "for", "with", "from"]
    ]))

    # Extract CWE
    cwe_match = re.search(r"CWE-(\d+)", report, re.IGNORECASE)
    if cwe_match:
        details["cwe"] = f"CWE-{cwe_match.group(1)}"

    # Extract keywords for searching
    # Look for important technical terms
    keyword_patterns = [
        r"\b(vulnerable|exploit|attack|payload|injection|bypass|overflow)\b",
        r"\b(input|output|parameter|argument|variable)\b",
        r"\b(validate|sanitize|encode|decode|parse|execute)\b",
    ]

    keywords_set = set()
    for pattern in keyword_patterns:
        matches = re.findall(pattern, report_lower)
        keywords_set.update(matches)

    details["keywords"] = list(keywords_set)

    # Store first 500 chars as description
    details["description"] = report[:500].strip()

    return details


def extract_code_mentions(report: str) -> List[str]:
    """
    Extract code snippets or references from report

    Args:
        report: Vulnerability report content

    Returns:
        List of code snippets or file:line references
    """
    mentions = []

    # Code blocks (markdown style)
    code_blocks = re.findall(r"```[\w]*\n(.*?)```", report, re.DOTALL)
    mentions.extend(code_blocks)

    # Inline code
    inline_code = re.findall(r"`([^`]+)`", report)
    mentions.extend(inline_code)

    # File:line references
    file_line_refs = re.findall(
        r"([\w\/\-\.]+\.[\w]+):(\d+)",
        report
    )
    mentions.extend([f"{f}:{l}" for f, l in file_line_refs])

    return mentions
