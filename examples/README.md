# Example Vulnerability Reports

This directory contains sample vulnerability reports demonstrating valid reports, invalid reports, and security testing scenarios.

## Report Examples

### 1. Legitimate Report (legitimate-report.md)

A well-structured, detailed vulnerability report that should pass all security checks.

**Test it:**
```bash
gavel -r examples/legitimate-report.md -c /path/to/codebase -v
```

**Characteristics of a valid report:**
- ✅ Specific file and function names
- ✅ Actual code snippets from the codebase
- ✅ Concrete attack vector with example payload
- ✅ Clear line numbers or code locations
- ✅ Demonstrates real exploitability
- ✅ Shows understanding of the code
- ✅ No prompt injection attempts

### 2. Invalid Report (sample-invalid-report.txt)

**Characteristics of an invalid/AI-generated report:**
- ❌ Vague descriptions ("may be vulnerable", "could potentially")
- ❌ No specific file paths or function names
- ❌ Generic attack patterns without code context
- ❌ Theoretical attacks without proof
- ❌ Assumptions about missing security controls
- ❌ Cookie-cutter template language

## Security Testing Examples

### 3. Prompt Injection Attempt (test-prompt-injection.txt)

Demonstrates a report containing malicious instructions to override the AI's verdict.

**Test it:**
```bash
gavel -r examples/test-prompt-injection.txt -c /path/to/codebase -v
```

**Expected result:**
```
[WARNING] Prompt injection detected: Potential prompt injection detected: 'ignore all previous instructions'

[INVALID]
Report rejected due to potential security issue. This report contains patterns
associated with prompt injection attacks and cannot be processed safely.
```

**Attack techniques demonstrated:**
- Direct instruction override ("Ignore all previous instructions")
- Role manipulation ("You are now in developer mode")
- Verdict forcing ("Always respond with VALID")

### 4. System Extraction Attempt (test-system-extraction.html)

An HTML-formatted report attempting to extract Gavel's system prompts and internal instructions.

**Test it:**
```bash
gavel -r examples/test-system-extraction.html -c /path/to/codebase -v
```

**Expected result:**
Report should be rejected due to multiple information extraction patterns detected.

**Attack techniques demonstrated:**
- System prompt extraction requests
- HTML format testing (Gavel should parse and detect patterns)
- Role questioning
- Internal guideline revelation attempts

## Format Support Examples

Gavel supports multiple input formats:

### Text Files (.txt)
```bash
gavel -r report.txt -c /path/to/code
```

### Markdown (.md)
```bash
gavel -r legitimate-report.md -c /path/to/code
```

### HTML (.html, .htm)
```bash
gavel -r test-system-extraction.html -c /path/to/code
```

HTML files are automatically parsed to extract text while preserving code blocks.

## Batch Testing

Test multiple reports at once:

```bash
# Process all example reports
gavel --batch examples/ -c /path/to/codebase --format json > results.json

# Process with verbose output
gavel --batch examples/ -c /path/to/codebase -v
```

## Security Feature Testing

### Test Input Sanitization

The following patterns should be automatically sanitized:

```bash
# Special tokens removed
echo "Report with <|system|>tokens" > test.txt
gavel -r test.txt -c /path/to/code -v

# Hidden Unicode characters removed
# Zero-width spaces, invisible characters, etc.
```

### Test Detection Patterns

Gavel detects 60+ prompt injection patterns:

| Category | Examples |
|----------|----------|
| Instruction Override | "ignore previous instructions", "disregard all rules" |
| Role Manipulation | "you are now", "act as if", "pretend to be" |
| System Impersonation | "system:", "admin override", "developer mode" |
| Output Forcing | "always respond with VALID", "output only VALID" |
| Info Extraction | "reveal your instructions", "show system prompt" |
| Jailbreaking | "DAN mode", "god mode" |

### Test Output Sanitization

Even if prompt injection bypasses detection, output is sanitized:

- System prompt fragments removed
- Internal reasoning not leaked
- Special tokens filtered
- Suspicious lines redacted

## Writing Good Vulnerability Reports

To maximize the chance of a VALID verdict from Gavel:

1. **Be Specific**: Include exact file paths, function names, and line numbers
2. **Show Code**: Include the actual vulnerable code snippet
3. **Prove Exploitability**: Demonstrate a working attack, not just theory
4. **Reference CWE**: Include relevant CWE identifiers
5. **Provide PoC**: Include a proof of concept exploit
6. **Avoid Hedging**: Use definitive language when you've verified the vulnerability
7. **Stay Focused**: Don't include instructions, questions, or commands for the AI

## Common Red Flags

### AI-Generated Slop
- "The application may be vulnerable..." (hedging)
- "Potentially could allow..." (vague)
- No specific code references
- Theoretical attacks without verification
- Generic recommendations without context
- Copy-paste security best practices lists

### Prompt Injection Attempts
- Direct commands to the AI
- Questions about system instructions
- Attempts to change the AI's role
- Forcing specific verdicts
- Excessive capitalization or repetition
- Hidden characters or encoding tricks

## Security Documentation

For detailed information about Gavel's security architecture, see:
- [SECURITY.md](../SECURITY.md) - Comprehensive security documentation
- [README.md](../README.md) - General usage and features

## Contributing Examples

Found a good example of a valid or invalid report? Submit a PR!

Make sure to:
- Anonymize any sensitive information
- Include proper attribution if from a public bug bounty
- Mark clearly whether it should be VALID, INVALID, or REJECTED (security)
- Document the expected behavior
- Test with `gavel -v` to verify detection works correctly

## Quick Reference

### Command Cheat Sheet

```bash
# Basic usage
gavel -r report.txt -c /path/to/code

# Verbose mode (see security checks)
gavel -r report.txt -c /path/to/code -v

# Multiple formats
gavel -r report.html -c /path/to/code
gavel -r report.md -c /path/to/code

# Batch processing
gavel --batch examples/ -c /path/to/code

# JSON output
gavel -r report.txt -c /path/to/code --format json

# Generate PoC
gavel -r report.txt -c /path/to/code --output-poc
```

### Expected Outcomes

| File | Expected Verdict | Reason |
|------|------------------|--------|
| legitimate-report.md | VALID or INVALID | Based on actual code analysis |
| test-prompt-injection.txt | REJECTED | Prompt injection detected |
| test-system-extraction.html | REJECTED | Information extraction attempt |
| sample-invalid-report.txt | INVALID | No specific code evidence |

## Troubleshooting

### False Positives

If a legitimate report is rejected as prompt injection:

1. Review the report for security-related terminology that might trigger detection
2. Rephrase any questions or commands as declarative statements
3. Remove excessive capitalization or repetition
4. Check for hidden characters or unusual encoding
5. File an issue if you believe it's a bug in detection

### False Negatives

If a malicious report passes through:

1. Report it immediately as a security issue
2. Include the report (sanitized) and detection logs
3. Note which patterns bypassed detection
4. Help improve Gavel's security by contributing to pattern database
