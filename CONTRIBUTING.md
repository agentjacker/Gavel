# Contributing to Gavel

Thank you for your interest in contributing to Gavel! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, professional, and constructive in all interactions.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/yourusername/gavel/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Example vulnerability report (if applicable)

### Suggesting Features

1. Open an issue with the "enhancement" label
2. Describe the feature and its use case
3. Explain why it would be useful to the community

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `pytest`
6. Format code: `black gavel/`
7. Lint code: `flake8 gavel/`
8. Type check: `mypy gavel/`
9. Commit with clear messages
10. Push and create a PR

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/gavel.git
cd gavel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run tests
pytest

# Format code
black gavel/

# Lint
flake8 gavel/

# Type check
mypy gavel/
```

## Project Structure

```
gavel/
├── gavel/              # Main package
│   ├── cli.py          # CLI interface
│   ├── core.py         # Core verification logic
│   ├── ai/             # AI provider integrations
│   ├── tools/          # Code analysis tools
│   └── utils/          # Utilities
├── web/                # Next.js web UI
├── tests/              # Test suite
├── examples/           # Example reports
└── docs/               # Documentation
```

## Coding Standards

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for function signatures
- Write docstrings for public functions
- Keep functions focused and small
- Maximum line length: 100 characters

### TypeScript (Web UI)

- Use TypeScript for all new code
- Follow the existing code style
- Use functional components with hooks
- Keep components small and focused

## Testing

- Write tests for all new functionality
- Maintain or improve code coverage
- Use descriptive test names: `test_<what>_<condition>_<expected>`
- Mock external API calls

Example:
```python
def test_sanitize_input_removes_null_bytes():
    """Test that null bytes are removed from input"""
    text = "Hello\x00World"
    result = sanitize_input(text)
    assert "\x00" not in result
```

## Documentation

- Update README.md for user-facing changes
- Add docstrings for new functions/classes
- Include examples in docstrings
- Update QUICKSTART.md for workflow changes

## Commit Messages

Follow conventional commits:

```
feat: Add batch processing support
fix: Correct SQL injection detection
docs: Update installation instructions
test: Add tests for token optimization
refactor: Simplify grep logic
```

## Areas for Contribution

### High Priority

- [ ] Support for more AI providers (OpenAI, Google)
- [ ] VSCode extension
- [ ] Improved PoC generation
- [ ] Better error messages

### Medium Priority

- [ ] Custom vulnerability rule definitions
- [ ] Integration with bug bounty platforms
- [ ] Support for more programming languages
- [ ] Performance optimizations

### Good First Issues

- [ ] Add more example reports
- [ ] Improve documentation
- [ ] Add unit tests
- [ ] Fix typos

## Questions?

- Open a [Discussion](https://github.com/yourusername/gavel/discussions)
- Join our community chat (coming soon)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
