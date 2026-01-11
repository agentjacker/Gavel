# 🔨 Gavel

**AI-Powered Vulnerability Report Triaging Tool**

Gavel helps security researchers and developers verify vulnerability reports before submission, reducing noise and false positives in bug bounty programs.

## Why Gavel?

With the rise of AI-generated security reports, bug bounty programs are overwhelmed with invalid submissions. Gavel uses advanced AI models to verify vulnerability reports against actual codebases, helping researchers validate their findings before submission and helping companies filter legitimate reports.

## Features

- **Binary Verification**: Get clear `Valid` or `Invalid` verdicts with concise reasoning
- **AI Reasoning Trace**: See step-by-step how the AI reached its conclusion
- **Universal File Support**: 50+ file formats supported (Python, JS, Java, C/C++, Go, Rust, Solidity, and more)
- **Multi-Layer Security**: Blocks executables, detects malware, scans for malicious patterns
- **Token-Optimized Analysis**: Efficiently processes code by removing blanks, minimizing comments, and focusing on relevant functions
- **Dual Interface**: Command-line tool for terminal users, web UI for easy access
- **Multiple Input Methods**: GitHub URLs, file uploads (multiple files), or zip archives
- **Batch Processing**: Verify multiple vulnerability reports at once
- **Read-Only Security**: No code modification, files never executed, automatic cleanup
- **Zero Data Retention**: Files deleted within seconds, complete user isolation
- **Flexible AI Backend**: Supports OpenRouter (Opus 4.5, Sonnet 4.5) and Anthropic API with batch request support

## Installation

### Python CLI

```bash
# Clone the repository
git clone https://github.com/yourusername/gavel.git
cd gavel

# Install dependencies
pip install -r requirements.txt

# Or use pip install
pip install -e .
```

### Web UI

```bash
cd web
npm install
npm run dev
```

## Configuration

Create a `.env` file in the root directory:

```env
# OpenRouter API Key (Recommended)
OPENROUTER_API_KEY=your_openrouter_key_here

# Or Anthropic API Key
ANTHROPIC_API_KEY=your_anthropic_key_here

# Default model (opus-4.5 recommended, sonnet-4.5 for faster/cheaper)
DEFAULT_MODEL=anthropic/claude-opus-4.5:beta

# Enable batch processing for Anthropic (reduces costs)
ENABLE_BATCH_REQUESTS=true
```

## Usage

### CLI

**Basic usage:**
```bash
gavel --report vuln_report.txt --codebase /path/to/code

# Or with GitHub repository
gavel --report vuln_report.txt --codebase https://github.com/user/repo
```

**Flags:**

- `--report, -r`: Path to vulnerability report file (required)
- `--codebase, -c`: Path to codebase (local path or GitHub URL) (required)
- `--output-poc`: Generate a Proof of Concept instead of just verification
- `--model`: Specify AI model (`opus-4.5` or `sonnet-4.5`)
- `--batch`: Process multiple reports from a directory
- `--format`: Output format (`text`, `json`)
- `--verbose, -v`: Enable verbose logging

**Examples:**

```bash
# Single report verification
gavel -r report.txt -c /path/to/project

# GitHub repository
gavel -r report.txt -c https://github.com/curl/curl

# Request PoC generation
gavel -r report.txt -c /path/to/project --output-poc

# Batch processing
gavel --batch reports/ -c /path/to/project

# Use specific model
gavel -r report.txt -c /path/to/project --model sonnet-4.5

# JSON output
gavel -r report.txt -c /path/to/project --format json
```

### Web UI

```bash
# Development
cd web
npm run dev

# Production deployment (Vercel)
vercel deploy
```

Access the UI at `http://localhost:3000`

**Web Features:**
- Clean, terminal-inspired black & white interface
- Paste large vulnerability reports directly
- Drag & drop report files
- GitHub URL or local path input
- Real-time verification status
- No data persistence (privacy-focused)

## How It Works

1. **Report Analysis**: Gavel parses the vulnerability report to extract key claims and technical details
2. **Smart Grepping**: Uses MCP-style tools to efficiently search the codebase for relevant code
3. **Token Optimization**:
   - Removes blank lines
   - Minimizes comment content (removes spaces while preserving meaning)
   - Focuses on function implementations over imports
   - Extracts only relevant code sections
4. **AI Verification**: Sends optimized context to AI model (Opus 4.5 recommended) for analysis
5. **Binary Verdict**: Returns `Valid` or `Invalid` with 1-2 sentence reasoning

## Token Optimization Strategies

Gavel implements several techniques to minimize API costs:

- **Selective Code Extraction**: Only includes functions mentioned in the report, not entire files
- **Comment Compression**: Removes extra spaces from comments while preserving readability
- **Import Skipping**: Avoids including import statements unless directly relevant
- **Blank Line Removal**: Strips unnecessary whitespace
- **Batch Requests**: Uses Anthropic's batch API when processing multiple reports

## Security & Privacy

- **Read-Only**: Gavel never modifies your codebase
- **No Data Sharing**: Web UI uses in-memory processing only; no data stored between sessions
- **Prompt Injection Protection**: Input sanitization and strict tool boundaries
- **Local-First**: Can run completely offline with local codebases

## Output Format

**Text Output:**
```
[VALID] or [INVALID]

Reasoning: Brief 1-2 sentence explanation of the verdict.
```

**JSON Output:**
```json
{
  "verdict": "VALID",
  "reasoning": "The report correctly identifies a command injection vulnerability in the parse_url function at src/url.c:145",
  "confidence": "high",
  "report_id": "abc123",
  "timestamp": "2025-01-08T12:00:00Z"
}
```

## API Models

### Recommended: Claude Opus 4.5
- Best accuracy for complex vulnerability analysis
- Higher cost but more reliable verdicts
- Use for high-value reports or when accuracy is critical

### Alternative: Claude Sonnet 4.5
- Faster and more cost-effective
- Good for initial triage or batch processing
- Suitable for straightforward vulnerability types

## Batch Processing

Process multiple reports efficiently:

```bash
# All reports in a directory
gavel --batch ./reports -c /path/to/codebase

# Outputs results.json with all verdicts
```

## Development

```bash
# Run tests
pytest tests/

# Lint
flake8 gavel/
black gavel/

# Type checking
mypy gavel/
```

## Architecture

```
gavel/
├── gavel/
│   ├── __init__.py
│   ├── cli.py              # CLI interface with ASCII art
│   ├── core.py             # Core verification logic
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── openrouter.py   # OpenRouter integration
│   │   ├── anthropic.py    # Anthropic API integration
│   │   └── batch.py        # Batch request handling
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── grep.py         # Efficient code grepping
│   │   ├── github.py       # GitHub repository handling
│   │   └── optimizer.py    # Token optimization
│   └── utils/
│       ├── __init__.py
│       ├── parser.py       # Report parsing
│       └── security.py     # Security & sanitization
├── web/                    # Next.js web interface
│   ├── app/
│   ├── components/
│   └── api/
├── tests/
├── requirements.txt
├── setup.py
└── README.md
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Roadmap

- [ ] Support for more AI providers (OpenAI, Google)
- [ ] VSCode extension
- [ ] Custom rule definitions
- [ ] Integration with bug bounty platforms
- [ ] Automated PoC generation improvements
- [ ] Support for more languages beyond general code analysis

## FAQ

**Q: How accurate is Gavel?**
A: With Claude Opus 4.5, Gavel achieves high accuracy for common vulnerability types. However, it's a tool to assist verification, not replace human judgment.

**Q: Does Gavel store my code or reports?**
A: No. The CLI processes everything locally, and the web UI uses in-memory processing with no persistence.

**Q: Can I use Gavel offline?**
A: Partially. You can analyze local codebases, but AI verification requires API access.

**Q: What about rate limits?**
A: Use batch processing with Anthropic's batch API to optimize costs and avoid rate limits.

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/gavel/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/gavel/discussions)

---

Built with ❤️ for the security research community
