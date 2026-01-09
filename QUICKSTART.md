# Gavel Quick Start Guide

Get up and running with Gavel in 5 minutes.

## Prerequisites

- Python 3.9 or higher
- Git
- API key from OpenRouter or Anthropic

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/gavel.git
cd gavel
```

### 2. Set up Python environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure API keys

```bash
# Copy example env file
cp .env.example .env

# Edit .env and add your API key
# Either ANTHROPIC_API_KEY or OPENROUTER_API_KEY
```

### 4. Run your first verification

```bash
# Verify a sample report
gavel -r examples/sample-report.txt -c https://github.com/curl/curl
```

## CLI Examples

### Basic verification

```bash
gavel -r vulnerability-report.txt -c /path/to/codebase
```

### GitHub repository

```bash
gavel -r report.txt -c https://github.com/user/repo
```

### Generate PoC

```bash
gavel -r report.txt -c /path/to/code --output-poc
```

### Use faster model

```bash
gavel -r report.txt -c /path/to/code --model sonnet-4.5
```

### Batch processing

```bash
gavel --batch reports/ -c /path/to/codebase
```

### JSON output

```bash
gavel -r report.txt -c /path/to/code --format json
```

## Web UI

### Run locally

```bash
cd web
npm install
npm run dev
```

Visit http://localhost:3000

### Deploy to Vercel

```bash
cd web
vercel
```

Add environment variables in Vercel dashboard.

## Tips

1. **Use Opus 4.5 for important reports** - More accurate, worth the cost
2. **Use Sonnet 4.5 for quick triage** - Faster and cheaper
3. **Batch processing saves money** - Process multiple reports efficiently
4. **Large repos take time** - Be patient with big codebases
5. **GitHub URLs work best** - Public repos are easiest to analyze

## Troubleshooting

### "No API key found"
- Check your `.env` file has `ANTHROPIC_API_KEY` or `OPENROUTER_API_KEY`
- Make sure `.env` is in the project root directory

### "Failed to clone repository"
- Check internet connection
- For private repos, add `GITHUB_TOKEN` to `.env`
- Verify the GitHub URL is correct

### "Module not found"
- Activate virtual environment: `source venv/bin/activate`
- Reinstall dependencies: `pip install -r requirements.txt`

### Web UI shows "No API key configured"
- Add API keys to `.env.local` in the `web/` directory
- Or set environment variables in Vercel dashboard

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check out [examples/](examples/) for sample reports
- Join discussions at [GitHub Discussions](https://github.com/yourusername/gavel/discussions)

## Support

- Issues: https://github.com/yourusername/gavel/issues
- Discussions: https://github.com/yourusername/gavel/discussions
