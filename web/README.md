# Gavel Web UI

Clean, terminal-inspired web interface for vulnerability report verification.

## Features

- **Black & White Design**: Crisp, minimal interface inspired by terminal aesthetics
- **Large Report Support**: Paste reports of any size
- **Real-time Verification**: Get instant VALID/INVALID verdicts
- **Multiple Input Methods**:
  - GitHub URLs (public repositories)
  - File upload (multiple files or zip archives)
- **Code Analysis**: Actually fetches and analyzes real code
- **AI Reasoning Trace**: See step-by-step how the AI reached its verdict
- **Privacy-Focused**: No data storage, all processing is in-memory
- **Model Selection**: Choose between Opus 4.5 (accurate) or Sonnet 4.5 (fast)
- **PoC Generation**: Optionally generate proof-of-concept exploits

## Development

```bash
# Install dependencies
npm install

# Create .env file
cp .env.example .env
# Add your API keys to .env

# Run development server
npm run dev
```

Visit `http://localhost:3000`

## Deployment to Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Set environment variables in Vercel dashboard:
# - ANTHROPIC_API_KEY or OPENROUTER_API_KEY
```

Or use the Vercel dashboard:
1. Import repository
2. Add environment variables
3. Deploy

## API Keys

You need either:
- `ANTHROPIC_API_KEY` - Direct Anthropic API access (recommended)
- `OPENROUTER_API_KEY` - Access via OpenRouter

Set these in your `.env.local` file for development or in Vercel environment variables for production.

## Architecture

- **Next.js 14** with App Router
- **TypeScript** for type safety
- **Tailwind CSS** for styling
- **Server-side API routes** for secure API key handling
- **No database** - all processing is stateless

## Security

- Input sanitization to prevent prompt injection
- No data persistence between requests
- API keys stored securely in environment variables
- Read-only operations only

## How to Use Local Files

You have two options for analyzing local code:

### Option 1: Upload Individual Files
1. Select "Upload Files/Zip" mode
2. Click the file input and select multiple code files
3. Supported: .py, .js, .ts, .jsx, .tsx, .java, .cpp, .c, .go, .rs, .sol

### Option 2: Upload Zip Archive
1. Zip your codebase: `zip -r myproject.zip myproject/`
2. Select "Upload Files/Zip" mode
3. Upload the .zip file (max 50MB)
4. Gavel will extract and search through it

## Limitations

The web version has some limitations compared to the CLI:
- File size limit: 50MB total
- No batch processing of multiple reports
- Zip extraction requires unzip command on server

For processing very large codebases or batch operations, use the Python CLI version.
