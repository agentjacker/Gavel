# Changelog

## [v0.4.0] - 2025-01-08

### Major Update: Universal File Format Support + Security Hardening

#### ✨ New Features

1. **All Code Formats Supported**
   - 50+ file extensions now supported
   - Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Ruby, PHP
   - Swift, Kotlin, Scala, Solidity, Vyper, Move, Cairo
   - Shell scripts, config files, web files, documentation
   - Archives (zip, tar, gz) with auto-extraction

2. **Multi-Layer Security System**
   - File extension validation (allow/block lists)
   - Binary executable detection (ELF, PE, Mach-O signatures)
   - Malicious content scanning (reverse shells, crypto miners, etc.)
   - Obfuscation detection (base64, low entropy)
   - File size limits (10MB/file, 50MB total, 100 files max)
   - Read-only analysis (never execute user code)

3. **Blocked Dangerous Files**
   - Windows executables: .exe, .dll, .bat, .msi, .vbs
   - macOS executables: .app, .dmg, .pkg
   - Office macros: .xlsm, .docm, .pptm
   - Disk images: .iso, .img

#### 🔒 Security Protections

**Against:**
- Malware uploads (executable detection)
- Reverse shells (pattern scanning)
- Data exfiltration (curl|bash detection)
- Crypto miners (xmrig, minergate)
- Obfuscated code (base64, entropy analysis)
- DoS attacks (file size/count limits)

**Examples Blocked:**
```bash
✗ malware.exe → Binary executable detected
✗ reverse_shell.sh → Malicious pattern: bash -i >& /dev/tcp
✗ miner.py → Crypto miner signature detected
✗ obfuscated.js → Excessive base64 encoding
```

#### 🛡️ Triple Cleanup Guarantee

1. Explicit cleanup in `finally` block
2. Vercel ephemeral filesystem
3. Container destruction after request

Files exist for 15-60 seconds maximum, then automatically wiped.

#### 📝 Documentation Added

- `SECURITY.md` - Complete security guide
- `FILE_UPLOAD_GUIDE.md` - How to upload files
- `VERCEL_DEPLOYMENT.md` - Deployment security

#### 🎨 UI Improvements

- Expandable list of supported formats
- Security status indicators
- Privacy guarantee footer
- Clear file limits displayed

---

## [v0.3.0] - 2025-01-08

### Major Update: Local File Upload Support

#### ✨ New Features

1. **Local File & Zip Upload**
   - Upload multiple code files directly from your computer
   - Upload .zip archives of your entire codebase (up to 50MB)
   - Supports all major file types (.py, .js, .ts, .java, .cpp, .go, .rs, .sol, etc.)
   - Automatic zip extraction and code search
   - No need for CLI when working with local code!

2. **Dual Input Modes**
   - **GitHub URL Mode**: Clone and analyze public repositories
   - **Upload Mode**: Upload files or zip archives for local code
   - Easy toggle between modes
   - Clear file list showing what's uploaded

3. **Enhanced File Processing**
   - Extracts and processes zip files automatically
   - Shows uploaded file names and sizes
   - Handles up to 50MB total file size
   - Automatic cleanup after analysis

#### 🔧 Improvements

- Updated UI with radio buttons for input mode selection
- Better error messages for missing inputs
- File size display for uploaded files
- More detailed analysis logs

#### 📝 What You Can Do Now

**Upload Local Files:**
```
1. Select "Upload Files/Zip" mode
2. Choose multiple .py, .js, etc. files OR a .zip of your project
3. Paste your vulnerability report
4. Click Verify
```

**Or Use GitHub:**
```
1. Select "GitHub URL" mode
2. Paste https://github.com/user/repo
3. Paste your vulnerability report
4. Click Verify
```

Both methods now work equally well!

---

## [v0.2.0] - 2025-01-08

### Major Updates: Code Analysis & Reasoning Trace

#### ✨ New Features

1. **Real Code Analysis in Web UI**
   - Web UI now actually fetches and analyzes code from GitHub repositories
   - Automatically clones repositories and searches for relevant code
   - Extracts function names, file names, and code snippets from reports
   - Shows detailed analysis log of what was found

2. **AI Reasoning Trace**
   - AI now shows step-by-step reasoning for every verdict
   - TRACE section shows:
     - What code was found in the repository
     - Whether the reported vulnerability exists
     - Whether the attack vector is exploitable
     - Final assessment
   - Completely transparent - you can see exactly why it gave VALID or INVALID

3. **Enhanced UI Display**
   - Analysis Log: Shows what Gavel did (cloning, searching, etc.)
   - Code Analysis Status: Indicates if code was successfully fetched
   - AI Reasoning Trace: Shows the AI's step-by-step thinking
   - Final Reasoning: Concise summary of the verdict
   - Better visual hierarchy with sections

4. **Improved Verification**
   - No longer just analyzes the report - now checks actual code
   - Compares vulnerability claims against real codebase
   - Much more accurate verdicts
   - Reduces false positives

#### 🔧 Technical Improvements

- Added GitHub repository cloning capability to web API
- Implemented code search using grep
- Extract search patterns from vulnerability reports
- Updated AI prompts to require detailed reasoning traces
- Added status messages during verification
- Better error handling for repository cloning

#### 🐛 Bug Fixes

- Fixed issue where web UI would say VALID for everything
- Fixed missing code analysis in web version
- Added proper environment variable handling

#### 📝 What You'll See Now

**Before:**
```
[VALID]
REASONING: The report describes a potential SQL injection vulnerability.
```

**After:**
```
ANALYSIS LOG:
Cloning repository...
✓ Repository cloned to /tmp/gavel_repos/curl_curl_123456
Searching for: search_users, users.py, SELECT, WHERE
✓ Code search complete

CODE ANALYSIS: ✓ Code fetched and analyzed from repository

AI REASONING TRACE:
1. Found code in src/api/users.py that matches the reported vulnerability
2. The search_users() function does use string concatenation for SQL queries
3. No parameterized queries or input sanitization detected
4. The attack vector described (OR '1'='1) would work as described
5. This is a real SQL injection vulnerability

VERDICT: [VALID]

FINAL REASONING: The SQL injection vulnerability exists in the search_users function.
The code uses unsafe string concatenation without parameterization.
```

#### 🚀 How to Use

1. **Stop your dev server** (Ctrl+C)
2. **Restart it:**
   ```bash
   cd web
   npm run dev
   ```
3. **Try a vulnerability report with a GitHub URL**
4. **Watch the analysis happen in real-time**
5. **See the detailed reasoning trace**

#### ⚠️ Important Notes

- **GitHub URLs only**: Local paths still require CLI (web can't access local filesystem)
- **Public repos only**: Private repos need CLI with GITHUB_TOKEN
- **Takes longer**: Cloning and analyzing code takes 10-30 seconds
- **More accurate**: But uses more tokens (costs more per verification)

#### 📊 What This Solves

**Your Issue:** "it still said its valid which means its not actually doing any reasoning on the code"

**Solution:**
- Now actually fetches and analyzes the real code
- Shows you exactly what it found and why
- Complete transparency in reasoning
- Can verify the AI is actually checking the codebase

---

## [v0.1.0] - 2025-01-08

Initial release with:
- Python CLI with ASCII art
- Token optimization
- OpenRouter & Anthropic API support
- Web UI with Next.js
- Batch processing
- Security features
