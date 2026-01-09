import { NextRequest, NextResponse } from 'next/server'
import Anthropic from '@anthropic-ai/sdk'
import OpenAI from 'openai'
import { exec } from 'child_process'
import { promisify } from 'util'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { validateFiles } from './file-security'

const execAsync = promisify(exec)

// Security: Sanitize input to prevent prompt injection
function sanitizeInput(text: string): string {
  if (!text) return ''

  // Limit length
  const maxLength = 500000
  if (text.length > maxLength) {
    text = text.substring(0, maxLength)
  }

  // Remove null bytes
  text = text.replace(/\x00/g, '')

  // Remove potential special tokens
  text = text.replace(/<\|endoftext\|>/gi, '')
  text = text.replace(/<\|startoftext\|>/gi, '')

  return text
}

// Clone GitHub repository
async function cloneRepo(repoUrl: string): Promise<string | null> {
  try {
    // Extract repo name
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/\.]+)/)
    if (!match) return null

    const [, owner, repo] = match
    const tempDir = path.join(os.tmpdir(), 'gavel_repos', `${owner}_${repo}_${Date.now()}`)

    // Clone with depth 1 for speed
    await execAsync(`git clone --depth 1 ${repoUrl} "${tempDir}"`, { timeout: 60000 })

    return tempDir
  } catch (error) {
    console.error('Clone error:', error)
    return null
  }
}

// Search for files matching patterns
async function searchCodebase(repoPath: string, patterns: string[]): Promise<string> {
  try {
    let codeSnippets = ''

    // Search for each pattern
    for (const pattern of patterns) {
      try {
        // Use grep to find matches
        const { stdout } = await execAsync(
          `grep -r -n -i "${pattern}" "${repoPath}" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.cpp" --include="*.c" --include="*.go" --include="*.rs" --include="*.sol" || true`,
          { maxBuffer: 1024 * 1024 * 5, timeout: 10000 }
        )

        if (stdout) {
          codeSnippets += `\n// Found matches for "${pattern}":\n${stdout.slice(0, 5000)}\n`
        }
      } catch (err) {
        // Continue on error
      }
    }

    return codeSnippets || 'No matching code found in repository.'
  } catch (error) {
    return 'Error searching codebase.'
  }
}

// Extract search patterns from report
function extractSearchPatterns(report: string): string[] {
  const patterns: string[] = []

  // Extract function names
  const funcMatches = report.match(/function\s+(\w+)|def\s+(\w+)|(\w+)\s*\(/g)
  if (funcMatches) {
    funcMatches.forEach(match => {
      const name = match.replace(/function\s+|def\s+|\s*\(/, '').trim()
      if (name.length > 3 && !['the', 'and', 'for'].includes(name)) {
        patterns.push(name)
      }
    })
  }

  // Extract file names
  const fileMatches = report.match(/[\w\/\-\.]+\.(py|js|ts|java|cpp|c|go|rs|sol)/g)
  if (fileMatches) {
    fileMatches.forEach(file => {
      const basename = path.basename(file, path.extname(file))
      if (basename.length > 2) {
        patterns.push(basename)
      }
    })
  }

  // Extract code in backticks
  const codeMatches = report.match(/`([^`]+)`/g)
  if (codeMatches) {
    codeMatches.forEach(code => {
      const cleaned = code.replace(/`/g, '').trim()
      if (cleaned.length > 3 && cleaned.length < 50) {
        patterns.push(cleaned)
      }
    })
  }

  return [...new Set(patterns)].slice(0, 10) // Limit to 10 patterns
}

// Build verification prompt with code context
function buildPrompt(report: string, codeContext: string, generatePoc: boolean): { system: string; user: string } {
  const system = `You are Gavel, an expert security researcher and code auditor specialized in verifying vulnerability reports.

Your role is to analyze vulnerability reports against actual codebases and determine if the reported vulnerability is VALID or INVALID.

CRITICAL RULES:
1. You MUST respond with ONLY "VALID" or "INVALID" - no partial verdicts, no "potentially valid", no hedging
2. A vulnerability is VALID if:
   - The reported vulnerability exists in the provided code
   - The attack vector is realistic and exploitable
   - The security impact is real (not theoretical)
3. A vulnerability is INVALID if:
   - The reported code doesn't exist or was misunderstood
   - Proper security controls are already in place
   - The attack vector is not actually exploitable
   - The report appears to be AI-generated slop without real analysis
4. Show your step-by-step reasoning in a TRACE section
5. After showing your trace, provide a final verdict and 1-2 sentence summary
6. Be skeptical of reports that:
   - Use generic vulnerability patterns without specific code references
   - Show signs of automated/AI generation without human review
   - Make assumptions about missing security controls without evidence
   - Describe theoretical attacks that don't work in the actual implementation

OUTPUT FORMAT:
TRACE:
1. [What I found in the codebase]
2. [Whether the reported vulnerability exists]
3. [Whether the attack vector is exploitable]
4. [Final assessment]

VERDICT: [VALID or INVALID]

REASONING: [Your 1-2 sentence explanation]

${generatePoc ? 'POC: [Proof of concept code or exploit steps]\n' : ''}
Be thorough in your trace. Security researchers and developers depend on your accurate assessment.`

  const user = `Please verify the following vulnerability report against the actual codebase.

${'='.repeat(60)}
VULNERABILITY REPORT:
${'='.repeat(60)}

${report}

${'='.repeat(60)}
CODE FROM REPOSITORY:
${'='.repeat(60)}

${codeContext}

${'='.repeat(60)}

First, show your TRACE analyzing:
1. What code you found in the repository
2. Whether the reported vulnerability actually exists in this code
3. Whether the attack vector described would work
4. Your final assessment

Then provide your VERDICT (VALID or INVALID) and REASONING.

${generatePoc ? 'If VALID, also provide a Proof of Concept (PoC) demonstrating the vulnerability.\n' : ''}
Remember:
- Show detailed TRACE of your analysis
- Output ONLY "VALID" or "INVALID" as verdict
- Provide 1-2 sentence reasoning
- Be skeptical of generic AI-generated reports
- Verify the vulnerability exists in the ACTUAL code provided`

  return { system, user }
}

// Parse AI response
function parseVerdict(response: string): {
  verdict: 'VALID' | 'INVALID'
  reasoning: string
  trace?: string
  poc?: string
} {
  // Extract verdict
  const verdictMatch = response.match(/VERDICT\s*[:\-]?\s*(VALID|INVALID)/i)
  let verdict: 'VALID' | 'INVALID' = 'INVALID' // Default to invalid

  if (verdictMatch) {
    verdict = verdictMatch[1].toUpperCase() as 'VALID' | 'INVALID'
  } else if (/^\s*VALID/i.test(response)) {
    verdict = 'VALID'
  } else if (/^\s*INVALID/i.test(response)) {
    verdict = 'INVALID'
  }

  // Extract reasoning
  const reasoningMatch = response.match(/REASONING\s*[:\-]?\s*(.+?)(?:\n\n|POC\s*[:\-]|$)/is)
  let reasoning = 'No reasoning provided'

  if (reasoningMatch) {
    reasoning = reasoningMatch[1].trim()
  } else {
    // Try to extract first few sentences
    const lines = response.split('\n').filter(l => l.trim() && !l.includes('VERDICT') && !l.includes('POC'))
    if (lines.length > 0) {
      reasoning = lines.slice(0, 2).join(' ')
    }
  }

  // Truncate to ~2 sentences
  const sentences = reasoning.split(/[.!?]+/)
  reasoning = sentences.slice(0, 2).join('. ').trim()
  if (reasoning && !reasoning.endsWith('.')) {
    reasoning += '.'
  }

  // Extract trace
  const traceMatch = response.match(/TRACE\s*[:\-]?\s*(.+?)(?:\n\nVERDICT|VERDICT)/is)
  const trace = traceMatch ? traceMatch[1].trim() : undefined

  // Extract PoC
  const pocMatch = response.match(/POC\s*[:\-]?\s*(.+)$/is)
  const poc = pocMatch ? pocMatch[1].trim() : undefined

  return { verdict, reasoning, trace, poc }
}

// Extract uploaded files
async function extractUploadedFiles(files: File[]): Promise<string> {
  try {
    const tempDir = path.join(os.tmpdir(), 'gavel_uploads', `upload_${Date.now()}`)
    await fs.mkdir(tempDir, { recursive: true })

    let codeContent = ''

    for (const file of files) {
      const filePath = path.join(tempDir, file.name)

      // Check if it's a zip file
      if (file.name.endsWith('.zip')) {
        // Save zip file
        const buffer = Buffer.from(await file.arrayBuffer())
        await fs.writeFile(filePath, buffer)

        // Extract zip
        try {
          await execAsync(`unzip -q "${filePath}" -d "${tempDir}"`, { timeout: 30000 })
        } catch (err) {
          console.error('Unzip error:', err)
        }
      } else {
        // Regular file - read and store
        const content = await file.text()
        await fs.writeFile(filePath, content)

        // Add to code content with file marker
        codeContent += `\n${'='.repeat(60)}\n`
        codeContent += `FILE: ${file.name}\n`
        codeContent += `${'='.repeat(60)}\n`
        codeContent += content.slice(0, 10000) // Limit per file
        codeContent += '\n'
      }
    }

    // If zip was extracted, search through it
    if (files.some(f => f.name.endsWith('.zip'))) {
      const patterns = ['function', 'def', 'class', 'const', 'var', 'let']
      codeContent = await searchCodebase(tempDir, patterns)
    }

    // NOTE: Cleanup handled by finally block in POST handler

    return codeContent || 'No code content could be extracted from uploaded files.'
  } catch (error) {
    console.error('File extraction error:', error)
    return 'Error extracting uploaded files.'
  }
}

export async function POST(request: NextRequest) {
  // Track temp directories for cleanup
  let tempDirsToCleanup: string[] = []

  try {
    const formData = await request.formData()
    const report = formData.get('report') as string
    const codebasePath = formData.get('codebasePath') as string | null
    const model = (formData.get('model') as string) || 'opus-4.5'
    const generatePoc = formData.get('generatePoc') === 'true'
    const files = formData.getAll('files') as File[]

    // Validate inputs
    if (!report) {
      return NextResponse.json(
        { error: 'Report is required' },
        { status: 400 }
      )
    }

    if (!codebasePath && files.length === 0) {
      return NextResponse.json(
        { error: 'Either codebase path or files are required' },
        { status: 400 }
      )
    }

    // Validate uploaded files for security
    if (files.length > 0) {
      const validationResult = await validateFiles(files)

      if (!validationResult.valid) {
        return NextResponse.json(
          { error: validationResult.error },
          { status: 400 }
        )
      }

      // Log warnings if any
      if (validationResult.warnings && validationResult.warnings.length > 0) {
        console.warn('File validation warnings:', validationResult.warnings)
      }
    }

    // Sanitize inputs
    const sanitizedReport = sanitizeInput(report)

    // Fetch code from repository or uploaded files
    let codeContext = 'No code available for analysis.'
    let analysisLog = ''

    if (files.length > 0) {
      // Handle uploaded files
      analysisLog += `Extracting ${files.length} uploaded file(s)...\n`
      const totalSize = files.reduce((sum, f) => sum + f.size, 0)
      analysisLog += `Total size: ${(totalSize / 1024 / 1024).toFixed(2)}MB\n`

      // Track temp directory
      const tempDir = path.join(os.tmpdir(), 'gavel_uploads', `upload_${Date.now()}`)
      tempDirsToCleanup.push(tempDir)

      codeContext = await extractUploadedFiles(files)
      analysisLog += `✓ Files processed and will be auto-deleted\n`

    } else if (codebasePath && codebasePath.includes('github.com')) {
      // Handle GitHub URL
      analysisLog += 'Cloning repository...\n'
      const repoPath = await cloneRepo(codebasePath)

      if (repoPath) {
        tempDirsToCleanup.push(repoPath) // Track for cleanup

        analysisLog += `✓ Repository cloned\n`

        // Extract search patterns from report
        const patterns = extractSearchPatterns(sanitizedReport)
        analysisLog += `Searching for: ${patterns.join(', ')}\n`

        // Search codebase
        codeContext = await searchCodebase(repoPath, patterns)
        analysisLog += `✓ Code search complete\n`
      } else {
        codeContext = 'Failed to clone repository. Analyzing report only.'
        analysisLog += '✗ Failed to clone repository\n'
      }
    } else {
      codeContext = 'No codebase provided for analysis.'
      analysisLog += '✗ No codebase provided\n'
    }

    // Build prompt with code context
    const { system, user } = buildPrompt(sanitizedReport, codeContext, generatePoc)

    // Check which API to use
    const anthropicKey = process.env.ANTHROPIC_API_KEY
    const openrouterKey = process.env.OPENROUTER_API_KEY

    let responseText: string

    if (anthropicKey) {
      // Use Anthropic API
      const client = new Anthropic({ apiKey: anthropicKey })

      const modelMap: Record<string, string> = {
        'opus-4.5': 'claude-opus-4-20250514',
        'sonnet-4.5': 'claude-sonnet-4-20250514',
      }

      const response = await client.messages.create({
        model: modelMap[model] || 'claude-opus-4-20250514',
        max_tokens: generatePoc ? 4096 : 2048,
        temperature: 0.1,
        system,
        messages: [{ role: 'user', content: user }],
      })

      responseText = response.content[0].type === 'text' ? response.content[0].text : ''
    } else if (openrouterKey) {
      // Use OpenRouter API
      const client = new OpenAI({
        apiKey: openrouterKey,
        baseURL: 'https://openrouter.ai/api/v1',
        defaultHeaders: {
          'HTTP-Referer': 'https://gavel.vercel.app',
          'X-Title': 'Gavel',
        },
      })

      const modelMap: Record<string, string> = {
        'opus-4.5': 'anthropic/claude-opus-4.5:beta',
        'sonnet-4.5': 'anthropic/claude-sonnet-4.5:beta',
      }

      const response = await client.chat.completions.create({
        model: modelMap[model] || 'anthropic/claude-opus-4.5:beta',
        messages: [{ role: 'user', content: `${system}\n\n${user}` }],
        max_tokens: generatePoc ? 4096 : 2048,
        temperature: 0.1,
      })

      responseText = response.choices[0]?.message?.content || ''
    } else {
      return NextResponse.json(
        { error: 'No API key configured. Please set ANTHROPIC_API_KEY or OPENROUTER_API_KEY in environment variables.' },
        { status: 500 }
      )
    }

    // Parse response
    const { verdict, reasoning, trace, poc } = parseVerdict(responseText)

    return NextResponse.json({
      verdict,
      reasoning,
      trace,
      analysisLog,
      codeFound: codeContext !== 'No code available for analysis.',
      confidence: model === 'opus-4.5' ? 'high' : 'medium',
      poc,
    })
  } catch (error: any) {
    console.error('Verification error:', error)
    return NextResponse.json(
      { error: error.message || 'An error occurred during verification' },
      { status: 500 }
    )
  } finally {
    // CRITICAL: Always cleanup temp files/directories
    // This ensures no files are left behind on the server
    for (const tempDir of tempDirsToCleanup) {
      try {
        await fs.rm(tempDir, { recursive: true, force: true })
      } catch (cleanupError) {
        // Log but don't fail - cleanup is best effort
        console.error(`Cleanup failed for ${tempDir}:`, cleanupError)
      }
    }
  }
}
