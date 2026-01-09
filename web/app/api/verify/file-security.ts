/**
 * File security and validation utilities
 * Prevents malicious file uploads while supporting vulnerability analysis
 */

// ALLOWED file extensions for vulnerability analysis
export const ALLOWED_CODE_EXTENSIONS = [
  // Programming languages
  '.py', '.pyw', '.pyc',           // Python
  '.js', '.mjs', '.cjs',           // JavaScript
  '.ts', '.tsx', '.jsx',           // TypeScript/React
  '.java', '.class', '.jar',       // Java
  '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx', // C/C++
  '.cs',                           // C#
  '.go',                           // Go
  '.rs',                           // Rust
  '.rb',                           // Ruby
  '.php', '.phtml',                // PHP
  '.swift',                        // Swift
  '.kt', '.kts',                   // Kotlin
  '.scala',                        // Scala
  '.sol', '.vy',                   // Smart contracts (Solidity, Vyper)
  '.move',                         // Move (blockchain)
  '.cairo',                        // Cairo (StarkNet)

  // Shell scripts (analyzed, not executed)
  '.sh', '.bash', '.zsh', '.fish',

  // Configuration files
  '.json', '.json5',
  '.yaml', '.yml',
  '.toml', '.ini', '.cfg',
  '.env', '.env.example',
  '.config',

  // Web files
  '.html', '.htm',
  '.css', '.scss', '.sass', '.less',
  '.vue', '.svelte',

  // Documentation
  '.md', '.markdown', '.txt', '.rst',

  // Build/project files
  '.gradle', '.maven',
  'Makefile', 'Dockerfile', 'Jenkinsfile',
  '.gitignore', '.dockerignore',

  // Archives (extracted, not executed)
  '.zip', '.tar', '.gz', '.tgz',
]

// BLOCKED file extensions (executable/dangerous)
export const BLOCKED_EXTENSIONS = [
  // Windows executables
  '.exe', '.dll', '.sys', '.bat', '.cmd', '.com', '.scr',
  '.msi', '.vbs', '.vbe', '.wsf', '.wsh',

  // macOS executables
  '.app', '.dmg', '.pkg',

  // Linux executables (note: .so libraries allowed for analysis)
  '.run', '.bin',

  // Office files with macros (security risk)
  '.xlsm', '.xlsb', '.xltm', '.docm', '.dotm', '.pptm',

  // Other dangerous
  '.iso', '.img',
]

// Malicious content patterns to detect
const MALICIOUS_PATTERNS = [
  // Shell command injection attempts
  /;\s*rm\s+-rf\s+\//, // rm -rf /
  /;\s*chmod\s+777/, // chmod 777
  /;\s*mkfs/, // format filesystem

  // Reverse shells
  /bash\s+-i\s+>&\s+\/dev\/tcp/,
  /nc\s+-e\s+\/bin\/(ba)?sh/,
  /python.*socket.*subprocess/,

  // Data exfiltration
  /curl.*\|\s*bash/,
  /wget.*\|\s*bash/,

  // Crypto miners
  /xmrig|minergate|cryptonight/i,

  // Common malware signatures
  /eval\s*\(\s*base64_decode/,
  /system\s*\(\s*base64_decode/,

  // SQL injection attempts in files (suspicious)
  /UNION\s+SELECT.*FROM\s+information_schema/i,
  /LOAD_FILE\s*\(/i,
]

/**
 * Check if file extension is allowed
 */
export function isAllowedFileType(filename: string): boolean {
  const lower = filename.toLowerCase()

  // Check if explicitly blocked
  for (const blocked of BLOCKED_EXTENSIONS) {
    if (lower.endsWith(blocked.toLowerCase())) {
      return false
    }
  }

  // Check if allowed
  for (const allowed of ALLOWED_CODE_EXTENSIONS) {
    if (lower.endsWith(allowed.toLowerCase())) {
      return true
    }
  }

  // Special case: files without extension (Makefile, Dockerfile, etc.)
  if (!lower.includes('.')) {
    const baseName = filename.split('/').pop() || ''
    const allowedNoExt = ['Makefile', 'Dockerfile', 'Jenkinsfile', 'Vagrantfile']
    if (allowedNoExt.includes(baseName)) {
      return true
    }
  }

  // Default: allow for analysis (we just read as text)
  // But warn about unknown types
  console.warn(`Unknown file type: ${filename}`)
  return true
}

/**
 * Check if file is a binary executable (dangerous)
 */
export function isBinaryExecutable(buffer: Buffer): boolean {
  // Check for common executable signatures
  const signatures = [
    // ELF (Linux)
    Buffer.from([0x7F, 0x45, 0x4C, 0x46]),
    // PE (Windows .exe)
    Buffer.from([0x4D, 0x5A]),
    // Mach-O (macOS)
    Buffer.from([0xFE, 0xED, 0xFA, 0xCE]),
    Buffer.from([0xFE, 0xED, 0xFA, 0xCF]),
    Buffer.from([0xCE, 0xFA, 0xED, 0xFE]),
    Buffer.from([0xCF, 0xFA, 0xED, 0xFE]),
  ]

  for (const sig of signatures) {
    if (buffer.length >= sig.length) {
      if (buffer.subarray(0, sig.length).equals(sig)) {
        return true
      }
    }
  }

  return false
}

/**
 * Scan file content for malicious patterns
 */
export function scanForMaliciousContent(content: string, filename: string): {
  isSafe: boolean
  issues: string[]
} {
  const issues: string[] = []

  // Check for malicious patterns
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.test(content)) {
      issues.push(`Detected suspicious pattern: ${pattern.source}`)
    }
  }

  // Check for excessive obfuscation
  const base64Matches = content.match(/[A-Za-z0-9+/]{100,}/g)
  if (base64Matches && base64Matches.length > 10) {
    issues.push('Excessive base64 encoding detected (possible obfuscation)')
  }

  // Check for very long lines (obfuscation)
  const lines = content.split('\n')
  const longLines = lines.filter(line => line.length > 10000)
  if (longLines.length > 5) {
    issues.push('Multiple extremely long lines detected (possible obfuscation)')
  }

  // Check file size to content ratio (compressed/obfuscated)
  if (content.length > 1000000) { // 1MB
    const uniqueChars = new Set(content).size
    const ratio = uniqueChars / content.length
    if (ratio < 0.01) {
      issues.push('Very low entropy detected (possible compressed malware)')
    }
  }

  return {
    isSafe: issues.length === 0,
    issues
  }
}

/**
 * Validate and sanitize uploaded file
 */
export async function validateFile(
  file: File
): Promise<{
  valid: boolean
  error?: string
  warnings?: string[]
}> {
  const warnings: string[] = []

  // 1. Check file extension
  if (!isAllowedFileType(file.name)) {
    return {
      valid: false,
      error: `File type not allowed: ${file.name}. Blocked for security.`
    }
  }

  // 2. Check file size (10MB per file max)
  const maxSize = 10 * 1024 * 1024 // 10MB
  if (file.size > maxSize) {
    return {
      valid: false,
      error: `File too large: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)}MB). Max 10MB per file.`
    }
  }

  // 3. Check if file is empty
  if (file.size === 0) {
    return {
      valid: false,
      error: `File is empty: ${file.name}`
    }
  }

  // 4. Read file content for analysis
  const buffer = Buffer.from(await file.arrayBuffer())

  // 5. Check if binary executable
  if (isBinaryExecutable(buffer)) {
    return {
      valid: false,
      error: `Binary executable detected: ${file.name}. Not allowed for security.`
    }
  }

  // 6. Try to read as text (with error handling for binary files)
  let content: string
  try {
    content = buffer.toString('utf-8')

    // Check if it's actually readable text
    const nonPrintable = content.match(/[\x00-\x08\x0B-\x0C\x0E-\x1F]/g)
    if (nonPrintable && nonPrintable.length > content.length * 0.1) {
      // More than 10% non-printable = binary file
      // Allow it but limit how much we use
      warnings.push(`File appears to be binary: ${file.name}. Will analyze partially.`)
    }
  } catch (e) {
    return {
      valid: false,
      error: `Unable to read file: ${file.name}. May be corrupted or binary.`
    }
  }

  // 7. Scan for malicious content
  const scanResult = scanForMaliciousContent(content, file.name)
  if (!scanResult.isSafe) {
    return {
      valid: false,
      error: `Malicious content detected in ${file.name}: ${scanResult.issues.join(', ')}`
    }
  }

  // 8. All checks passed
  return {
    valid: true,
    warnings: warnings.length > 0 ? warnings : undefined
  }
}

/**
 * Validate all files in upload
 */
export async function validateFiles(files: File[]): Promise<{
  valid: boolean
  error?: string
  warnings?: string[]
}> {
  // Check total size
  const totalSize = files.reduce((sum, f) => sum + f.size, 0)
  const maxTotalSize = 50 * 1024 * 1024 // 50MB

  if (totalSize > maxTotalSize) {
    return {
      valid: false,
      error: `Total file size too large: ${(totalSize / 1024 / 1024).toFixed(2)}MB. Max 50MB total.`
    }
  }

  // Check file count
  const maxFiles = 100
  if (files.length > maxFiles) {
    return {
      valid: false,
      error: `Too many files: ${files.length}. Max ${maxFiles} files.`
    }
  }

  // Validate each file
  const allWarnings: string[] = []

  for (const file of files) {
    const result = await validateFile(file)

    if (!result.valid) {
      return result // Return first error
    }

    if (result.warnings) {
      allWarnings.push(...result.warnings)
    }
  }

  return {
    valid: true,
    warnings: allWarnings.length > 0 ? allWarnings : undefined
  }
}
