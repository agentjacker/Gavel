'use client'

import { useState } from 'react'

type VerificationResult = {
  verdict: 'VALID' | 'INVALID' | 'ERROR'
  reasoning: string
  trace?: string
  analysisLog?: string
  codeFound?: boolean
  confidence?: string
  poc?: string
}

export default function Home() {
  const [report, setReport] = useState('')
  const [codebasePath, setCodebasePath] = useState('')
  const [uploadedFiles, setUploadedFiles] = useState<FileList | null>(null)
  const [inputMode, setInputMode] = useState<'url' | 'upload'>('url')
  const [model, setModel] = useState<'opus-4.5' | 'sonnet-4.5'>('opus-4.5')
  const [generatePoc, setGeneratePoc] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [status, setStatus] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!report.trim()) {
      alert('Please provide a vulnerability report')
      return
    }

    if (inputMode === 'url' && !codebasePath.trim()) {
      alert('Please provide a GitHub URL')
      return
    }

    if (inputMode === 'upload' && (!uploadedFiles || uploadedFiles.length === 0)) {
      alert('Please upload code files or a zip file')
      return
    }

    setLoading(true)
    setResult(null)
    setStatus('Analyzing report and fetching code...')

    try {
      const formData = new FormData()
      formData.append('report', report)
      formData.append('model', model)
      formData.append('generatePoc', generatePoc.toString())

      if (inputMode === 'url') {
        formData.append('codebasePath', codebasePath)
      } else {
        // Upload files
        if (uploadedFiles) {
          for (let i = 0; i < uploadedFiles.length; i++) {
            formData.append('files', uploadedFiles[i])
          }
        }
      }

      const response = await fetch('/api/verify', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Verification failed')
      }

      setStatus('Running AI analysis...')
      const data = await response.json()
      setStatus('')
      setResult(data)
    } catch (error: any) {
      setStatus('')
      setResult({
        verdict: 'ERROR',
        reasoning: error.message || 'An error occurred during verification',
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="min-h-screen p-8 max-w-6xl mx-auto">
      {/* Header */}
      <div className="mb-8 text-center border border-black p-6">
        <pre className="text-xs mb-4 inline-block">
{`    ╔═══════════════════════════════════════╗
    ║                                       ║
    ║              ⚖️  GAVEL ⚖️             ║
    ║                                       ║
    ║    AI-Powered Vulnerability Triage   ║
    ║                                       ║
    ╚═══════════════════════════════════════╝`}
        </pre>
        <p className="text-sm">
          Verify vulnerability reports against codebases using advanced AI models
        </p>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Input Mode Selection */}
        <div className="border border-black p-4">
          <div className="text-sm font-bold mb-3">CODEBASE SOURCE</div>
          <div className="flex gap-4 mb-4">
            <label className="flex items-center cursor-pointer">
              <input
                type="radio"
                value="url"
                checked={inputMode === 'url'}
                onChange={(e) => setInputMode(e.target.value as 'url')}
                className="mr-2"
              />
              <span className="text-sm">GitHub URL</span>
            </label>
            <label className="flex items-center cursor-pointer">
              <input
                type="radio"
                value="upload"
                checked={inputMode === 'upload'}
                onChange={(e) => setInputMode(e.target.value as 'upload')}
                className="mr-2"
              />
              <span className="text-sm">Upload Files/Zip</span>
            </label>
          </div>

          {/* GitHub URL Input */}
          {inputMode === 'url' && (
            <>
              <label htmlFor="codebasePath" className="block text-sm font-bold mb-2">
                GITHUB REPOSITORY URL
              </label>
              <input
                id="codebasePath"
                type="text"
                value={codebasePath}
                onChange={(e) => setCodebasePath(e.target.value)}
                placeholder="https://github.com/user/repo"
                className="input-field"
              />
              <p className="text-xs mt-2 text-gray-600">
                Enter a public GitHub repository URL
              </p>
            </>
          )}

          {/* File Upload */}
          {inputMode === 'upload' && (
            <>
              <label htmlFor="fileUpload" className="block text-sm font-bold mb-2">
                UPLOAD CODE FILES (MULTIPLE SUPPORTED)
              </label>
              <div className="border-2 border-dashed border-black p-6 text-center bg-gray-50">
                <input
                  id="fileUpload"
                  type="file"
                  multiple
                  onChange={(e) => setUploadedFiles(e.target.files)}
                  className="w-full text-sm"
                />
                <p className="text-xs mt-3 text-gray-600">
                  Select multiple files (Ctrl/Cmd+Click) or drag & drop
                </p>
                <p className="text-xs mt-1 text-gray-600">
                  Max 10MB per file • 50MB total • 100 files max
                </p>
                <details className="mt-3 text-left">
                  <summary className="text-xs cursor-pointer text-gray-600 hover:text-black">
                    ✓ All code formats supported (click to see)
                  </summary>
                  <div className="text-xs mt-2 text-gray-600 pl-4">
                    <strong>Languages:</strong> Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Ruby, PHP, Swift, Kotlin, Scala, Solidity, Vyper, Move, Cairo<br/>
                    <strong>Config:</strong> JSON, YAML, TOML, ENV, INI<br/>
                    <strong>Web:</strong> HTML, CSS, Vue, Svelte<br/>
                    <strong>Scripts:</strong> Bash, Shell (analyzed, not executed)<br/>
                    <strong>Docs:</strong> Markdown, TXT<br/>
                    <strong>Archives:</strong> ZIP, TAR, GZ<br/>
                    <strong className="text-red-600">Blocked:</strong> EXE, DLL, APP, MSI (executables)
                  </div>
                </details>
              </div>
              {uploadedFiles && uploadedFiles.length > 0 && (
                <div className="mt-2 text-xs">
                  <span className="font-bold">Selected files:</span>
                  <ul className="list-disc list-inside mt-1">
                    {Array.from(uploadedFiles).slice(0, 10).map((file, i) => (
                      <li key={i}>{file.name} ({(file.size / 1024).toFixed(1)}KB)</li>
                    ))}
                    {uploadedFiles.length > 10 && (
                      <li>... and {uploadedFiles.length - 10} more files</li>
                    )}
                  </ul>
                </div>
              )}
            </>
          )}
        </div>

        {/* Vulnerability Report */}
        <div className="border border-black p-4">
          <label htmlFor="report" className="block text-sm font-bold mb-2">
            VULNERABILITY REPORT
          </label>
          <textarea
            id="report"
            value={report}
            onChange={(e) => setReport(e.target.value)}
            placeholder="Paste your vulnerability report here..."
            rows={15}
            className="textarea-field"
          />
          <p className="text-xs mt-2 text-gray-600">
            Large reports are supported. Paste your full vulnerability description.
          </p>
        </div>

        {/* Options */}
        <div className="border border-black p-4 space-y-4">
          <div className="text-sm font-bold mb-2">OPTIONS</div>

          {/* Model Selection */}
          <div>
            <label className="block text-xs mb-2">AI Model</label>
            <div className="flex gap-4">
              <label className="flex items-center cursor-pointer">
                <input
                  type="radio"
                  value="opus-4.5"
                  checked={model === 'opus-4.5'}
                  onChange={(e) => setModel(e.target.value as 'opus-4.5')}
                  className="mr-2"
                />
                <span className="text-sm">Claude Opus 4.5 (Recommended)</span>
              </label>
              <label className="flex items-center cursor-pointer">
                <input
                  type="radio"
                  value="sonnet-4.5"
                  checked={model === 'sonnet-4.5'}
                  onChange={(e) => setModel(e.target.value as 'sonnet-4.5')}
                  className="mr-2"
                />
                <span className="text-sm">Claude Sonnet 4.5 (Faster/Cheaper)</span>
              </label>
            </div>
          </div>

          {/* Generate PoC */}
          <div>
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={generatePoc}
                onChange={(e) => setGeneratePoc(e.target.checked)}
                className="mr-2"
              />
              <span className="text-sm">Generate Proof of Concept (if valid)</span>
            </label>
          </div>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={loading}
          className="w-full btn-primary disabled:bg-gray-400 disabled:cursor-not-allowed"
        >
          {loading ? 'VERIFYING...' : 'VERIFY REPORT'}
        </button>
      </form>

      {/* Status */}
      {status && (
        <div className="mt-6 border border-black p-4 bg-blue-50">
          <div className="text-sm font-mono">
            ⚙️ {status}
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className={`mt-8 border-2 p-6 ${
          result.verdict === 'VALID' ? 'border-black bg-green-50' :
          result.verdict === 'INVALID' ? 'border-black bg-red-50' :
          'border-black bg-yellow-50'
        }`}>
          <div className="text-center mb-4">
            <div className={`text-4xl font-bold ${
              result.verdict === 'VALID' ? 'text-green-600' :
              result.verdict === 'INVALID' ? 'text-red-600' :
              'text-yellow-600'
            }`}>
              [{result.verdict}]
            </div>
          </div>

          {/* Analysis Log */}
          {result.analysisLog && (
            <div className="border-t border-black pt-4 mt-4">
              <div className="text-xs font-bold mb-2">ANALYSIS LOG:</div>
              <pre className="text-xs bg-white border border-black p-3 font-mono">
                {result.analysisLog}
              </pre>
            </div>
          )}

          {/* Code Found Indicator */}
          {result.codeFound !== undefined && (
            <div className="mt-4">
              <div className="text-xs font-bold mb-2">CODE ANALYSIS:</div>
              <div className={`text-sm ${result.codeFound ? 'text-green-600' : 'text-red-600'}`}>
                {result.codeFound ? '✓ Code fetched and analyzed from repository' : '✗ No code available for analysis'}
              </div>
            </div>
          )}

          {/* AI Reasoning Trace */}
          {result.trace && (
            <div className="border-t border-black pt-4 mt-4">
              <div className="text-xs font-bold mb-2">AI REASONING TRACE:</div>
              <div className="text-sm bg-white border border-black p-3 whitespace-pre-wrap">
                {result.trace}
              </div>
            </div>
          )}

          {/* Final Reasoning */}
          <div className="border-t border-black pt-4 mt-4">
            <div className="text-xs font-bold mb-2">FINAL REASONING:</div>
            <div className="text-sm bg-white border border-black p-3">
              {result.reasoning}
            </div>
          </div>

          {/* Confidence */}
          {result.confidence && (
            <div className="mt-4">
              <div className="text-xs font-bold mb-2">CONFIDENCE:</div>
              <div className="text-sm">{result.confidence.toUpperCase()}</div>
            </div>
          )}

          {/* Proof of Concept */}
          {result.poc && (
            <div className="mt-4">
              <div className="text-xs font-bold mb-2">PROOF OF CONCEPT:</div>
              <pre className="text-xs bg-white border border-black p-3 overflow-x-auto">
                {result.poc}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <footer className="mt-16 text-center text-xs text-gray-500 border-t border-black pt-8">
        <p>Gavel v0.4.0 | Built for the security research community</p>
      </footer>
    </main>
  )
}
