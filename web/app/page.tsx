'use client'

import { useCallback, useEffect, useState } from 'react'
import PolicyEditor from './policy-editor'

type Asset = { id: string; name: string }
type Program = { organization_id: string; name: string; assets: Asset[]; submission_auth_required: boolean }
type Decision = {
  validity?: string; disposition?: string; priority?: string; summary?: string; owner?: string | null
  latent?: boolean; missing_prerequisites?: unknown[]; attack_paths?: unknown[]; evidence?: unknown[]
  [key: string]: unknown
}
type Report = { id: string; title: string; asset_id: string; status: string; created_at?: string; description?: string; decision?: Decision | null }
type GraphNode = { id: string; name?: string; kind?: string; owner?: string; [key: string]: unknown }
type GraphEdge = { id: string; source: string; target: string; kind?: string; state?: string; requires?: string[]; provides?: string[]; [key: string]: unknown }
type Graph = { revision: string; nodes: GraphNode[]; edges: GraphEdge[]; sources: Record<string, unknown>[] }
type Receipt = { id: string; receipt_token: string; status: string; message: string; outcome?: string }
type View = 'inbox' | 'context' | 'policy' | 'delivery' | 'researcher'

const navigation: { id: View; label: string }[] = [
  { id: 'inbox', label: 'Reports' },
  { id: 'context', label: 'Organization context' },
  { id: 'policy', label: 'Risk policy' },
  { id: 'delivery', label: 'Deliveries' },
]
const pageCopy: Record<View, { title: string; description: string }> = {
  inbox: { title: 'Reports', description: 'Review submitted vulnerabilities, supporting evidence, and company decisions.' },
  context: { title: 'Organization context', description: 'Indexed code and declared infrastructure. Each record belongs to a versioned source.' },
  policy: { title: 'Risk policy', description: 'Set critical assets, evidence freshness, routing, and accepted risks.' },
  delivery: { title: 'Deliveries', description: 'Notification events for your configured Jira and Slack destinations.' },
  researcher: { title: 'Submit a report', description: 'Report a vulnerability or check an existing submission.' },
}
const movementKinds = new Set(['connects', 'calls', 'trusts', 'reads', 'writes', 'assumes'])

function human(value: unknown): string {
  const outcomes: Record<string, string> = { evidence_supported: 'Source evidence supports this report', not_supported_by_current_evidence: 'Not supported by current evidence', requires_review: 'Needs security team review' }
  if (typeof value === 'string' && outcomes[value]) return outcomes[value]
  return String(value ?? 'Unassigned').replaceAll('_', ' ').toLowerCase().replace(/^./, first => first.toUpperCase())
}
function display(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2)
}
function Badge({ value }: { value: unknown }) {
  const text = String(value || 'pending')
  const tone = /invalid|blocked|failed|reject|critical|refuted/i.test(text) ? 'red' : /valid|complete|sent|allowed|observed|accept|supported/i.test(text) && !/invalid|not_supported/i.test(text) ? 'green' : /review|latent|queued|pending|unknown|uncertain|analyzing/i.test(text) ? 'amber' : 'neutral'
  return <span className={`badge ${tone}`}>{human(text)}</span>
}
async function api<T>(path: string, token?: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(`/api/gavel/${path}`, {
    method, cache: 'no-store', headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(method !== 'GET' ? { 'Content-Type': 'application/json' } : {}) },
    ...(method !== 'GET' ? { body: JSON.stringify(body ?? {}) } : {}), signal: AbortSignal.timeout(25_000),
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`)
  return data as T
}

export default function Home() {
  const [view, setView] = useState<View>('inbox')
  const [program, setProgram] = useState<Program | null>(null)
  const [connectionError, setConnectionError] = useState('')
  const [token, setToken] = useState('')
  const [tokenInput, setTokenInput] = useState('')
  const [reports, setReports] = useState<Report[]>([])
  const [graph, setGraph] = useState<Graph | null>(null)
  const [policy, setPolicy] = useState('')
  const [events, setEvents] = useState<Record<string, unknown>[]>([])
  const [selected, setSelected] = useState<Report | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [filter, setFilter] = useState('all')
  const [graphFilter, setGraphFilter] = useState('')

  const loadProgram = useCallback(async () => {
    try { setProgram(await api<Program>('program')); setConnectionError('') }
    catch (err) { setConnectionError(err instanceof Error ? err.message : 'Service unavailable') }
  }, [])
  useEffect(() => { void loadProgram() }, [loadProgram])

  const loadWorkspace = useCallback(async (access = token, nextView = view) => {
    if (!access || nextView === 'researcher') return
    setBusy(true); setError(''); setNotice('')
    try {
      if (nextView === 'inbox') {
        const inbox = await api<{ reports: Report[]; truncated?: boolean }>('admin/reports', access)
        setReports(inbox.reports)
        if (inbox.truncated) setNotice('Showing the newest reports within the inbox limit. Older reports remain in risk and chain analysis.')
      }
      if (nextView === 'context') setGraph(await api<Graph>('admin/graph', access))
      if (nextView === 'policy') {
        const [currentPolicy, currentGraph, currentReports] = await Promise.all([api('admin/policy', access), api<Graph>('admin/graph', access), api<{ reports: Report[] }>('admin/reports', access)])
        setPolicy(JSON.stringify(currentPolicy, null, 2)); setGraph(currentGraph); setReports(currentReports.reports)
      }
      if (nextView === 'delivery') setEvents((await api<{ events: Record<string, unknown>[] }>('admin/outbox', access)).events)
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not load the console') }
    finally { setBusy(false) }
  }, [token, view])
  useEffect(() => { if (token) void loadWorkspace() }, [token, view, loadWorkspace])
  useEffect(() => {
    if (!selected) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setSelected(null) }
    document.addEventListener('keydown', closeOnEscape)
    return () => document.removeEventListener('keydown', closeOnEscape)
  }, [selected])

  async function unlock(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      await api('admin/reports', tokenInput.trim())
      setToken(tokenInput.trim()); setTokenInput('')
    } catch (err) { setError(err instanceof Error ? err.message : 'Unable to sign in') }
    finally { setBusy(false) }
  }
  async function openReport(id: string) {
    setError('')
    try { setSelected(await api<Report>(`admin/reports/${id}`, token)) }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not load report') }
  }
  async function reportAction(action: 'reevaluate' | 'approve') {
    if (!selected) return
    setBusy(true); setError('')
    try {
      await api(`admin/reports/${selected.id}/${action}`, token, 'POST')
      setNotice(action === 'reevaluate' ? 'Report queued for re-evaluation.' : 'Delivery approved. Check Deliveries for its status.')
      setSelected(await api<Report>(`admin/reports/${selected.id}`, token))
      setReports((await api<{ reports: Report[] }>('admin/reports', token)).reports)
    } catch (err) { setError(err instanceof Error ? err.message : 'Action failed') }
    finally { setBusy(false) }
  }
  async function savePolicy(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('')
    try {
      const saved = await api('admin/policy', token, 'PUT', JSON.parse(policy))
      setPolicy(JSON.stringify(saved, null, 2)); setNotice('Policy saved. Reports are queued for reassessment.')
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not save policy') }
    finally { setBusy(false) }
  }
  function navigate(next: View) { setView(next); setSelected(null); setError(''); setNotice(''); window.scrollTo(0, 0) }
  function lock() { setToken(''); setReports([]); setGraph(null); setSelected(null); setPolicy(''); setEvents([]); setError(''); setNotice('') }
  const copy = pageCopy[view]
  const needsReview = reports.filter(report => /review/i.test(`${report.status} ${report.decision?.disposition} ${report.decision?.validity}`)).length
  const latentCount = reports.filter(report => report.decision?.latent).length
  const filtered = reports.filter(report => filter === 'all' || (filter === 'review' ? /review/i.test(`${report.status} ${report.decision?.disposition} ${report.decision?.validity}`) : report.decision?.latent))
  const nodes = graph?.nodes.filter(node => !graphFilter || display(node).toLowerCase().includes(graphFilter.toLowerCase())) || []
  const relationships = graph ? [...graph.edges].sort((first, second) => Number(movementKinds.has(second.kind || '')) - Number(movementKinds.has(first.kind || ''))) : []

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="/" aria-label="Gavel home">gavel<span className="brand-period">.</span></a>
      <div className="sidebar-org">{program?.name || 'Security console'}</div>
      <nav aria-label="Console">
        {navigation.map(item => <button key={item.id} onClick={() => navigate(item.id)} aria-current={view === item.id ? 'page' : undefined} className={`nav-item ${view === item.id ? 'active' : ''}`}><span>{item.label}</span>{item.id === 'inbox' && token && <span className="nav-count">{reports.length}</span>}</button>)}
      </nav>
      <div className="nav-divider" />
      <button onClick={() => navigate('researcher')} aria-current={view === 'researcher' ? 'page' : undefined} className={`nav-item ${view === 'researcher' ? 'active' : ''}`}><span>Submit a report</span><span aria-hidden="true">↗</span></button>
      <div className="sidebar-bottom"><div className="deployment"><span className={`status-dot ${program ? 'online' : ''}`} /><span>{program ? 'Service connected' : 'Service offline'}</span></div><span className="version-label">Self-hosted / 0.5.0</span></div>
    </aside>
    <div className="main-shell">
      <header className="topbar"><div className="breadcrumb"><span>Gavel</span><span aria-hidden="true">/</span><strong>{copy.title}</strong></div><div className="topbar-right">{token ? <button className="quiet-button" onClick={lock}>Lock console</button> : <span className="muted">{view === 'researcher' ? 'Researcher access' : 'Operator access'}</span>}</div></header>
      <main>
        <div className="page-heading"><div><h1>{copy.title}</h1><p className="page-description">{copy.description}</p></div>{view !== 'researcher' && token && <button className="button secondary refresh-button" disabled={busy} onClick={() => { void loadWorkspace() }}>{busy ? 'Refreshing…' : 'Refresh'}</button>}</div>
        {connectionError && <div className="alert error" role="alert"><div><strong>Gavel service unavailable</strong><p>{connectionError}</p></div><button className="quiet-button" onClick={() => { void loadProgram() }}>Retry</button></div>}
        {error && <div className="alert error" role="alert"><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error">Dismiss</button></div>}
        {notice && <div className="alert success" role="status">{notice}</div>}
        {view === 'researcher' ? <ResearcherPortal program={program} /> : !token ? <section className="access-panel">
          <div className="unlock-panel"><h2>Operator sign in</h2><p>Enter your deployment’s access token to view reports and company context.</p><form onSubmit={unlock}><label htmlFor="operator-token">Access token</label><input id="operator-token" type="password" autoComplete="off" spellCheck={false} value={tokenInput} onChange={event => setTokenInput(event.target.value)} required /><button className="button primary" disabled={busy || !tokenInput.trim()}>{busy ? 'Signing in…' : 'Sign in'}</button></form><p className="form-footnote">The token is kept in this tab until you lock the console.</p></div>
          {program && <dl className="access-meta"><div><dt>Program</dt><dd>{program.name}</dd></div><div><dt>Published assets</dt><dd>{program.assets.length}</dd></div><div><dt>Submission access</dt><dd>{program.submission_auth_required ? 'Program token required' : 'Public'}</dd></div></dl>}
        </section> : <>
          {view === 'inbox' && <>
            <div className="summary-strip"><Summary value={reports.length} label="reports" /><Summary value={needsReview} label="need review" /><Summary value={latentCount} label="latent findings" /></div>
            <section className="panel inbox-panel"><div className="panel-header"><h2>All reports <span className="inline-count">{reports.length}</span></h2><div className="segmented" aria-label="Filter reports">{[['all', 'All'], ['review', 'Needs review'], ['latent', 'Latent']].map(([value, label]) => <button key={value} className={filter === value ? 'selected' : ''} aria-pressed={filter === value} onClick={() => setFilter(value)}>{label}</button>)}</div></div>
              {filtered.length ? <div className="table-scroll"><table><thead><tr><th>Report</th><th>Validity</th><th>Decision</th><th>Priority</th><th>Owner</th><th><span className="sr-only">Details</span></th></tr></thead><tbody>{filtered.map(report => <tr key={report.id}><td><button className="finding-title" onClick={() => { void openReport(report.id) }}>{report.title}</button><div className="row-meta"><code>{report.id.slice(0, 8)}</code><span>{report.asset_id}</span>{report.decision?.latent && <span className="latent-marker">Latent</span>}</div></td><td><Badge value={report.decision?.validity || report.status} /></td><td><Badge value={report.decision?.disposition || 'pending'} /></td><td><span className="priority">{human(report.decision?.priority || 'unrated')}</span></td><td className="muted">{report.decision?.owner || 'Unassigned'}</td><td><button className="row-arrow" aria-label={`Open ${report.title}`} onClick={() => { void openReport(report.id) }}>Open</button></td></tr>)}</tbody></table></div> : <Empty title={filter === 'all' ? 'No reports yet' : 'No matching reports'} description={filter === 'all' ? 'Researcher submissions will appear here.' : 'Choose another filter to see other reports.'} action={filter === 'all' ? <button className="button secondary" onClick={() => navigate('researcher')}>Submit a report</button> : undefined} />}
            </section><p className="subtle-note">An absent attack path does not establish that a finding is safe.</p>
          </>}
          {view === 'context' && graph && <>
            <div className="summary-strip"><Summary value={graph.nodes.length} label="records" /><Summary value={graph.edges.length} label="relationships" /><Summary value={graph.sources.length} label="sources" /></div>
            <div className="revision-strip"><span>Revision</span><code>{graph.revision}</code></div>
            <section className="panel"><div className="panel-header"><h2>Inventory</h2><input className="search-input" aria-label="Filter context records" placeholder="Filter by name, type, or owner" value={graphFilter} onChange={event => setGraphFilter(event.target.value)} /></div>
              {nodes.length ? <div className="table-scroll"><table className="inventory-table"><thead><tr><th>Name / identifier</th><th>Type</th><th>Owner</th><th>Source facts</th></tr></thead><tbody>{nodes.slice(0, 120).map(node => <tr key={node.id}><td><span className="node-name">{node.name || node.id}</span><code>{node.id}</code></td><td className="node-kind">{human(node.kind || 'record')}</td><td className="muted">{node.owner || '—'}</td><td><details className="node-facts"><summary>Inspect</summary><pre>{JSON.stringify(node, null, 2)}</pre></details></td></tr>)}</tbody></table></div> : <Empty title={graphFilter ? 'No matching records' : 'No company context'} description={graphFilter ? 'Try another name, type, or owner.' : 'Synchronize a repository or import a topology source to add context.'} />}
              {nodes.length > 120 && <p className="list-limit">Showing 120 of {nodes.length} matching records. Use the filter to narrow the list.</p>}
            </section>
            <section className="panel"><div className="panel-header"><div><h2>Relationships</h2><p>Infrastructure relationships appear first. Code definitions and calls do not establish runtime reachability.</p></div></div>
              {relationships.length ? <div className="table-scroll"><table><thead><tr><th>From</th><th>Relationship</th><th>To</th><th>State</th><th>Prerequisites</th></tr></thead><tbody>{relationships.slice(0, 150).map(edge => <tr key={edge.id}><td><code>{edge.source}</code></td><td>{human(edge.kind || 'related')}</td><td><code>{edge.target}</code></td><td><Badge value={edge.state || 'unknown'} /></td><td>{edge.requires?.length ? edge.requires.join(', ') : '—'}</td></tr>)}</tbody></table></div> : <Empty title="No relationships" description="This context has no declared connections or indexed code relationships." />}
              {relationships.length > 150 && <p className="list-limit">Showing 150 of {relationships.length} relationships. The full graph is available through the operator API.</p>}
            </section>
            <section className="panel"><div className="panel-header"><h2>Sources</h2></div>{graph.sources.length ? <div className="table-scroll"><table className="source-table"><thead><tr><th>Source</th><th>Kind</th><th>Revision</th><th>Last synchronized</th><th>Details</th></tr></thead><tbody>{graph.sources.map((source, index) => <tr key={String(source.source_id || source.id || index)}><td><code>{String(source.source_id || source.id || '—')}</code></td><td>{human(source.kind || 'source')}</td><td><code>{String(source.revision || '—')}</code></td><td className="muted">{source.synced_at ? new Date(String(source.synced_at)).toLocaleString() : '—'}</td><td><details className="node-facts"><summary>Inspect</summary><pre>{JSON.stringify(source, null, 2)}</pre></details></td></tr>)}</tbody></table></div> : <Empty title="No sources" description="No source has been synchronized." />}</section>
          </>}
          {view === 'policy' && <form onSubmit={savePolicy}><section className="panel"><div className="panel-header"><h2>Company policy</h2><button className="button primary" disabled={busy || !policy}>{busy ? 'Saving…' : 'Save changes'}</button></div><PolicyEditor value={policy} onChange={setPolicy} nodes={graph?.nodes || []} findings={reports} busy={busy} /></section></form>}
          {view === 'delivery' && <section className="panel"><div className="panel-header"><h2>Delivery events <span className="inline-count">{events.length}</span></h2></div>{events.length ? <div className="table-scroll"><table className="delivery-table"><thead><tr><th>Destination</th><th>Status</th><th>Report</th><th>Attempts</th><th>Event</th></tr></thead><tbody>{events.map((event, index) => <tr key={String(event.id || index)}><td>{human(event.destination || event.integration || event.kind || 'Destination')}</td><td><Badge value={event.state || event.status || 'pending'} /></td><td><code>{String(event.report_id || '—')}</code></td><td>{String(event.attempts ?? '—')}</td><td><details className="node-facts"><summary>Inspect</summary><pre>{JSON.stringify(event, null, 2)}</pre></details></td></tr>)}</tbody></table></div> : <Empty title="No delivery events" description="Approve an eligible report to queue a notification to configured destinations." />}</section>}
        </>}
      </main>
    </div>
    {selected && <div className="drawer-backdrop" onClick={() => setSelected(null)}><aside className="report-drawer" role="dialog" aria-modal="true" aria-label="Report details" onClick={event => event.stopPropagation()}><div className="drawer-top"><span>Report details</span><button className="quiet-button" aria-label="Close report details" onClick={() => setSelected(null)}>Close <span aria-hidden="true">×</span></button></div><div className="drawer-content"><div className="row-meta"><code>{selected.id}</code><span>{selected.asset_id}</span></div><h2>{selected.title}</h2><div className="finding-badges"><Badge value={selected.decision?.validity || selected.status} /><Badge value={selected.decision?.disposition || 'pending'} />{selected.decision?.latent && <Badge value="latent" />}</div><div className="decision-summary"><h3>Assessment</h3><p>{selected.decision?.summary || 'Evaluation pending.'}</p></div><dl className="finding-facts"><div><dt>Priority</dt><dd>{human(selected.decision?.priority || 'unrated')}</dd></div><div><dt>Owner</dt><dd>{selected.decision?.owner || 'Unassigned'}</dd></div><div><dt>Received</dt><dd>{selected.created_at ? new Date(selected.created_at).toLocaleString() : '—'}</dd></div></dl>{selected.description && <section><h3>Researcher report</h3><p className="report-body">{selected.description}</p></section>}{selected.decision && <>{['missing_prerequisites', 'attack_paths', 'evidence'].map(key => <section key={key}><h3>{human(key)}</h3>{Array.isArray(selected.decision?.[key]) && (selected.decision?.[key] as unknown[]).length ? <div className="evidence-list">{(selected.decision?.[key] as unknown[]).map((item, index) => <pre key={index}>{display(item)}</pre>)}</div> : <p className="muted">None recorded.</p>}</section>)}<details className="full-assessment"><summary>Inspect full assessment</summary><pre>{JSON.stringify(selected.decision, null, 2)}</pre></details></>}</div><div className="drawer-actions"><button className="button secondary" disabled={busy} onClick={() => { void reportAction('reevaluate') }}>Re-evaluate</button><button className="button primary" disabled={busy || !selected.decision} onClick={() => { void reportAction('approve') }}>Approve delivery</button></div></aside></div>}
  </div>
}

function Summary({ value, label }: { value: number; label: string }) {
  return <div className="summary-item"><strong>{value}</strong><span>{label}</span></div>
}
function Empty({ title, description, action }: { title: string; description: string; action?: React.ReactNode }) {
  return <div className="empty"><h3>{title}</h3><p>{description}</p>{action}</div>
}

function ResearcherPortal({ program }: { program: Program | null }) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [asset, setAsset] = useState('')
  const [submissionToken, setSubmissionToken] = useState('')
  const [receipt, setReceipt] = useState<Receipt | null>(null)
  const [receiptId, setReceiptId] = useState('')
  const [receiptToken, setReceiptToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const poll = useCallback(async (id: string, access: string) => {
    const status = await api<Omit<Receipt, 'receipt_token'>>(`reports/${encodeURIComponent(id)}`, access)
    setReceipt({ ...status, receipt_token: access })
  }, [])
  useEffect(() => {
    if (!receipt || !['queued', 'analyzing', 'processing', 'evaluating', 'pending'].includes(receipt.status)) return
    const timer = window.setInterval(() => { void poll(receipt.id, receipt.receipt_token).catch(() => { /* Manual refresh retries a disconnected service. */ }) }, 4000)
    return () => window.clearInterval(timer)
  }, [receipt, poll])
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setCopied(false)
    try {
      const data = await api<Receipt>('reports', submissionToken, 'POST', { title, description, asset_id: asset })
      setReceipt(data); setReceiptId(data.id); setReceiptToken(data.receipt_token)
      setTitle(''); setDescription(''); setSubmissionToken('')
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not submit report') }
    finally { setBusy(false) }
  }
  async function checkReceipt(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try { await poll(receiptId.trim(), receiptToken.trim()) }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not retrieve submission') }
    finally { setBusy(false) }
  }
  return <div className="portal-grid"><div>{error && <div className="alert error" role="alert">{error}</div>}{receipt && <section className="panel receipt-panel"><div className="receipt-heading"><h2>Report received</h2><Badge value={receipt.status} /></div><p className="receipt-message" aria-live="polite">{receipt.message}</p>{receipt.outcome && <div className="receipt-outcome"><Badge value={receipt.outcome} /><p>This source assessment is pending the security team’s decision. It does not establish runtime exploitability.</p></div>}<label htmlFor="new-receipt-id">Report ID</label><input id="new-receipt-id" value={receipt.id} readOnly /><label htmlFor="new-receipt-token">Receipt token</label><input id="new-receipt-token" type="password" value={receipt.receipt_token} readOnly autoComplete="off" /><div className="receipt-actions"><button className="button secondary" onClick={() => { void navigator.clipboard.writeText(JSON.stringify({ id: receipt.id, receipt_token: receipt.receipt_token }, null, 2)).then(() => setCopied(true)).catch(() => setError('Could not copy. Select and save your report ID and receipt token.')) }}>{copied ? 'Copied' : 'Copy receipt'}</button><button className="quiet-button" onClick={() => { void poll(receipt.id, receipt.receipt_token).catch(err => setError(err.message)) }}>Refresh status</button></div><p className="form-footnote">Save this receipt before closing the tab. The token is required to check this report.</p></section>}<section className="panel"><div className="panel-header"><h2>New vulnerability report</h2></div><form className="submission-form" onSubmit={submit}><p className="section-caption">{program?.name ? `Submitting to ${program.name}.` : 'Select a published asset and describe the vulnerability.'}</p><label htmlFor="asset">Affected asset <span>Required</span></label><select id="asset" required value={asset} onChange={event => setAsset(event.target.value)} disabled={!program?.assets.length}><option value="">{program?.assets.length ? 'Select an asset' : 'No assets configured'}</option>{program?.assets.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select><label htmlFor="report-title">Title <span>Required</span></label><input id="report-title" required maxLength={200} value={title} onChange={event => setTitle(event.target.value)} placeholder="Affected behavior and location" /><label htmlFor="description">Report <span>Required</span></label><textarea id="description" required minLength={20} maxLength={50000} value={description} onChange={event => setDescription(event.target.value)} rows={12} placeholder={'Steps to reproduce\nObserved and expected behavior\nEvidence and potential impact\n\nInclude prerequisites and related findings, if relevant.'} /><div className="textarea-note"><span>Text reports up to 50,000 characters.</span><span>{description.length.toLocaleString()} / 50,000</span></div>{program?.submission_auth_required && <><label htmlFor="submission-token">Program token</label><input id="submission-token" type="password" autoComplete="off" value={submissionToken} onChange={event => setSubmissionToken(event.target.value)} required /></>}<div className="submit-footer"><span>A private receipt is returned after submission.</span><button className="button primary" disabled={busy || !asset || !program}>{busy ? 'Submitting…' : 'Submit report'}</button></div></form></section></div><aside className="portal-aside"><section className="receipt-lookup"><h2>Check a report</h2><p>Use the ID and token from your submission receipt.</p><form onSubmit={checkReceipt}><label htmlFor="receipt-id">Report ID</label><input id="receipt-id" required value={receiptId} onChange={event => setReceiptId(event.target.value)} autoComplete="off" /><label htmlFor="receipt-token">Receipt token</label><input id="receipt-token" required type="password" value={receiptToken} onChange={event => setReceiptToken(event.target.value)} autoComplete="off" /><button className="button secondary" disabled={busy}>Check status</button></form><p className="form-footnote">Your receipt shows the report’s status and assessment. Company code and infrastructure remain private.</p></section></aside></div>
}
