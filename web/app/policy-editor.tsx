'use client'

import { useId } from 'react'

type Node = { id: string; name?: string; kind?: string; [key: string]: unknown }
type Acceptance = { asset_id: string; primitive_id: string; evidence_fingerprint: string; reason: string; expires_at: string }
type Policy = { version: number; critical_assets: string[]; max_context_age_hours: number; auto_route: boolean; acceptances: Acceptance[] }
type Finding = { title: string; asset_id: string; decision?: { primitives?: unknown; [key: string]: unknown } | null }
type Primitive = { id: string; asset_id: string; fingerprint?: string }

function localDateTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const pad = (number: number) => String(number).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

export default function PolicyEditor({ value, onChange, nodes, findings, busy }: {
  value: string; onChange: (value: string) => void; nodes: Node[]; findings: Finding[]; busy: boolean
}) {
  const formId = useId()
  if (!value) return <div className="policy-editor"><p className="muted">Loading policy…</p></div>
  const policy = JSON.parse(value) as Policy
  const businessNodes = nodes.filter(node => !['file', 'symbol', 'function', 'class', 'module', 'import'].includes(node.kind || ''))
  const knownAssets = new Map(businessNodes.map(node => [node.id, node]))
  for (const asset of [...policy.critical_assets, ...policy.acceptances.map(item => item.asset_id)]) {
    if (asset && !knownAssets.has(asset)) knownAssets.set(asset, { id: asset, name: `${asset} (not in current context)` })
  }
  const assets = Array.from(knownAssets.values()).sort((first, second) => (first.name || first.id).localeCompare(second.name || second.id))
  const primitives: Primitive[] = findings.flatMap(finding => Array.isArray(finding.decision?.primitives) ? finding.decision.primitives as Primitive[] : [])
  function update(next: Partial<Policy>) { onChange(JSON.stringify({ ...policy, ...next }, null, 2)) }
  function changeAcceptance(index: number, changes: Partial<Acceptance>) {
    const acceptances = policy.acceptances.map((item, row) => row === index ? { ...item, ...changes } : item)
    update({ acceptances })
  }
  function choosePrimitive(index: number, primitiveId: string) {
    const acceptance = policy.acceptances[index]
    const matching = primitives.find(primitive => primitive.id === primitiveId && primitive.asset_id === acceptance.asset_id)
    changeAcceptance(index, { primitive_id: primitiveId, evidence_fingerprint: matching?.fingerprint || '' })
  }
  return <div className="policy-editor friendly-policy">
    <fieldset disabled={busy}>
      <section className="policy-section">
        <div className="policy-section-heading"><div><h3>Protected assets</h3><p>Prioritize findings that create access or impact on these resources.</p></div></div>
        {assets.length ? <div className="asset-options">{assets.map(asset => <label className="asset-option" key={asset.id}><input type="checkbox" checked={policy.critical_assets.includes(asset.id)} onChange={event => update({ critical_assets: event.target.checked ? [...policy.critical_assets, asset.id] : policy.critical_assets.filter(id => id !== asset.id) })} /><span><strong>{asset.name || asset.id}</strong><small>{asset.kind ? asset.kind.replaceAll('_', ' ') : 'Previously configured asset'}{asset.owner ? ` · ${String(asset.owner)}` : ''}</small></span></label>)}</div> : <div className="policy-empty">No resources indexed. Add organization context to select protected assets.</div>}
      </section>
      <section className="policy-section">
        <div className="policy-section-heading"><div><h3>Source freshness</h3><p>Require review when indexed sources are older than this limit.</p></div></div>
        <div className="hours-control"><label htmlFor={`${formId}-freshness`}>Maximum source age</label><div><input id={`${formId}-freshness`} type="number" min={1} max={720} step={1} required value={policy.max_context_age_hours} onChange={event => update({ max_context_age_hours: event.target.value === '' ? 0 : Number(event.target.value) })} /><span>hours</span></div><p>1–720 hours.</p></div>
      </section>
      <section className="policy-section">
        <div className="policy-section-heading"><div><h3>Delivery approval</h3><p>Choose whether eligible findings need operator approval before delivery.</p></div></div>
        <label className="routing-option"><input type="checkbox" checked={policy.auto_route} onChange={event => update({ auto_route: event.target.checked })} /><span><strong>Route eligible findings automatically</strong><small>When off, approve each delivery from the report. Owner assignments come from organization context.</small></span></label>
        <p className="policy-hint">Jira and Slack destinations are configured on the service.</p>
      </section>
      <section className="policy-section">
        <div className="policy-section-heading"><div><h3>Risk acceptances</h3><p>Accept a specific primitive until a set date. Changes to its evidence invalidate the acceptance.</p></div></div>
        {policy.acceptances.length ? <div className="acceptance-list">{policy.acceptances.map((acceptance, index) => <article className="acceptance-card" key={index}>
          <div className="acceptance-card-heading"><h4>{acceptance.asset_id || 'New acceptance'}</h4><button type="button" className="remove-acceptance" onClick={() => update({ acceptances: policy.acceptances.filter((_, row) => row !== index) })}>Remove</button></div>
          <div className="acceptance-fields"><div><label htmlFor={`${formId}-asset-${index}`}>Affected asset</label><select id={`${formId}-asset-${index}`} required value={acceptance.asset_id} onChange={event => changeAcceptance(index, { asset_id: event.target.value, primitive_id: '', evidence_fingerprint: '' })}><option value="">Choose an asset</option>{assets.map(asset => <option key={asset.id} value={asset.id}>{asset.name || asset.id}</option>)}</select></div>
          <div><label htmlFor={`${formId}-primitive-${index}`}>Primitive</label><input id={`${formId}-primitive-${index}`} list={`${formId}-primitives-${index}`} value={acceptance.primitive_id} onChange={event => choosePrimitive(index, event.target.value)} required maxLength={120} placeholder="Select or enter a primitive ID" autoComplete="off" /><datalist id={`${formId}-primitives-${index}`}>{primitives.filter(primitive => primitive.asset_id === acceptance.asset_id).map((primitive, option) => <option key={`${primitive.id}-${option}`} value={primitive.id} />)}</datalist></div></div>
          <label htmlFor={`${formId}-fingerprint-${index}`}>Evidence fingerprint</label><input id={`${formId}-fingerprint-${index}`} className="fingerprint-input" value={acceptance.evidence_fingerprint} onChange={event => changeAcceptance(index, { evidence_fingerprint: event.target.value })} required pattern="[a-f0-9]{64}" maxLength={64} title="64-character fingerprint from the report’s private assessment." placeholder="Select a primitive or paste its fingerprint" autoComplete="off" spellCheck={false} /><p className="field-help">Filled automatically for known primitives.</p>
          <label htmlFor={`${formId}-reason-${index}`}>Reason</label><textarea id={`${formId}-reason-${index}`} required maxLength={500} rows={3} value={acceptance.reason} onChange={event => changeAcceptance(index, { reason: event.target.value })} placeholder="Business reason and compensating controls" />
          <label htmlFor={`${formId}-expires-${index}`}>Expires</label><input id={`${formId}-expires-${index}`} className="expiry-input" type="datetime-local" required value={localDateTime(acceptance.expires_at)} onChange={event => changeAcceptance(index, { expires_at: event.target.value ? new Date(event.target.value).toISOString() : '' })} /><p className="field-help">Your local time.</p>
        </article>)}</div> : <div className="policy-empty">No active risk acceptances.</div>}
        <button type="button" className="button secondary add-acceptance" disabled={policy.acceptances.length >= 100} onClick={() => update({ acceptances: [...policy.acceptances, { asset_id: '', primitive_id: '', evidence_fingerprint: '', reason: '', expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() }] })}>Add acceptance</button>
      </section>
    </fieldset>
    <details className="advanced-policy"><summary>Policy configuration</summary><pre>{JSON.stringify(policy, null, 2)}</pre><p>Version {policy.version}</p></details>
    <p className="form-footnote">Saving requeues reports for assessment. Risk acceptance preserves the technical finding.</p>
  </div>
}
