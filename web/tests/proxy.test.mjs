import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { after, before, test } from 'node:test'

let upstream, next, base
let lastRequest = null
let mode = 'normal'
let buildOutput = ''
const listen = async server => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port }

before(async () => {
  upstream = createServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    lastRequest = { url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString() }
    if (mode === 'redirect') { response.writeHead(302, { Location: 'http://127.0.0.1:1/private' }); response.end(); return }
    if (mode === 'oversized') { response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify({ payload: 'x'.repeat(2 * 1024 * 1024) })); return }
    response.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'private=secret', 'X-Upstream-Secret': 'hidden' })
    response.end(JSON.stringify({ ok: true, path: request.url }))
  })
  const upstreamPort = await listen(upstream)
  const temporary = createServer()
  const port = await listen(temporary)
  await new Promise(resolve => temporary.close(resolve))
  base = `http://127.0.0.1:${port}`
  next = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '--hostname', '127.0.0.1', '--port', String(port)], {
    env: { ...process.env, GAVEL_BACKEND_URL: `http://127.0.0.1:${upstreamPort}`, NEXT_TELEMETRY_DISABLED: '1' }, stdio: ['ignore', 'pipe', 'pipe'],
  })
  next.stdout.on('data', chunk => { buildOutput += chunk })
  next.stderr.on('data', chunk => { buildOutput += chunk })
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    if (next.exitCode !== null) throw new Error(`Next server exited: ${buildOutput}`)
    try { if ((await fetch(`${base}/api/gavel/program`)).ok) return } catch {}
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error(`Next server did not start: ${buildOutput}`)
}, { timeout: 25_000 })

after(async () => {
  if (next?.exitCode === null) { next.kill('SIGTERM'); await once(next, 'exit') }
  if (upstream) { upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve)) }
})

test('allows only configured API paths and rejects request-controlled destinations', async () => {
  const response = await fetch(`${base}/api/gavel/program`)
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { ok: true, path: '/v1/program' })
  for (const path of ['admin/secrets', 'program?url=http://127.0.0.1', 'http://attacker.test', 'reports/short']) {
    assert.equal((await fetch(`${base}/api/gavel/${path}`)).status, 404, path)
  }
})

test('forwards explicit authorization but strips cookies and all upstream framing headers', async () => {
  const response = await fetch(`${base}/api/gavel/admin/reports`, { headers: { Authorization: 'Bearer operator-test_123', Cookie: 'session=private', 'X-Forwarded-Host': 'attacker.test' } })
  assert.equal(response.status, 200)
  assert.equal(lastRequest.headers.authorization, 'Bearer operator-test_123')
  assert.equal(lastRequest.headers.cookie, undefined)
  assert.notEqual(lastRequest.headers['x-forwarded-host'], 'attacker.test')
  assert.equal(response.headers.get('set-cookie'), null)
  assert.equal(response.headers.get('x-upstream-secret'), null)
  assert.equal(response.headers.get('cache-control'), 'no-store')
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff')
})

test('enforces content type, valid JSON, token format, and the byte limit before forwarding', async () => {
  const options = { method: 'POST', headers: { 'Content-Type': 'application/json' } }
  assert.equal((await fetch(`${base}/api/gavel/reports`, { ...options, body: '{broken' })).status, 400)
  assert.equal((await fetch(`${base}/api/gavel/reports`, { method: 'POST', body: '{}' })).status, 415)
  assert.equal((await fetch(`${base}/api/gavel/reports`, { ...options, body: JSON.stringify({ description: 'x'.repeat(128 * 1024) }) })).status, 413)
  assert.equal((await fetch(`${base}/api/gavel/program`, { headers: { Authorization: 'Basic private' } })).status, 401)
  const payload = { title: 'A valid JSON report', description: 'The complete evidence', asset_id: 'public-api' }
  const response = await fetch(`${base}/api/gavel/reports`, { ...options, body: JSON.stringify(payload) })
  assert.equal(response.status, 200)
  assert.deepEqual(JSON.parse(lastRequest.body), payload)
})

test('bounds chunked request bodies even without a Content-Length header', async () => {
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(70 * 1024)); controller.enqueue(new Uint8Array(70 * 1024)); controller.close() } })
  const response = await fetch(`${base}/api/gavel/reports`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: stream, duplex: 'half' })
  assert.equal(response.status, 413)
})

test('refuses upstream redirects and bounds upstream response bodies', async () => {
  mode = 'redirect'
  assert.equal((await fetch(`${base}/api/gavel/program`)).status, 503)
  mode = 'oversized'
  assert.equal((await fetch(`${base}/api/gavel/program`)).status, 413)
  mode = 'normal'
})

test('retires the legacy shell and upload endpoint', async () => {
  const response = await fetch(`${base}/api/verify`, { method: 'POST', body: 'untrusted arbitrary upload' })
  assert.equal(response.status, 410)
})
