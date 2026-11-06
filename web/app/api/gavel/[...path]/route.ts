import { NextRequest, NextResponse } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const REQUEST_LIMIT = 128 * 1024
const RESPONSE_LIMIT = 2 * 1024 * 1024
const ID = '[A-Za-z0-9_-]{8,128}'
const ROUTES: Record<string, RegExp[]> = {
  GET: [
    /^program$/,
    new RegExp(`^reports/${ID}$`),
    /^admin\/(graph|reports|policy|outbox)$/,
    new RegExp(`^admin/reports/${ID}$`),
  ],
  POST: [/^reports$/, new RegExp(`^admin/reports/${ID}/(reevaluate|approve)$`)],
  PUT: [/^admin\/policy$/],
}

class BodyLimitError extends Error {}

async function readBounded(body: ReadableStream<Uint8Array> | null, limit: number, signal: AbortSignal): Promise<Uint8Array> {
  if (!body) return new Uint8Array()
  const reader = body.getReader()
  const parts: Uint8Array[] = []
  let length = 0
  const abort = () => { void reader.cancel().catch(() => undefined) }
  signal.addEventListener('abort', abort, { once: true })
  try {
    while (true) {
      signal.throwIfAborted()
      const { done, value } = await reader.read()
      signal.throwIfAborted()
      if (done) break
      length += value.byteLength
      if (length > limit) {
        await reader.cancel()
        throw new BodyLimitError('Request too large')
      }
      parts.push(value)
    }
  } finally {
    signal.removeEventListener('abort', abort)
    reader.releaseLock()
  }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const part of parts) {
    bytes.set(part, offset)
    offset += part.byteLength
  }
  return bytes
}

function response(data: unknown, status = 200) {
  return NextResponse.json(data, {
    status,
    headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  })
}

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params
  const endpoint = path.join('/')
  if (!ROUTES[request.method]?.some(pattern => pattern.test(endpoint)) || request.nextUrl.search) {
    return response({ error: 'Endpoint not available' }, 404)
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 20_000)
  try {
    // Destination is deployment configuration, never a request field or header.
    const backend = new URL(process.env.GAVEL_BACKEND_URL || 'http://127.0.0.1:8080')
    if (!['http:', 'https:'].includes(backend.protocol) || backend.username || backend.password || backend.search || backend.hash || backend.pathname !== '/') {
      return response({ error: 'Gavel service configuration is invalid' }, 503)
    }
    const headers: Record<string, string> = { Accept: 'application/json' }
    const authorization = request.headers.get('authorization')
    if (authorization) {
      if (!/^Bearer [A-Za-z0-9._~+\/-]{1,512}={0,2}$/.test(authorization)) {
        return response({ error: 'Invalid access token' }, 401)
      }
      headers.Authorization = authorization
    }
    let body: string | undefined
    if (request.method !== 'GET') {
      if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
        return response({ error: 'Send a JSON request' }, 415)
      }
      const length = request.headers.get('content-length')
      if (length && (!/^\d+$/.test(length) || Number(length) > REQUEST_LIMIT)) {
        return response({ error: 'Request exceeds 128 KiB' }, 413)
      }
      const bytes = await readBounded(request.body, REQUEST_LIMIT, controller.signal)
      body = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      try { JSON.parse(body) } catch { return response({ error: 'Invalid JSON request' }, 400) }
      headers['Content-Type'] = 'application/json'
    }
    const upstream = await fetch(new URL(`/v1/${endpoint}`, backend), {
      method: request.method,
      headers,
      body,
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
    })
    // Reconstruct JSON rather than forwarding framing, cookies, or upstream headers.
    if (!upstream.headers.get('content-type')?.includes('application/json')) {
      await upstream.body?.cancel()
      return response({ error: 'Gavel service returned an unexpected response' }, 502)
    }
    const bytes = await readBounded(upstream.body, endpoint === 'admin/graph' ? 16 * 1024 * 1024 : RESPONSE_LIMIT, controller.signal)
    const data: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return response(data, upstream.status)
  } catch (error) {
    if (error instanceof BodyLimitError) return response({ error: 'Request or response exceeds the size limit' }, 413)
    if (error instanceof TypeError && error.message.includes('encoded data')) return response({ error: 'Invalid text encoding' }, 400)
    return response({ error: 'Gavel service is unavailable. Check that the self-hosted service is running.' }, 503)
  } finally {
    clearTimeout(timer)
  }
}

export { proxy as GET, proxy as POST, proxy as PUT }
