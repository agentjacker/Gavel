# Gavel security workspace

The web app is a browser interface for the self-hosted Python service. It has a company workspace for private triage and a researcher portal for submissions and receipt-based status checks.

## Run

Start the Python service using the root repository instructions, then:

```sh
cd web
npm ci
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000. Set `GAVEL_BACKEND_URL` to the service's private address in `.env.local`; the default is `http://127.0.0.1:8080`. This setting stays on the web server. Model keys belong on the Python service, never in a `NEXT_PUBLIC_` variable.

Use the operator token configured on the service to open the company workspace. It is held only in the current tab's React memory; locking or reloading the workspace clears it. Researcher submission tokens and receipt tokens are separate credentials. Receipt tokens grant access to only the associated submission's public status. Save the private receipt after submitting; the app does not persist it.

The organization inventory displays source-backed code context and administrator-declared topology. Import repositories and topology manifests through the trusted service administration workflow. The researcher endpoint cannot choose a repository, upload code, or control internal paths.

The risk policy form lets operators select critical company assets, choose a context freshness limit, turn automatic owner routing on or off, and record expiring risk acceptances. Each acceptance names an asset and finding primitive, binds its evidence fingerprint, records a business reason, and sets an expiry in the browser’s local time. Choosing a known primitive fills its fingerprint automatically. Changed cited evidence invalidates the acceptance. Re-evaluate findings after policy updates to see the current decision. A collapsed advanced view shows the saved configuration for inspection.

## Deployment

```sh
npm run build
npm start
```

Deploy the app behind TLS and point `GAVEL_BACKEND_URL` at the service on a private network. Do not expose development mode publicly. Keep the backend's operator token private; do not put it in the web environment. The web app forwards explicit bearer credentials from the current request and never forwards browser cookies.

The API proxy allows only the documented public and operator routes. It accepts JSON bodies up to 128 KiB, enforces the limit while streaming, rejects redirects, and reconstructs bounded JSON responses without forwarding upstream headers or cookies. The retired `/api/verify` endpoint returns `410 Gone`. Arbitrary uploads, cloning, shell execution, and direct model calls are removed from web intake.

## Verification

```sh
npm run build
npm run lint
npm test
```

Proxy integration tests run the built app against a local fake service. They cover path allowlisting, bearer/cookie isolation, request byte limits including chunked bodies, invalid JSON, response limits, redirects, and retirement of the legacy endpoint.

Framework: Next.js 15.5.29 with React 18.3.1. The November 3, 2026 [Next.js advisory](https://github.com/vercel/next.js/security/advisories/GHSA-pc58-hwjq-p385) lists 15.5.29 as patched for fetched-response framing disclosure.
