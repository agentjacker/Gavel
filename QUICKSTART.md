# Run Gavel locally

Install Python 3.12+ and Node.js 22+, then open two terminals in the Gavel project folder.

## Terminal 1: start the service

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp gavel.config.example.json gavel.config.json
export GAVEL_ADMIN_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))')"
printf '%s\n' "$GAVEL_ADMIN_TOKEN"
.venv/bin/python -m gavel.server --config gavel.config.json
```

Use the printed operator token to open the company console.
The service runs at `http://127.0.0.1:8080`.

## Terminal 2: start the website

```sh
cd web
npm ci
npm run dev
```

Open [localhost:3000](http://localhost:3000), submit an example report, then open the company console with your operator token to review it.
The example uses demo code and infrastructure; replace those inputs before handling company reports.

## Connect AI and notifications

The default configuration has no AI model or notification destinations, so reports require security team review and no Slack or Jira messages are sent.
Configure your model, company context, and delivery destinations in `gavel.config.json`; see the [architecture guide](docs/architecture.md#models-and-delivery) and [example configuration](gavel.config.example.json).
