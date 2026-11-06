# Gavel examples

The v2 demo pairs [a deliberately unsafe source file](demo-app/service.py) with [an illustrative topology manifest](topology.json). Gavel indexes the source as text; it does not run this file, execute submitted payloads, or establish that the example is deployed anywhere.

## Try the contextual workflow

1. Follow the [local setup](../README.md#run-locally) using `gavel.config.example.json`.
2. Open [the local web workspace](http://localhost:3000) and choose the researcher portal.
3. Select **Customer API (demo)** and submit a report such as:

   ```text
   Title: SQL query construction in lookup_customer

   service.py:lookup_customer concatenates customer_id into the SQL string
   passed to database.execute. If customer_id is controlled by an attacker,
   this can change the query rather than bind a literal customer ID.

   Please assess the code evidence and prerequisites. The source alone does
   not establish a reachable HTTP route, the database driver's behavior,
   or the database permissions in a real deployment.
   ```

4. Save the returned report ID and private receipt token. Use them to check status and the safe public outcome.
5. Open the operator workspace with `GAVEL_ADMIN_TOKEN` to inspect the private assessment, evidence, prerequisites, owner and paths.

The default example has no AI provider or notification destinations. Intake still works, and analysis requires review until a model is configured. With a configured model, source support is a static hypothesis rather than a promised fixed verdict. The topology's conditional database relationship and blocked billing path are company declarations for demonstration; replace them with evidence from the actual deployment. The default policy does not designate any protected assets or enable automatic routing.

After editing the demo source or topology, call the operator `POST /v1/admin/sync` endpoint. Changed hashes update the saved context, invalidate previous decisions and queue new assessments. Unchanged file contents are retained. See [configuration and API usage](../README.md) and the [architecture](../docs/architecture.md).

## Historical report fixtures

These files were created for the original one-shot verifier. Their filenames describe historical examples, not authoritative verdicts. Several refer to code that is absent from the demo repository.

| File | What it exercises | Correct interpretation |
| --- | --- | --- |
| `legitimate-report.md` | Detailed PHP authentication claim with a payload and proposed fix. | Verify against the actual referenced implementation. Formatting and a claim of prior testing do not establish validity; the PHP file is not part of this demo. |
| `sample-sql-injection.txt` | SQL injection report structure and code references. | Check the specific source and attacker prerequisites; do not assume it describes the demo service. |
| `sample-invalid-report.txt` | An underspecified XSS hypothesis. | Missing evidence requires review. A vague report is not proof that the claimed bug is absent. |
| `test-prompt-injection.txt` | Instructions that try to force a model verdict. | Treat the payload as untrusted data. It cannot change policy, context, destinations or public output; matching an injection phrase alone is not grounds to reject a vulnerability. |
| `test-system-extraction.html` | HTML text containing attempts to extract model instructions. | Treat the content as data and preserve the private/public boundary. The v2 HTTP intake accepts JSON text fields, not HTML/file uploads. |

AI-assisted reports are welcome. AI authorship, confident wording, hedging, template style and the presence of attack strings do not determine technical validity. Reports about prompt injection often need to quote the exact malicious instructions being reported.

The compatibility CLI can read text, Markdown and HTML fixtures:

```sh
.venv/bin/python -m gavel.cli \
  --report examples/legitimate-report.md \
  --codebase /path/to/the/referenced/repository \
  --format json
```

The CLI is separate from the persistent contextual service. Its `NEEDS_REVIEW` result covers insufficient context and unusable model output. Use the v2 intake for organization policies, saved topology, conditional chains and delivery approval. The old web `/api/verify` endpoint is retired.

## Adding useful examples

Include matching source fixtures, explicit deployment assumptions, expected evidence and unresolved prerequisites. Add cases for refuted claims, contained primitives, newly enabled chains and accepted risks that become material after a change. Keep reports anonymized and avoid real credentials. Expected behavior should describe evidence and policy boundaries rather than require a model to emit a particular verdict because of writing style.

The [threat model](../docs/threat-model.md) describes prompt-injection boundaries, safe source ingestion and remaining limitations. Automated invariants belong in the [test suite](../tests), not in assertions that a particular model will always interpret a prose fixture correctly.
