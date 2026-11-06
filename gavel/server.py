"""Self-hosted, single-organization API with durable triage and private evidence."""

import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web

from gavel.context import ContextGraph
from gavel.integrations import dispatch_one, validate_destinations
from gavel.store import Store
from gavel.triage import analyze_with_model, decide, unknown_analysis


LOG = logging.getLogger("gavel.server")
MAX_BODY = 128 * 1024


def load_config(path):
    config_path = Path(path).resolve()
    config = json.loads(config_path.read_text())
    config["_directory"] = str(config_path.parent)
    return config


def resolve_config_path(config, path):
    root = Path(config.get("_directory", ".")).resolve()
    value = Path(path)
    return (
        str((root / value).resolve())
        if not value.is_absolute()
        else str(value.resolve())
    )


def validate_config(config):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", config.get("organization_id", "")):
        raise ValueError("Configure a stable organization_id")
    token = os.environ.get(config.get("admin_token_env", "GAVEL_ADMIN_TOKEN"), "")
    if len(token) < 32:
        raise ValueError(
            "Set the configured admin token environment variable to at least 32 random characters"
        )
    submission_env = config.get("submission_token_env")
    if submission_env and len(os.environ.get(submission_env, "")) < 32:
        raise ValueError(
            "Configured submission tokens must have at least 32 random characters"
        )
    if submission_env and secrets.compare_digest(token, os.environ[submission_env]):
        raise ValueError("Admin and researcher tokens must differ")
    model = dict(config.get("model", {}))
    if model:
        url = urlsplit(model.get("base_url", ""))
        if (
            url.scheme not in ("http", "https")
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "Model base_url must be an HTTP(S) API endpoint without credentials"
            )
        if model.get("data_boundary") not in ("on_premises", "external"):
            raise ValueError(
                "Declare the model data_boundary as on_premises or external"
            )
        if model["data_boundary"] == "external":
            if (
                os.environ.get("GAVEL_ALLOW_EXTERNAL_AI") != "true"
                or url.scheme != "https"
            ):
                raise ValueError(
                    "External models require HTTPS and GAVEL_ALLOW_EXTERNAL_AI=true"
                )
        if not model.get("model"):
            raise ValueError("Configure the deployment's model identifier")
        model["api_key"] = os.environ.get(
            model.get("api_key_env", "GAVEL_MODEL_API_KEY"), ""
        )
    validate_destinations(config.get("destinations", {}))
    return token, os.environ.get(submission_env, "") if submission_env else "", model


def sync_context(config, graph):
    before = graph.snapshot()["revision"]
    summaries = []
    for repository in config.get("repositories", []):
        summaries.append(
            graph.sync_repository(
                repository["id"],
                resolve_config_path(config, repository["path"]),
                repository.get("revision", "working-tree"),
            )
        )
    if config.get("topology_file"):
        topology = json.loads(
            Path(resolve_config_path(config, config["topology_file"])).read_text()
        )
        summaries.append(
            graph.replace_topology(
                topology.get("source_id", "deployment"),
                topology["nodes"],
                topology["edges"],
                topology.get("revision", "declared"),
            )
        )
    return {
        "changed": graph.snapshot()["revision"] != before,
        "sources": summaries,
        "revision": graph.snapshot()["revision"],
    }


class Engine:
    def __init__(self, store, graph, model, destinations, analyzer=analyze_with_model):
        self.store, self.graph, self.model = store, graph, model
        self.destinations, self.analyzer = destinations, analyzer

    def process_one(self):
        report = self.store.claim()
        if not report:
            return False
        graph = self.graph.snapshot()
        context = self.graph.context_for([report["asset_id"]])
        if context["revision"] != graph["revision"]:
            self.store.requeue(report["id"])
            return True
        try:
            analysis = self.analyzer(report, context, self.model)
        except Exception:
            # Never turn provider errors, schema failures, missing code or injections into INVALID.
            analysis = unknown_analysis(
                "Model analysis failed or returned unverifiable evidence; operator review is required"
            )
        if context.get("truncated"):
            analysis["missing_evidence"].append("Retrieved context was truncated")
        decision = decide(
            report, analysis, graph, self.store.policy(), self.store.decisions()
        )
        if self.graph.snapshot()["revision"] != graph["revision"]:
            self.store.requeue(report["id"])
            return True
        if self.store.finish(report["id"], report["generation"], decision):
            self.refresh_chains()
        return True

    def refresh_chains(self):
        graph, policy, peers = (
            self.graph.snapshot(),
            self.store.policy(),
            self.store.decisions(),
        )
        for report in peers:
            previous = report.get("decision")
            if not previous or previous["graph_revision"] != graph["revision"]:
                continue
            updated = decide(report, previous["analysis"], graph, policy, peers)
            with self.store.connect() as db:
                if any(
                    previous.get(key) != updated.get(key)
                    for key in (
                        "priority",
                        "disposition",
                        "capabilities_gained",
                        "missing_evidence",
                        "attack_paths",
                    )
                ):
                    db.execute(
                        "UPDATE outbox SET state='cancelled' WHERE organization_id=? AND report_id=? AND state IN ('pending','failed')",
                        (self.store.organization_id, report["id"]),
                    )
                db.execute(
                    "UPDATE reports SET decision=? WHERE organization_id=? AND id=? AND generation=? AND decision IS NOT NULL",
                    (
                        json.dumps(updated),
                        self.store.organization_id,
                        report["id"],
                        report["generation"],
                    ),
                )
                if updated["validity"] != "supported" or updated["disposition"] not in (
                    "fix",
                    "monitor",
                ):
                    db.execute(
                        "UPDATE outbox SET state='cancelled' WHERE organization_id=? AND report_id=? AND state IN ('pending','failed')",
                        (self.store.organization_id, report["id"]),
                    )
            if (
                policy["auto_route"]
                and updated["validity"] == "supported"
                and updated["disposition"] in ("fix", "monitor")
            ):
                for destination in self.destinations:
                    self.store.enqueue_delivery(report["id"], destination)


def bearer(request):
    value = request.headers.get("Authorization", "")
    return value[7:] if value.startswith("Bearer ") and len(value) < 1024 else ""


def create_app(config, *, analyzer=analyze_with_model, background=True):
    admin_token, submission_token, model = validate_config(config)
    database = resolve_config_path(config, config.get("database", "data/gavel.db"))
    store, graph = Store(database, config["organization_id"]), ContextGraph(
        database, config["organization_id"]
    )
    engine = Engine(store, graph, model, config.get("destinations", {}), analyzer)
    rate = {}
    mutation_lock = asyncio.Lock()

    def guard(request):
        if request.path.startswith("/v1/admin/") and not secrets.compare_digest(
            bearer(request), admin_token
        ):
            raise web.HTTPUnauthorized(
                text='{"error":"Operator authentication required"}',
                content_type="application/json",
            )
        if request.method == "POST" and request.path == "/v1/reports":
            if submission_token and not secrets.compare_digest(
                bearer(request), submission_token
            ):
                raise web.HTTPUnauthorized(
                    text='{"error":"Submission authentication required"}',
                    content_type="application/json",
                )
            # Only the socket peer is trusted. Never trust attacker-provided forwarded IP headers.
            # A reverse proxy should additionally apply its own per-client limits.
            key = request.remote or "unknown"
            current = time.monotonic()
            entry = rate.get(key, (current, 0))
            if current - entry[0] >= 60:
                entry = (current, 0)
            if entry[1] >= 10:
                raise web.HTTPTooManyRequests(headers={"Retry-After": "60"})
            if len(rate) >= 10000 and key not in rate:
                rate.clear()
            rate[key] = (entry[0], entry[1] + 1)

    @web.middleware
    async def boundaries(request, handler):
        try:
            guard(request)
            response = await handler(request)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            response = web.json_response(
                {"error": "Invalid request or configuration"}, status=400
            )
        except OverflowError:
            response = web.json_response(
                {"error": "The submission queue is full; retry later"}, status=503
            )
        except web.HTTPException as error:
            headers = (
                {"Retry-After": error.headers["Retry-After"]}
                if "Retry-After" in error.headers
                else {}
            )
            response = web.json_response(
                {"error": error.reason}, status=error.status, headers=headers
            )
        except Exception:
            LOG.error("Request failed: %s %s", request.method, request.path)
            response = web.json_response(
                {"error": "Request could not be completed"}, status=500
            )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app = web.Application(client_max_size=MAX_BODY, middlewares=[boundaries])
    app["store"], app["graph"], app["engine"] = store, graph, engine

    async def body(request):
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        value = await request.json()
        if not isinstance(value, dict):
            raise ValueError("Expected JSON object")
        return value

    async def program(request):
        assets = [
            {"id": n["id"], "name": n.get("name", n["id"])}
            for n in graph.snapshot()["nodes"]
            if n.get("reportable") is True
        ]
        return web.json_response(
            {
                "organization_id": config["organization_id"],
                "name": config.get("name", "Gavel"),
                "assets": assets,
                "submission_auth_required": bool(submission_token),
            }
        )

    async def submit(request):
        data = await body(request)
        if set(data) != {"title", "description", "asset_id"}:
            raise ValueError("Unexpected report fields")
        for key, maximum in (("title", 240), ("description", 80000), ("asset_id", 240)):
            if (
                not isinstance(data[key], str)
                or not 1 <= len(data[key].strip()) <= maximum
                or "\x00" in data[key]
            ):
                raise ValueError("Invalid report field")
        if not any(
            n["id"] == data["asset_id"] and n.get("reportable") is True
            for n in graph.snapshot()["nodes"]
        ):
            raise ValueError("Asset is not in the disclosure program")
        return web.json_response(
            store.submit(data["title"].strip(), data["description"], data["asset_id"]),
            status=202,
        )

    async def receipt(request):
        result = store.public_report(request.match_info["id"], bearer(request))
        if result is None:
            raise web.HTTPNotFound()
        return web.json_response(result)

    async def admin_graph(request):
        return web.json_response(graph.snapshot())

    async def reports(request):
        return web.json_response(store.inbox())

    async def report(request):
        result = store.report(request.match_info["id"])
        if not result:
            raise web.HTTPNotFound()
        return web.json_response(result)

    async def reevaluate(request):
        report_id = request.match_info["id"]
        async with mutation_lock:
            if not store.requeue(report_id):
                raise web.HTTPNotFound()
            await asyncio.to_thread(engine.refresh_chains)
        return web.json_response({"id": report_id, "status": "queued"})

    async def approve(request):
        async with mutation_lock:
            report_id = request.match_info["id"]
            # Freshness and acceptance expiry change without graph revisions.
            # Re-evaluate saved evidence before authorizing an outbound event.
            await asyncio.to_thread(engine.refresh_chains)
            result = store.report(report_id)
            if not result:
                raise web.HTTPNotFound()
            if (
                not result["decision"]
                or result["decision"]["graph_revision"] != graph.snapshot()["revision"]
            ):
                raise ValueError("Re-evaluate against current graph first")
            if not config.get("destinations"):
                return web.json_response(
                    {"error": "No delivery destinations are configured"}, status=409
                )
            events = [
                store.enqueue_delivery(report_id, target)
                for target in config["destinations"]
            ]
            return web.json_response(
                {"id": report_id, "status": "routed", "events": events}, status=202
            )

    async def policy(request):
        if request.method == "GET":
            return web.json_response(store.policy())
        async with mutation_lock:
            return web.json_response(store.save_policy(await body(request)))

    async def sync(request):
        async with mutation_lock:
            result = await asyncio.to_thread(sync_context, config, graph)
            if result["changed"]:
                store.requeue()
            return web.json_response(result)

    async def topology(request):
        data = await body(request)
        if set(data) != {"source_id", "nodes", "edges", "revision"}:
            raise ValueError("Invalid topology update")
        async with mutation_lock:
            before = graph.snapshot()["revision"]
            result = await asyncio.to_thread(
                graph.replace_topology,
                data["source_id"],
                data["nodes"],
                data["edges"],
                data["revision"],
            )
            if graph.snapshot()["revision"] != before:
                store.requeue()
            return web.json_response(result)

    async def delete_source(request):
        async with mutation_lock:
            result = graph.delete_source(request.match_info["source_id"])
            store.requeue()
            return web.json_response(result)

    async def outbox(request):
        return web.json_response({"events": store.outbox()})

    async def audit(request):
        return web.json_response({"events": store.audit()})

    async def health(request):
        return web.json_response({"status": "ok"})

    app.add_routes(
        [
            web.get("/healthz", health),
            web.get("/v1/program", program),
            web.post("/v1/reports", submit),
            web.get("/v1/reports/{id:[a-f0-9]{32}}", receipt),
            web.get("/v1/admin/graph", admin_graph),
            web.get("/v1/admin/reports", reports),
            web.get("/v1/admin/reports/{id:[a-f0-9]{32}}", report),
            web.post("/v1/admin/reports/{id:[a-f0-9]{32}}/reevaluate", reevaluate),
            web.post("/v1/admin/reports/{id:[a-f0-9]{32}}/approve", approve),
            web.get("/v1/admin/policy", policy),
            web.put("/v1/admin/policy", policy),
            web.post("/v1/admin/sync", sync),
            web.put("/v1/admin/topology", topology),
            web.delete("/v1/admin/sources/{source_id}", delete_source),
            web.get("/v1/admin/outbox", outbox),
            web.get("/v1/admin/audit", audit),
        ]
    )

    async def lifecycle(application):
        store.recover()
        result = await asyncio.to_thread(sync_context, config, graph)
        if result["changed"]:
            store.requeue()
        stopping = asyncio.Event()

        async def worker():
            last_refresh = 0
            while not stopping.is_set():
                try:
                    async with mutation_lock:
                        processed = await asyncio.to_thread(engine.process_one)
                        if time.monotonic() - last_refresh >= 60:
                            await asyncio.to_thread(engine.refresh_chains)
                            last_refresh = time.monotonic()
                        await asyncio.to_thread(
                            dispatch_one,
                            store,
                            config.get("destinations", {}),
                            graph.snapshot()["revision"],
                        )
                except Exception:
                    LOG.error("Worker failed; operator attention is required")
                    processed = False
                await asyncio.sleep(0.05 if processed else 1)

        task = asyncio.create_task(worker()) if background else None
        yield
        if task:
            # Let the current bounded model/delivery call finish before closing
            # the graph. Cancelling to_thread would leave a live writer behind.
            stopping.set()
            await task
        graph.close()

    app.cleanup_ctx.append(lifecycle)
    return app


def main():
    parser = argparse.ArgumentParser(description="Gavel contextual triage service")
    parser.add_argument("--config", default="gavel.config.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    web.run_app(
        create_app(load_config(args.config)),
        host=args.host,
        port=args.port,
        access_log=None,
    )


if __name__ == "__main__":
    main()
