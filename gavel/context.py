"""Persistent, source-owned organization context without executing repository code.

Python definitions and directly resolved intra-file calls are static syntax facts,
never claims of runtime reachability. Administrators contribute deployment topology
independently, including ``code_paths`` that bind services to repository-relative
paths. Absence of an edge is not a control.
"""

import ast
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Dict, List


MAX_FILES = 3000
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
MAX_ENTRIES = 30000
MAX_TOPOLOGY_NODES = 5000
MAX_TOPOLOGY_EDGES = 15000
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_CHARS = 200000
EXTRACTOR_VERSION = "python-ast-v1"
MAX_AST_NODES = 12000
MAX_AST_SECONDS = 0.5
MAX_FILE_SYMBOLS = 200
MAX_FILE_CODE_EDGES = 600
MAX_SOURCE_CODE_OBJECTS = 25000
MAX_SOURCE_AST_SECONDS = 5

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".ssh",
    ".aws",
    ".azure",
    ".gcp",
    ".gnupg",
    ".codex",
    ".agents",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".next",
    "dist",
    "build",
    "target",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    ".terraform",
    ".idea",
    ".vscode",
}
SKIP_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "credentials",
    "authorized_keys",
    "known_hosts",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "terraform.tfstate",
    "terraform.tfstate.backup",
}
SKIP_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.tfstate*",
    "*secret*",
    "*credential*",
    "*.min.js",
    "*.map",
    "*.sqlite*",
    "*.db",
)
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".swift",
    ".kt",
    ".scala",
    ".sol",
    ".vy",
    ".sh",
    ".bash",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".conf",
    ".cfg",
    ".tf",
    ".hcl",
    ".sql",
    ".xml",
    ".graphql",
    ".proto",
    ".dockerfile",
    ".md",
}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$")


def _json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid %s" % label)
    return value


def _revision(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("A bounded, nonempty source revision is required")
    return value


def _safe_relative(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError("Invalid repository-relative code path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Code paths must remain relative to the repository")
    return path.as_posix()


def _serialized(method):
    """Keep each connection operation and its complete transaction together."""

    @wraps(method)
    def operation(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return operation


def _python_graph(file: Dict) -> Dict:
    """Extract bounded lexical call candidates without importing any source.

    Only bare-name calls to uniquely defined same-file symbols are resolved.
    Attribute dispatch, imports, shadowed names and dynamic rebinding remain
    unresolved. Even a resolved lexical reference is not execution evidence.
    """
    if file["language"] != "py":
        return {"nodes": [], "edges": [], "parse_status": "unsupported_language"}
    started = time.monotonic()
    try:
        tree = ast.parse(file["content"], filename=file["path"], mode="exec")
        count = 0
        for _ in ast.walk(tree):
            count += 1
            if count > MAX_AST_NODES or time.monotonic() - started > MAX_AST_SECONDS:
                return {"nodes": [], "edges": [], "parse_status": "ast_budget_exceeded"}
    except SyntaxError:
        return {"nodes": [], "edges": [], "parse_status": "syntax_error"}
    except (ValueError, RecursionError, MemoryError):
        return {"nodes": [], "edges": [], "parse_status": "parser_resource_limit"}

    nodes, edges, calls = [], [], []
    scopes = {
        file["id"]: {
            "parent": None,
            "kind": "module",
            "bindings": {},
            "uncertain": set(),
            "qualified": "",
        }
    }

    def bind(scope, name, target=None):
        scopes[scope]["bindings"].setdefault(name, []).append(target)

    def provenance(start, end):
        return {
            "id": file["id"] + "@" + file["content_hash"],
            "path": file["path"],
            "content_hash": file["content_hash"],
            "source_id": file["source_id"],
            "start_line": start,
            "end_line": end,
        }

    pending = [(tree, file["id"])]
    while pending:
        item, scope = pending.pop()
        if time.monotonic() - started > MAX_AST_SECONDS:
            return {"nodes": [], "edges": [], "parse_status": "ast_budget_exceeded"}
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if len(nodes) >= MAX_FILE_SYMBOLS or len(item.name) > 240:
                return {
                    "nodes": [],
                    "edges": [],
                    "parse_status": "symbol_budget_exceeded",
                }
            symbol_id = file["id"] + "::symbol:" + str(item.lineno) + ":" + item.name
            qualified = (scopes[scope]["qualified"] + "." + item.name).lstrip(".")
            symbol_kind = (
                "class"
                if isinstance(item, ast.ClassDef)
                else (
                    "async_function"
                    if isinstance(item, ast.AsyncFunctionDef)
                    else "function"
                )
            )
            bind(scope, item.name, symbol_id)
            nodes.append(
                {
                    "id": symbol_id,
                    "kind": "symbol",
                    "name": qualified,
                    "symbol_kind": symbol_kind,
                    "path": file["path"],
                    "file_id": file["id"],
                    "source_id": file["source_id"],
                    "content_hash": file["content_hash"],
                    "collector": EXTRACTOR_VERSION,
                    "semantics": "definition_syntax",
                    "runtime_reachability": "unknown",
                    "evidence": provenance(
                        item.lineno, getattr(item, "end_lineno", item.lineno)
                    ),
                }
            )
            edges.append(
                {
                    "id": symbol_id + "::definition",
                    "source": file["id"],
                    "target": symbol_id,
                    "kind": "code_defines",
                    "state": "observed",
                    "source_id": file["source_id"],
                    "file_id": file["id"],
                    "requires": [],
                    "provides": [],
                    "semantics": "definition_syntax",
                    "runtime_reachability": "unknown",
                    "evidence": provenance(
                        item.lineno, getattr(item, "end_lineno", item.lineno)
                    ),
                }
            )
            scopes[symbol_id] = {
                "parent": scope,
                "kind": symbol_kind,
                "bindings": {},
                "uncertain": set(),
                "qualified": qualified,
            }
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = (
                    item.args.posonlyargs + item.args.args + item.args.kwonlyargs
                )
                parameters += [
                    value for value in (item.args.vararg, item.args.kwarg) if value
                ]
                for parameter in parameters:
                    bind(symbol_id, parameter.arg)
                outside_body = (
                    item.decorator_list
                    + item.args.defaults
                    + [value for value in item.args.kw_defaults if value]
                )
            else:
                outside_body = (
                    item.decorator_list
                    + item.bases
                    + [keyword.value for keyword in item.keywords]
                )
            # Assignment expressions in defaults/bases can rebind an enclosing
            # name. Do not mistake that name for a unique local definition.
            for expression in outside_body:
                for candidate in ast.walk(expression):
                    if isinstance(candidate, ast.Name) and isinstance(
                        candidate.ctx, (ast.Store, ast.Del)
                    ):
                        bind(scope, candidate.id)
            # Defaults, decorators and annotations execute in other contexts;
            # omit them instead of attributing those calls to this body.
            pending.extend((child, symbol_id) for child in reversed(item.body))
            continue
        if isinstance(
            item,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            continue  # separate/dynamic binding contexts are deliberately unsupported
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
            bind(scope, item.id)
        elif isinstance(item, (ast.Import, ast.ImportFrom)):
            for alias in item.names:
                if alias.name == "*":
                    scopes[scope]["uncertain"].add("*")
                bind(scope, alias.asname or alias.name.split(".")[0])
        elif isinstance(item, (ast.Global, ast.Nonlocal)):
            scopes[scope]["uncertain"].update(item.names)
        elif isinstance(item, ast.ExceptHandler) and item.name:
            bind(scope, item.name)
        elif type(item).__name__ in {"MatchAs", "MatchStar", "MatchMapping"}:
            captured = getattr(item, "name", None) or getattr(item, "rest", None)
            if captured:
                bind(scope, captured)
        if isinstance(item, ast.Call):
            calls.append((item, scope))
        pending.extend(
            (child, scope) for child in reversed(list(ast.iter_child_nodes(item)))
        )

    unresolved = 0
    for call, caller in calls:
        if time.monotonic() - started > MAX_AST_SECONDS:
            return {"nodes": [], "edges": [], "parse_status": "ast_budget_exceeded"}
        target = None
        name = call.func.id if isinstance(call.func, ast.Name) else None
        scope = caller
        while name and scope is not None:
            current = scopes[scope]
            if name in current["uncertain"] or "*" in current["uncertain"]:
                break
            bindings = current["bindings"].get(name)
            if bindings is not None:
                target = bindings[0] if len(bindings) == 1 else None
                break
            scope = current["parent"]
            # A class namespace is not an enclosing lexical scope for methods.
            while scope is not None and scopes[scope]["kind"] == "class":
                scope = scopes[scope]["parent"]
        if not target:
            unresolved += 1
            continue
        if len(edges) >= MAX_FILE_CODE_EDGES:
            return {"nodes": [], "edges": [], "parse_status": "edge_budget_exceeded"}
        edges.append(
            {
                "id": file["id"]
                + "::call:"
                + _digest([caller, target, call.lineno, call.col_offset]),
                "source": caller,
                "target": target,
                "kind": "code_call",
                "state": "unknown",
                "file_id": file["id"],
                "source_id": file["source_id"],
                "requires": [],
                "provides": [],
                "semantics": "unique_lexical_reference",
                "runtime_reachability": "unknown",
                "evidence": provenance(
                    call.lineno, getattr(call, "end_lineno", call.lineno)
                ),
            }
        )
    return {
        "nodes": nodes,
        "edges": edges,
        "parse_status": "parsed",
        "resolved_calls": len(edges) - len(nodes),
        "unresolved_calls": unresolved,
    }


class ContextGraph:
    """A tenant-isolated SQLite context graph safe to share between threads.

    Only trusted collector/admin code should invoke mutation methods. Reports and
    model output must never be passed to ``replace_topology`` as trusted facts.
    An instance serializes graph operations with a reentrant lock, including
    complete read snapshots. Model calls should happen outside graph operations.
    """

    def __init__(self, database_path: str, organization_id: str):
        self.organization_id = _identifier(organization_id, "organization ID")
        self.database_path = str(database_path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            self.database_path, timeout=30, check_same_thread=False
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS context_sources (
                organization_id TEXT NOT NULL, source_id TEXT NOT NULL,
                kind TEXT NOT NULL, revision TEXT NOT NULL, digest TEXT NOT NULL,
                metadata TEXT NOT NULL,
                PRIMARY KEY (organization_id, source_id)
            );
            CREATE TABLE IF NOT EXISTS context_nodes (
                organization_id TEXT NOT NULL, id TEXT NOT NULL, source_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (organization_id, id),
                FOREIGN KEY (organization_id, source_id)
                    REFERENCES context_sources(organization_id, source_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS context_nodes_source
                ON context_nodes(organization_id, source_id);
            CREATE TABLE IF NOT EXISTS context_edges (
                organization_id TEXT NOT NULL, id TEXT NOT NULL, source_id TEXT NOT NULL,
                source TEXT NOT NULL, target TEXT NOT NULL, payload TEXT NOT NULL,
                PRIMARY KEY (organization_id, id),
                FOREIGN KEY (organization_id, source_id)
                    REFERENCES context_sources(organization_id, source_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS context_files (
                organization_id TEXT NOT NULL, id TEXT NOT NULL, source_id TEXT NOT NULL,
                path TEXT NOT NULL, content_hash TEXT NOT NULL, content TEXT NOT NULL,
                PRIMARY KEY (organization_id, id),
                FOREIGN KEY (organization_id, source_id)
                    REFERENCES context_sources(organization_id, source_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS context_derivations (
                organization_id TEXT NOT NULL, id TEXT NOT NULL, source_id TEXT NOT NULL,
                file_id TEXT NOT NULL, object_kind TEXT NOT NULL, object_bytes INTEGER NOT NULL,
                PRIMARY KEY (organization_id, id, object_kind),
                FOREIGN KEY (organization_id, source_id)
                    REFERENCES context_sources(organization_id, source_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS context_derivations_file
                ON context_derivations(organization_id,source_id,file_id);
        """
        )
        columns = {
            row["name"]
            for row in self._db.execute("PRAGMA table_info(context_sources)")
        }
        if "synced_at" not in columns:
            self._db.execute("ALTER TABLE context_sources ADD COLUMN synced_at TEXT")
            self._db.commit()

    @_serialized
    def close(self) -> None:
        self._db.close()

    @contextmanager
    def _consistent_read(self):
        if self._db.in_transaction:
            yield
        else:
            with self._db:
                self._db.execute("BEGIN")
                yield

    def _source(self, source_id: str):
        return self._db.execute(
            "SELECT * FROM context_sources WHERE organization_id=? AND source_id=?",
            (self.organization_id, source_id),
        ).fetchone()

    def _assert_source_kind(self, source_id: str, kind: str) -> None:
        existing = self._source(source_id)
        if existing and existing["kind"] != kind:
            raise ValueError("A source ID cannot change collector kind")

    def _assert_ownership(self, table: str, ids: List[str], source_id: str) -> None:
        # table is an internal constant, never a caller-supplied SQL identifier.
        for item_id in ids:
            row = self._db.execute(
                "SELECT source_id FROM " + table + " WHERE organization_id=? AND id=?",
                (self.organization_id, item_id),
            ).fetchone()
            if row and row["source_id"] != source_id:
                raise ValueError(
                    "Graph ID is already owned by another source: " + item_id
                )

    def _put_source(
        self, source_id: str, kind: str, revision: str, digest: str, metadata: Dict
    ) -> None:
        self._db.execute(
            "INSERT INTO context_sources (organization_id,source_id,kind,revision,digest,metadata,synced_at) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(organization_id,source_id) DO UPDATE SET "
            "revision=excluded.revision,digest=excluded.digest,metadata=excluded.metadata,synced_at=excluded.synced_at",
            (
                self.organization_id,
                source_id,
                kind,
                revision,
                digest,
                _json(metadata),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    @_serialized
    def sync_repository(self, source_id: str, root: str, revision: str) -> Dict:
        """Hash bounded text files and replace only changed/deleted file facts.

        No shell, importer, build, archive extractor or network call is involved.
        An over-budget scan raises before changing the previous complete index.
        """
        source_id = _identifier(source_id, "source ID")
        revision = _revision(revision)
        repository = Path(root)
        if repository.is_symlink() or not repository.is_dir():
            raise ValueError("Repository root must be a real directory, not a symlink")
        repository = repository.resolve(strict=True)
        files = {}
        skipped = 0
        entries = 0
        total_bytes = 0

        def scan_error(error):
            raise ValueError(
                "Repository directory could not be read; previous index was preserved"
            ) from error

        for walk_root, dirs, names in os.walk(
            repository, followlinks=False, onerror=scan_error
        ):
            entries += len(dirs) + len(names)
            if entries > MAX_ENTRIES:
                raise ValueError(
                    "Repository entry budget exceeded; previous index was preserved"
                )
            dirs[:] = sorted(
                d
                for d in dirs
                if d not in SKIP_DIRS
                and not any(
                    fnmatch.fnmatch(d.lower(), pattern) for pattern in SKIP_PATTERNS
                )
                and not (Path(walk_root) / d).is_symlink()
            )
            for name in sorted(names):
                path = Path(walk_root) / name
                lowered = name.lower()
                if (
                    path.is_symlink()
                    or lowered in SKIP_NAMES
                    or any(fnmatch.fnmatch(lowered, p) for p in SKIP_PATTERNS)
                ):
                    skipped += 1
                    continue
                if path.suffix.lower() not in TEXT_SUFFIXES and lowered not in {
                    "dockerfile",
                    "containerfile",
                    "makefile",
                }:
                    skipped += 1
                    continue
                relative = path.relative_to(repository).as_posix()
                content = self._read_confined(repository, relative)
                if content is None:
                    skipped += 1
                    continue
                size = len(content.encode("utf-8"))
                total_bytes += size
                if len(files) >= MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError(
                        "Repository text budget exceeded; previous index was preserved"
                    )
                file_id = source_id + ":" + relative
                content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                files[file_id] = {
                    "id": file_id,
                    "kind": "file",
                    "name": relative,
                    "path": relative,
                    "source_id": source_id,
                    "content_hash": content_hash,
                    "language": path.suffix.lower().lstrip(".") or lowered,
                    "content": content,
                }

        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            self._assert_source_kind(source_id, "repository")
            self._assert_ownership("context_nodes", list(files), source_id)
            previous_source = self._source(source_id)
            old_metadata = (
                json.loads(previous_source["metadata"]) if previous_source else {}
            )
            old = {
                row["id"]: row["content_hash"]
                for row in self._db.execute(
                    "SELECT id,content_hash FROM context_files WHERE organization_id=? AND source_id=?",
                    (self.organization_id, source_id),
                )
            }
            old_nodes = {
                row["id"]: json.loads(row["payload"])
                for row in self._db.execute(
                    "SELECT id,payload FROM context_nodes WHERE organization_id=? AND source_id=?",
                    (self.organization_id, source_id),
                )
                if json.loads(row["payload"]).get("kind") == "file"
            }
            changed = [
                key
                for key, value in files.items()
                if old.get(key) != value["content_hash"]
            ]
            removed = sorted(set(old) - set(files))
            rebuild = (
                list(files)
                if old_metadata.get("extractor_version") != EXTRACTOR_VERSION
                else changed
            )
            generated = {}
            parsing_started = time.monotonic()
            for file_id in rebuild:
                generated[file_id] = _python_graph(files[file_id])
                if time.monotonic() - parsing_started > MAX_SOURCE_AST_SECONDS:
                    raise ValueError(
                        "Repository parser time budget exceeded; previous index was preserved"
                    )
            new_records = []
            file_nodes = {}
            for file_id, file in files.items():
                if file_id in generated:
                    graph = generated[file_id]
                    node = {
                        key: value for key, value in file.items() if key != "content"
                    }
                    node.update(
                        {
                            "parse_status": graph["parse_status"],
                            "collector": EXTRACTOR_VERSION,
                            "code_graph_hash": _digest(graph),
                            "symbol_count": len(graph["nodes"]),
                            "resolved_calls": graph.get("resolved_calls", 0),
                            "unresolved_calls": graph.get("unresolved_calls", 0),
                        }
                    )
                    file_nodes[file_id] = node
                    for object_kind, objects in (
                        ("node", graph["nodes"]),
                        ("edge", graph["edges"]),
                    ):
                        for value in objects:
                            encoded = _json(value)
                            new_records.append((file_id, object_kind, value, encoded))
                else:
                    file_nodes[file_id] = old_nodes[file_id]
            replaced_files = set(rebuild) | set(removed)
            retained = [
                row
                for row in self._db.execute(
                    "SELECT file_id,object_kind,object_bytes FROM context_derivations WHERE organization_id=? AND source_id=?",
                    (self.organization_id, source_id),
                )
                if row["file_id"] not in replaced_files
            ]
            if (
                len(retained) + len(new_records) > MAX_SOURCE_CODE_OBJECTS
                or sum(row["object_bytes"] for row in retained)
                + sum(len(record[3].encode("utf-8")) for record in new_records)
                > MAX_SOURCE_BYTES
            ):
                raise ValueError(
                    "Repository derived graph budget exceeded; previous index was preserved"
                )
            self._assert_ownership(
                "context_nodes",
                [record[2]["id"] for record in new_records if record[1] == "node"],
                source_id,
            )
            self._assert_ownership(
                "context_edges",
                [record[2]["id"] for record in new_records if record[1] == "edge"],
                source_id,
            )
            digest = _digest(
                {
                    "extractor_version": EXTRACTOR_VERSION,
                    "files": {
                        key: {
                            "content_hash": value["content_hash"],
                            "code_graph_hash": value["code_graph_hash"],
                        }
                        for key, value in sorted(file_nodes.items())
                    },
                }
            )
            statuses = {}
            for node in file_nodes.values():
                status = node["parse_status"]
                statuses[status] = statuses.get(status, 0) + 1
            symbols = sum(row["object_kind"] == "node" for row in retained) + sum(
                record[1] == "node" for record in new_records
            )
            code_edges = len(retained) + len(new_records) - symbols
            self._put_source(
                source_id,
                "repository",
                revision,
                digest,
                {
                    "files": len(files),
                    "skipped": skipped,
                    "extractor_version": EXTRACTOR_VERSION,
                    "symbols": symbols,
                    "code_edges": code_edges,
                    "parse_statuses": statuses,
                },
            )
            for file_id in replaced_files:
                for record in self._db.execute(
                    "SELECT id,object_kind FROM context_derivations WHERE organization_id=? AND source_id=? AND file_id=?",
                    (self.organization_id, source_id, file_id),
                ).fetchall():
                    table = (
                        "context_nodes"
                        if record["object_kind"] == "node"
                        else "context_edges"
                    )
                    self._db.execute(
                        "DELETE FROM "
                        + table
                        + " WHERE organization_id=? AND source_id=? AND id=?",
                        (self.organization_id, source_id, record["id"]),
                    )
                self._db.execute(
                    "DELETE FROM context_derivations WHERE organization_id=? AND source_id=? AND file_id=?",
                    (self.organization_id, source_id, file_id),
                )
            for file_id in removed:
                for table in ("context_nodes", "context_files"):
                    self._db.execute(
                        "DELETE FROM " + table + " WHERE organization_id=? AND id=?",
                        (self.organization_id, file_id),
                    )
            for file_id in rebuild:
                file = files[file_id]
                node = file_nodes[file_id]
                self._db.execute(
                    "INSERT INTO context_nodes VALUES (?,?,?,?) ON CONFLICT(organization_id,id) "
                    "DO UPDATE SET payload=excluded.payload",
                    (self.organization_id, file_id, source_id, _json(node)),
                )
                self._db.execute(
                    "INSERT INTO context_files VALUES (?,?,?,?,?,?) ON CONFLICT(organization_id,id) "
                    "DO UPDATE SET content_hash=excluded.content_hash,content=excluded.content",
                    (
                        self.organization_id,
                        file_id,
                        source_id,
                        file["path"],
                        file["content_hash"],
                        file["content"],
                    ),
                )
            for file_id, object_kind, value, encoded in new_records:
                if object_kind == "node":
                    self._db.execute(
                        "INSERT INTO context_nodes VALUES (?,?,?,?)",
                        (self.organization_id, value["id"], source_id, encoded),
                    )
                else:
                    self._db.execute(
                        "INSERT INTO context_edges VALUES (?,?,?,?,?,?)",
                        (
                            self.organization_id,
                            value["id"],
                            source_id,
                            value["source"],
                            value["target"],
                            encoded,
                        ),
                    )
                self._db.execute(
                    "INSERT INTO context_derivations VALUES (?,?,?,?,?,?)",
                    (
                        self.organization_id,
                        value["id"],
                        source_id,
                        file_id,
                        object_kind,
                        len(encoded.encode("utf-8")),
                    ),
                )
        return {
            "source_id": source_id,
            "revision": self.snapshot()["revision"],
            "source_revision": revision,
            "files": len(files),
            "changed": sorted(changed),
            "deleted": removed,
            "unchanged": len(files) - len(changed),
            "skipped": skipped,
            "parsed_files": len(rebuild),
            "symbols": symbols,
            "code_edges": code_edges,
            "parse_statuses": statuses,
        }

    @staticmethod
    def _read_confined(repository: Path, relative: str):
        # Resolve each component via directory descriptors and O_NOFOLLOW so a
        # concurrent symlink swap cannot redirect reads outside the repository.
        if not hasattr(os, "O_NOFOLLOW"):
            raise RuntimeError("Safe repository indexing requires O_NOFOLLOW")
        descriptors = []
        try:
            current = os.open(
                str(repository), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            descriptors.append(current)
            parts = PurePosixPath(relative).parts
            for part in parts[:-1]:
                current = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current
                )
                descriptors.append(current)
            descriptor = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current
            )
            descriptors.append(descriptor)
            import stat

            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                return None
            with os.fdopen(os.dup(descriptor), "rb") as handle:
                raw = handle.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
                return None
            text = raw.decode("utf-8")
            if "-----BEGIN " in text and "PRIVATE KEY-----" in text:
                return None
            return text
        except (OSError, UnicodeError):
            return None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @_serialized
    def replace_topology(
        self, source_id: str, nodes: List[Dict], edges: List[Dict], revision: str
    ) -> Dict:
        """Replace one trusted source contribution, rejecting ownership conflicts."""
        source_id = _identifier(source_id, "source ID")
        revision = _revision(revision)
        if (
            not isinstance(nodes, list)
            or not isinstance(edges, list)
            or len(nodes) > MAX_TOPOLOGY_NODES
            or len(edges) > MAX_TOPOLOGY_EDGES
        ):
            raise ValueError("Topology exceeds item bounds")
        # Round-trip prevents callers mutating nested attributes during storage.
        try:
            serialized = _json({"nodes": nodes, "edges": edges})
            if len(serialized.encode("utf-8")) > MAX_SOURCE_BYTES:
                raise ValueError("Topology exceeds byte budget")
            copied = json.loads(serialized)
        except (TypeError, RecursionError) as exc:
            raise ValueError("Topology must contain JSON data") from exc
        nodes, edges = copied["nodes"], copied["edges"]
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError("Nodes must be objects")
            _identifier(node.get("id"), "node ID")
            _identifier(node.get("kind"), "node kind")
            if (
                not isinstance(node.get("name"), str)
                or not node["name"]
                or len(node["name"]) > 1024
            ):
                raise ValueError("Node name is required and bounded")
            if "source_id" in node and node["source_id"] != source_id:
                raise ValueError("Node source ownership cannot be overridden")
            node["source_id"] = source_id
            if "exposure" in node and node["exposure"] not in (
                "public",
                "internal",
                "unknown",
            ):
                raise ValueError("Invalid node exposure")
            if "owner" in node and (
                not isinstance(node["owner"], str)
                or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,119}", node["owner"]
                )
            ):
                raise ValueError("Owner must be a bounded safe team identifier")
            if "reportable" in node and not isinstance(node["reportable"], bool):
                raise ValueError("reportable must be a boolean")
            if "initial_capabilities" in node:
                capabilities = node["initial_capabilities"]
                if not isinstance(capabilities, list) or len(capabilities) > 100:
                    raise ValueError("Invalid initial capabilities")
                for capability in capabilities:
                    _identifier(capability, "initial capability")
            if "code_source_ids" in node:
                if (
                    not isinstance(node["code_source_ids"], list)
                    or not 1 <= len(node["code_source_ids"]) <= 100
                ):
                    raise ValueError("Invalid code source bindings")
                for code_source in node["code_source_ids"]:
                    _identifier(code_source, "code source ID")
            if "code_paths" in node:
                if (
                    not isinstance(node["code_paths"], list)
                    or len(node["code_paths"]) > 200
                ):
                    raise ValueError("Invalid code_paths")
                node["code_paths"] = [
                    _safe_relative(value) for value in node["code_paths"]
                ]
        node_ids = [node["id"] for node in nodes]
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("Duplicate node IDs")
        for edge in edges:
            if not isinstance(edge, dict):
                raise ValueError("Edges must be objects")
            for field in ("id", "source", "target", "kind"):
                _identifier(edge.get(field), "edge " + field)
            if edge.get("state", "unknown") not in {"observed", "blocked", "unknown"}:
                raise ValueError("Invalid edge state")
            edge.setdefault("state", "unknown")
            if "source_id" in edge and edge["source_id"] != source_id:
                raise ValueError("Edge source ownership cannot be overridden")
            edge["source_id"] = source_id
            for field in ("requires", "provides"):
                edge.setdefault(field, [])
                if not isinstance(edge[field], list) or len(edge[field]) > 100:
                    raise ValueError("Invalid capability list")
                for capability in edge[field]:
                    _identifier(capability, "capability")
        edge_ids = [edge["id"] for edge in edges]
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("Duplicate edge IDs")
        digest = _digest(
            {
                "nodes": sorted(nodes, key=lambda n: n["id"]),
                "edges": sorted(edges, key=lambda e: e["id"]),
            }
        )
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            self._assert_source_kind(source_id, "topology")
            self._assert_ownership("context_nodes", node_ids, source_id)
            self._assert_ownership("context_edges", edge_ids, source_id)
            known = {
                row["id"]
                for row in self._db.execute(
                    "SELECT id FROM context_nodes WHERE organization_id=? AND source_id<>?",
                    (self.organization_id, source_id),
                )
            } | set(node_ids)
            if any(
                edge["source"] not in known or edge["target"] not in known
                for edge in edges
            ):
                raise ValueError("Topology edges must reference existing nodes")
            previous = self._source(source_id)
            self._put_source(
                source_id,
                "topology",
                revision,
                digest,
                {"nodes": len(nodes), "edges": len(edges)},
            )
            for table in ("context_nodes", "context_edges"):
                self._db.execute(
                    "DELETE FROM " + table + " WHERE organization_id=? AND source_id=?",
                    (self.organization_id, source_id),
                )
            self._db.executemany(
                "INSERT INTO context_nodes VALUES (?,?,?,?)",
                [
                    (self.organization_id, node["id"], source_id, _json(node))
                    for node in nodes
                ],
            )
            self._db.executemany(
                "INSERT INTO context_edges VALUES (?,?,?,?,?,?)",
                [
                    (
                        self.organization_id,
                        edge["id"],
                        source_id,
                        edge["source"],
                        edge["target"],
                        _json(edge),
                    )
                    for edge in edges
                ],
            )
        return {
            "source_id": source_id,
            "revision": self.snapshot()["revision"],
            "source_revision": revision,
            "nodes": len(nodes),
            "edges": len(edges),
            "changed": previous is None or previous["digest"] != digest,
        }

    @_serialized
    def delete_source(self, source_id: str) -> Dict:
        """Delete a collector's complete contribution; dangling edges are hidden."""
        source_id = _identifier(source_id, "source ID")
        with self._db:
            cursor = self._db.execute(
                "DELETE FROM context_sources WHERE organization_id=? AND source_id=?",
                (self.organization_id, source_id),
            )
        return {
            "source_id": source_id,
            "deleted": cursor.rowcount > 0,
            "revision": self.snapshot()["revision"],
        }

    @_serialized
    def snapshot(self) -> Dict:
        with self._consistent_read():
            return self._snapshot()

    def _snapshot(self) -> Dict:
        sources = [
            dict(row)
            for row in self._db.execute(
                "SELECT source_id,kind,revision,digest,metadata,synced_at FROM context_sources WHERE organization_id=? ORDER BY source_id",
                (self.organization_id,),
            )
        ]
        for source in sources:
            source["metadata"] = json.loads(source["metadata"])
        nodes = [
            json.loads(row["payload"])
            for row in self._db.execute(
                "SELECT payload FROM context_nodes WHERE organization_id=? ORDER BY id",
                (self.organization_id,),
            )
        ]
        node_ids = {node["id"] for node in nodes}
        edges = [
            json.loads(row["payload"])
            for row in self._db.execute(
                "SELECT payload FROM context_edges WHERE organization_id=? ORDER BY id",
                (self.organization_id,),
            )
        ]
        edges = [
            edge
            for edge in edges
            if edge["source"] in node_ids and edge["target"] in node_ids
        ]
        revision = _digest(
            {
                "organization_id": self.organization_id,
                "sources": [
                    {
                        key: source[key]
                        for key in ("source_id", "kind", "revision", "digest")
                    }
                    for source in sources
                ],
            }
        )
        return {
            "revision": revision,
            "nodes": nodes,
            "edges": edges,
            "sources": sources,
        }

    @_serialized
    def context_for(self, asset_ids: List[str], max_chars: int = 60000) -> Dict:
        """Return bounded cited files and complete topology for contextual review.

        File selection uses explicit IDs, matching file paths or trusted service
        ``code_paths``. It does not interpret report text as filesystem paths.
        Topology remains complete to avoid making omitted controls look absent.
        """
        with self._consistent_read():
            return self._context_for(asset_ids, max_chars)

    def _context_for(self, asset_ids: List[str], max_chars: int) -> Dict:
        if (
            not isinstance(asset_ids, list)
            or len(asset_ids) > 100
            or any(
                not isinstance(value, str) or len(value) > 1024 for value in asset_ids
            )
        ):
            raise ValueError("A bounded list of asset identifiers is required")
        if (
            not isinstance(max_chars, int)
            or isinstance(max_chars, bool)
            or not 1000 <= max_chars <= MAX_CONTEXT_CHARS
        ):
            raise ValueError(
                "Context budget must be between 1000 and 200000 characters"
            )
        snapshot = self.snapshot()
        requested = set(asset_ids)
        files = [node for node in snapshot["nodes"] if node["kind"] == "file"]
        selected_ids = set()
        ambiguous = False
        for node in snapshot["nodes"]:
            if node["id"] in requested and node["kind"] != "file":
                if node["kind"] == "symbol" and node.get("file_id"):
                    selected_ids.add(node["file_id"])
                binding = node.get("code_source_ids")
                for prefix in node.get("code_paths", []):
                    matching = [
                        file
                        for file in files
                        if (
                            file["path"] == prefix
                            or file["path"].startswith(prefix.rstrip("/") + "/")
                        )
                        and (binding is None or file["source_id"] in binding)
                    ]
                    if (
                        binding is None
                        and len({file["source_id"] for file in matching}) > 1
                    ):
                        ambiguous = True
                    else:
                        selected_ids.update(file["id"] for file in matching)
        for value in requested:
            selected_ids.update(file["id"] for file in files if file["id"] == value)
            matching = [file for file in files if file["path"] == value]
            if len({file["source_id"] for file in matching}) > 1:
                ambiguous = True
            else:
                selected_ids.update(file["id"] for file in matching)
        if not requested:
            selected_ids.update(file["id"] for file in files)
        selected = [file for file in files if file["id"] in selected_ids]
        repository_sources = {
            source["source_id"]
            for source in snapshot["sources"]
            if source["kind"] == "repository"
        }
        derived_nodes = [
            node
            for node in snapshot["nodes"]
            if node["kind"] == "symbol"
            and node.get("source_id") in repository_sources
            and node.get("file_id")
        ]
        derived_ids = {node["id"] for node in derived_nodes}
        topology_nodes = [
            node
            for node in snapshot["nodes"]
            if node["kind"] != "file" and node["id"] not in derived_ids
        ]
        code_edges = [
            edge
            for edge in snapshot["edges"]
            if edge.get("source_id") in repository_sources
            and edge.get("file_id")
            and edge["kind"] in {"code_defines", "code_call"}
        ]
        code_edge_ids = {edge["id"] for edge in code_edges}
        result = {
            "revision": snapshot["revision"],
            "nodes": topology_nodes + selected,
            "edges": [
                edge for edge in snapshot["edges"] if edge["id"] not in code_edge_ids
            ],
            "sources": snapshot["sources"],
            "evidence": [],
            "truncated": ambiguous,
            "code_graph_truncated": False,
            "coverage": (
                "ambiguous repository paths; bind code_source_ids explicitly"
                if ambiguous
                else "bounded source evidence, Python syntax graph and administrator-declared topology"
            ),
        }
        if len(_json(result)) > max_chars:
            # Never silently slice topology. The caller can request a larger
            # budget or arrange smaller source contributions for retrieval.
            return {
                "revision": snapshot["revision"],
                "nodes": [],
                "edges": [],
                "sources": [],
                "evidence": [],
                "truncated": True,
                "coverage": "graph metadata exceeded context budget",
            }
        if ambiguous:
            return result
        # Syntax helpers are optional: reserve the bulk of retrieval for exact
        # source evidence and include no derived facts from unrelated files.
        code_budget = min(max_chars // 4, max_chars - len(_json(result)))
        relevant_nodes = [
            node for node in derived_nodes if node["file_id"] in selected_ids
        ]
        relevant_edges = [
            edge for edge in code_edges if edge["file_id"] in selected_ids
        ]
        visible_ids = {node["id"] for node in result["nodes"]}
        for node in relevant_nodes:
            size = len(_json(node)) + 1
            if size > code_budget:
                result["code_graph_truncated"] = True
                continue
            result["nodes"].append(node)
            visible_ids.add(node["id"])
            code_budget -= size
        for edge in relevant_edges:
            size = len(_json(edge)) + 1
            if (
                edge["source"] not in visible_ids
                or edge["target"] not in visible_ids
                or size > code_budget
            ):
                result["code_graph_truncated"] = True
                continue
            result["edges"].append(edge)
            code_budget -= size
        source_revisions = {
            source["source_id"]: source["revision"] for source in snapshot["sources"]
        }
        for node in selected:
            row = self._db.execute(
                "SELECT * FROM context_files WHERE organization_id=? AND id=?",
                (self.organization_id, node["id"]),
            ).fetchone()
            if not row:
                continue
            evidence = {
                "id": node["id"] + "@" + row["content_hash"],
                "node_id": node["id"],
                "path": row["path"],
                "content_hash": row["content_hash"],
                "start_line": 1,
                "end_line": 0,
                "content": "",
                "source_id": row["source_id"],
                "revision": source_revisions[row["source_id"]],
            }
            # Whole original lines preserve citation offsets. No content
            # rewriting, import stripping, comment compression or execution.
            for number, line in enumerate(row["content"].splitlines(keepends=True), 1):
                evidence["content"] += line
                evidence["end_line"] = number
                if len(_json(result)) + len(_json(evidence)) + 1 > max_chars:
                    evidence["content"] = evidence["content"][: -len(line)]
                    evidence["end_line"] = number - 1
                    result["truncated"] = True
                    break
            if evidence["content"]:
                result["evidence"].append(evidence)
            if result["truncated"]:
                break
        return result
