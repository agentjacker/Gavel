"""Evidence and ownership invariants for the persistent organization graph."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import gavel.context as context_module
from gavel.context import ContextGraph


@pytest.fixture
def graph(tmp_path):
    instance = ContextGraph(str(tmp_path / "context.sqlite"), "acme")
    yield instance
    instance.close()


def write(root, path, content):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def service(node_id="api", **attributes):
    return {"id": node_id, "kind": "service", "name": node_id, **attributes}


def edge(edge_id="api-db", source="api", target="db", **attributes):
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "kind": "connects_to",
        **attributes,
    }


def test_repository_updates_only_changed_files_and_deletes_stale_evidence(
    graph, tmp_path
):
    root = tmp_path / "repo"
    write(root, "src/api.py", "def handle():\n    return 1\n")
    unchanged = write(root, "src/auth.py", "# authentication middleware\n")
    first = graph.sync_repository("code", str(root), "commit-a")
    assert first["changed"] == ["code:src/api.py", "code:src/auth.py"]
    stable_revision = graph.sync_repository("code", str(root), "commit-a")["revision"]
    assert stable_revision == first["revision"]
    write(root, "src/api.py", "def handle():\n    return 2\n")
    unchanged.unlink()
    second = graph.sync_repository("code", str(root), "commit-b")
    assert second["changed"] == ["code:src/api.py"]
    assert second["deleted"] == ["code:src/auth.py"]
    assert second["revision"] != first["revision"]
    assert graph.context_for(["code:src/auth.py"])["evidence"] == []
    assert (
        len([node for node in graph.snapshot()["nodes"] if node["kind"] == "file"]) == 1
    )


def test_evidence_preserves_imports_whitespace_and_original_line_numbers(
    graph, tmp_path
):
    root = tmp_path / "repo"
    content = "import middleware\n\n# ordinary comment\ndef check():\n    return True\n"
    write(root, "src/check.py", content)
    graph.sync_repository("code", str(root), "commit-a")
    result = graph.context_for(["src/check.py"])
    evidence = result["evidence"][0]
    assert evidence["content"] == content
    assert evidence["content_hash"] == hashlib.sha256(content.encode()).hexdigest()
    assert evidence["start_line"] == 1
    assert evidence["end_line"] == 5
    assert evidence["revision"] == "commit-a"
    assert evidence["source_id"] == "code"
    assert evidence["node_id"] == "code:src/check.py"
    assert evidence["id"] == "code:src/check.py@" + evidence["content_hash"]
    assert str(root) not in json.dumps(result)


def test_service_paths_select_repository_evidence(graph, tmp_path):
    root = tmp_path / "repo"
    write(root, "services/api/handler.py", "pass\n")
    write(root, "services/admin/handler.py", "pass\n")
    graph.sync_repository("code", str(root), "commit-a")
    graph.replace_topology(
        "deployment", [service(code_paths=["services/api"], owner="api-team")], [], "v1"
    )
    result = graph.context_for(["api"])
    assert [item["path"] for item in result["evidence"]] == ["services/api/handler.py"]
    assert any(node.get("owner") == "api-team" for node in result["nodes"])


def test_source_ownership_conflict_is_atomic(graph):
    graph.replace_topology("one", [service()], [], "v1")
    previous = graph.snapshot()
    with pytest.raises(ValueError, match="owned by another source"):
        graph.replace_topology("two", [service(name="other company")], [], "v2")
    assert graph.snapshot() == previous
    assert [source["source_id"] for source in graph.snapshot()["sources"]] == ["one"]


def test_source_kind_cannot_be_reused(graph, tmp_path):
    root = tmp_path / "repo"
    write(root, "main.py", "pass\n")
    graph.sync_repository("code", str(root), "commit-a")
    with pytest.raises(ValueError, match="collector kind"):
        graph.replace_topology("code", [], [], "v2")
    assert len(graph.snapshot()["nodes"]) == 1


def test_organizations_can_use_same_ids_without_accessing_each_other(tmp_path):
    database = str(tmp_path / "context.sqlite")
    first = ContextGraph(database, "first")
    second = ContextGraph(database, "second")
    try:
        first.replace_topology("deployment", [service(name="first only")], [], "v1")
        assert second.snapshot()["nodes"] == []
        second.replace_topology("deployment", [service(name="second only")], [], "v2")
        assert first.snapshot()["nodes"][0]["name"] == "first only"
        assert second.snapshot()["nodes"][0]["name"] == "second only"
        second.delete_source("deployment")
        assert len(first.snapshot()["nodes"]) == 1
    finally:
        first.close()
        second.close()


def test_deleting_source_removes_files_and_suppresses_dangling_edges(graph, tmp_path):
    root = tmp_path / "repo"
    write(root, "main.py", "pass\n")
    graph.sync_repository("code", str(root), "commit-a")
    graph.replace_topology(
        "deployment", [service()], [edge(target="code:main.py")], "v1"
    )
    assert len(graph.snapshot()["edges"]) == 1
    graph.delete_source("code")
    assert graph.snapshot()["edges"] == []
    assert graph.context_for([])["evidence"] == []
    assert graph.snapshot()["nodes"][0]["id"] == "api"


def test_topology_replacement_deletes_removed_nodes_and_edges(graph):
    graph.replace_topology(
        "deployment",
        [service(), service("db")],
        [edge(state="blocked", evidence={"control": "network-policy-v2"})],
        "v1",
    )
    graph.replace_topology("deployment", [service()], [], "v2")
    assert [node["id"] for node in graph.snapshot()["nodes"]] == ["api"]
    assert graph.snapshot()["edges"] == []


def test_topology_revision_is_order_independent_and_freshness_is_explicit(graph):
    first = graph.replace_topology(
        "deployment", [service(), service("db")], [edge()], "v1"
    )
    second = graph.replace_topology(
        "deployment", [service("db"), service()], [edge()], "v1"
    )
    assert first["revision"] == second["revision"]
    assert second["changed"] is False
    assert graph.snapshot()["sources"][0]["synced_at"].endswith("+00:00")


@pytest.mark.parametrize(
    "nodes,edges",
    [
        ([service(), service()], []),
        ([service(code_paths=["../outside"])], []),
        ([service(code_paths=["/etc/passwd"])], []),
        ([service(source_id="forged")], []),
        ([service(exposure="probably_public")], []),
        ([service(initial_capabilities="access:api")], []),
        ([service(initial_capabilities=[{"access": "api"}])], []),
        ([service(owner="@channel\nsecret")], []),
        ([service(reportable="true")], []),
        ([service(code_source_ids="repo")], []),
        ([service()], [edge(target="missing")]),
        ([service()], [edge(target="api", state="certain")]),
        ([service()], [edge(target="api", requires="root")]),
    ],
)
def test_invalid_topology_preserves_previous_snapshot(graph, nodes, edges):
    graph.replace_topology("deployment", [service("existing")], [], "v1")
    previous = graph.snapshot()
    with pytest.raises(ValueError):
        graph.replace_topology("deployment", nodes, edges, "v2")
    assert graph.snapshot() == previous


def test_index_skips_symlinks_secret_files_binary_and_generated_directories(
    graph, tmp_path
):
    root = tmp_path / "repo"
    write(root, "safe.py", "pass\n")
    outside = write(tmp_path, "outside.py", "outside secret value\n")
    (root / "linked.py").symlink_to(outside)
    directory = tmp_path / "outside-dir"
    write(directory, "hidden.py", "hidden value\n")
    (root / "linked-dir").symlink_to(directory, target_is_directory=True)
    write(root, ".env", "TOKEN=secret\n")
    write(root, "credentials.json", '{"token":"secret"}')
    write(root, "private.py", "-----BEGIN RSA PRIVATE KEY-----\nsecret\n")
    write(root, "node_modules/dep/main.js", "untrusted generated file\n")
    (root / "binary.py").write_bytes(b"a\x00b")
    graph.sync_repository("code", str(root), "commit-a")
    assert [node["path"] for node in graph.snapshot()["nodes"]] == ["safe.py"]
    assert "secret" not in json.dumps(graph.context_for([]))


def test_budget_exceeded_does_not_turn_partial_scan_into_complete_index(
    graph, tmp_path, monkeypatch
):
    root = tmp_path / "repo"
    write(root, "one.py", "pass\n")
    graph.sync_repository("code", str(root), "commit-a")
    previous = graph.snapshot()
    write(root, "two.py", "pass\n")
    monkeypatch.setattr(context_module, "MAX_FILES", 1)
    with pytest.raises(ValueError, match="budget exceeded"):
        graph.sync_repository("code", str(root), "commit-b")
    assert graph.snapshot() == previous


def test_context_truncates_at_original_line_boundary(graph, tmp_path):
    root = tmp_path / "repo"
    content = "".join("line-%03d %s\n" % (number, "x" * 40) for number in range(100))
    write(root, "main.py", content)
    graph.sync_repository("code", str(root), "commit-a")
    result = graph.context_for(["main.py"], max_chars=2500)
    assert result["truncated"] is True
    assert len(json.dumps(result, sort_keys=True, separators=(",", ":"))) <= 2500
    evidence = result["evidence"][0]
    assert evidence["content"] == "".join(
        content.splitlines(keepends=True)[: evidence["end_line"]]
    )
    assert evidence["content"].endswith("\n")


def test_persisted_index_survives_new_instance(tmp_path):
    database = str(tmp_path / "context.sqlite")
    root = tmp_path / "repo"
    write(root, "main.py", "pass\n")
    first = ContextGraph(database, "acme")
    revision = first.sync_repository("code", str(root), "commit-a")["revision"]
    first.close()
    second = ContextGraph(database, "acme")
    try:
        assert second.snapshot()["revision"] == revision
        assert second.context_for(["main.py"])["evidence"][0]["content"] == "pass\n"
    finally:
        second.close()


def test_shared_graph_connection_serializes_worker_reads_and_mutations(graph, tmp_path):
    root = tmp_path / "repo"
    write(root, "main.py", "pass\n")
    graph.sync_repository("code", str(root), "commit-a")
    graph.replace_topology("deployment", [service(code_paths=["main.py"])], [], "v0")

    def operation(number):
        if number % 3 == 0:
            return graph.replace_topology(
                "deployment",
                [service(code_paths=["main.py"], owner="team-%d" % number)],
                [],
                "v%d" % number,
            )
        if number % 3 == 1:
            snapshot = graph.snapshot()
            assert len(snapshot["nodes"]) == 2
            assert len(snapshot["sources"]) == 2
            return snapshot
        retrieved = graph.context_for(["api"])
        assert len(retrieved["evidence"]) == 1
        assert retrieved["evidence"][0]["content"] == "pass\n"
        assert str(root) not in json.dumps(retrieved)
        return retrieved

    with ThreadPoolExecutor(max_workers=8) as workers:
        outcomes = list(workers.map(operation, range(60)))
    assert len(outcomes) == 60
    assert len(graph.snapshot()["nodes"]) == 2


def test_service_bindings_prevent_cross_repository_evidence_confusion(graph, tmp_path):
    first_root, second_root = tmp_path / "first", tmp_path / "second"
    write(first_root, "src/handler.py", "first implementation\n")
    write(second_root, "src/handler.py", "second implementation\n")
    graph.sync_repository("first-code", str(first_root), "a")
    graph.sync_repository("second-code", str(second_root), "b")
    graph.replace_topology("deployment", [service(code_paths=["src"])], [], "v1")
    ambiguous = graph.context_for(["api"])
    assert ambiguous["truncated"] is True
    assert ambiguous["evidence"] == []
    assert "ambiguous" in ambiguous["coverage"]
    assert graph.context_for(["src/handler.py"])["truncated"] is True
    graph.replace_topology(
        "deployment",
        [service(code_paths=["src"], code_source_ids=["second-code"])],
        [],
        "v2",
    )
    result = graph.context_for(["api"])
    assert result["truncated"] is False
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["source_id"] == "second-code"
    assert result["evidence"][0]["content"] == "second implementation\n"
    explicit = graph.context_for(["first-code:src/handler.py"])
    assert explicit["truncated"] is False
    assert explicit["evidence"][0]["source_id"] == "first-code"


def test_python_graph_records_cited_definitions_and_lexical_calls_without_execution(
    graph, tmp_path
):
    root = tmp_path / "repo"
    marker = tmp_path / "must-not-exist"
    content = (
        "from pathlib import Path\n"
        + 'Path(%r).write_text("executed")\n' % str(marker)
        + "\ndef helper():\n    return 1\n\n"
        + "async def entry():\n    return helper()\n\n"
        + "class Handler:\n    def run(self):\n        return helper()\n"
    )
    write(root, "main.py", content)
    summary = graph.sync_repository("code", str(root), "commit-a")
    assert not marker.exists()
    snapshot = graph.snapshot()
    symbols = {
        node["name"]: node for node in snapshot["nodes"] if node["kind"] == "symbol"
    }
    assert set(symbols) == {"helper", "entry", "Handler", "Handler.run"}
    assert symbols["entry"]["symbol_kind"] == "async_function"
    assert symbols["helper"]["evidence"]["start_line"] == 4
    assert symbols["helper"]["evidence"]["end_line"] == 5
    assert (
        symbols["helper"]["evidence"]["content_hash"]
        == hashlib.sha256(content.encode()).hexdigest()
    )
    calls = [edge for edge in snapshot["edges"] if edge["kind"] == "code_call"]
    assert {(edge["source"], edge["target"]) for edge in calls} == {
        (symbols["entry"]["id"], symbols["helper"]["id"]),
        (symbols["Handler.run"]["id"], symbols["helper"]["id"]),
    }
    assert all(
        edge["state"] == "unknown" and edge["runtime_reachability"] == "unknown"
        for edge in calls
    )
    assert all(not edge["requires"] and not edge["provides"] for edge in calls)
    assert (
        len([edge for edge in snapshot["edges"] if edge["kind"] == "code_defines"]) == 4
    )
    assert summary["symbols"] == 4
    assert summary["parse_statuses"] == {"parsed": 1}


@pytest.mark.parametrize(
    "content",
    [
        "def helper():\n    pass\ndef entry(helper):\n    helper()\n",
        "def helper():\n    pass\ndef helper():\n    pass\ndef entry():\n    helper()\n",
        "def helper():\n    pass\nfrom somewhere import helper\ndef entry():\n    helper()\n",
        "def helper():\n    pass\nfrom somewhere import *\ndef entry():\n    helper()\n",
        "def helper():\n    pass\ndef entry():\n    helper = other\n    helper()\n",
        "def helper():\n    pass\ndef entry(value=(helper := replacement)):\n    helper()\n",
        "class Handler:\n    def helper(self):\n        pass\n    def entry(self):\n        self.helper()\n",
    ],
)
def test_python_graph_leaves_shadowed_ambiguous_and_dynamic_calls_unresolved(
    graph, tmp_path, content
):
    root = tmp_path / "repo"
    write(root, "main.py", content)
    graph.sync_repository("code", str(root), "commit-a")
    assert not any(edge["kind"] == "code_call" for edge in graph.snapshot()["edges"])


def test_incremental_graph_skips_unchanged_ast_and_removes_changed_or_deleted_derivations(
    graph, tmp_path, monkeypatch
):
    root = tmp_path / "repo"
    write(root, "one.py", "def helper():\n    pass\ndef entry():\n    helper()\n")
    other = write(root, "two.py", "def unchanged():\n    pass\n")
    first = graph.sync_repository("code", str(root), "commit-a")
    original_parse = context_module.ast.parse
    parsed = []

    def record_parse(source, *args, **kwargs):
        parsed.append(kwargs["filename"])
        return original_parse(source, *args, **kwargs)

    monkeypatch.setattr(context_module.ast, "parse", record_parse)
    repeated = graph.sync_repository("code", str(root), "commit-a")
    assert repeated["revision"] == first["revision"]
    assert repeated["parsed_files"] == 0
    assert parsed == []
    write(root, "one.py", "def replacement():\n    pass\n")
    changed = graph.sync_repository("code", str(root), "commit-b")
    assert parsed == ["one.py"]
    assert changed["changed"] == ["code:one.py"]
    snapshot = graph.snapshot()
    assert {node["name"] for node in snapshot["nodes"] if node["kind"] == "symbol"} == {
        "replacement",
        "unchanged",
    }
    assert not any(edge["kind"] == "code_call" for edge in snapshot["edges"])
    other.unlink()
    graph.sync_repository("code", str(root), "commit-c")
    assert {
        node["name"] for node in graph.snapshot()["nodes"] if node["kind"] == "symbol"
    } == {"replacement"}
    assert all(edge["file_id"] != "code:two.py" for edge in graph.snapshot()["edges"])


def test_syntax_failure_retains_new_source_evidence_and_removes_stale_graph(
    graph, tmp_path
):
    root = tmp_path / "repo"
    write(root, "main.py", "def previously_valid():\n    pass\n")
    graph.sync_repository("code", str(root), "commit-a")
    write(root, "main.py", "def broken(:\n    pass\n")
    result = graph.sync_repository("code", str(root), "commit-b")
    assert result["parse_statuses"] == {"syntax_error": 1}
    assert len(graph.snapshot()["nodes"]) == 1
    assert graph.snapshot()["edges"] == []
    assert (
        graph.context_for(["main.py"])["evidence"][0]["content"]
        == "def broken(:\n    pass\n"
    )


def test_ast_and_source_graph_budgets_do_not_publish_partial_derivations(
    graph, tmp_path, monkeypatch
):
    root = tmp_path / "repo"
    write(root, "main.py", "pass\n")
    graph.sync_repository("code", str(root), "commit-a")
    previous = graph.snapshot()
    write(root, "main.py", "def first():\n    pass\ndef second():\n    pass\n")
    monkeypatch.setattr(context_module, "MAX_SOURCE_CODE_OBJECTS", 1)
    with pytest.raises(ValueError, match="derived graph budget exceeded"):
        graph.sync_repository("code", str(root), "commit-b")
    assert graph.snapshot() == previous
    monkeypatch.setattr(context_module, "MAX_SOURCE_CODE_OBJECTS", 25000)
    monkeypatch.setattr(context_module, "MAX_AST_NODES", 2)
    result = graph.sync_repository("code", str(root), "commit-b")
    assert result["parse_statuses"] == {"ast_budget_exceeded": 1}
    assert len(graph.snapshot()["nodes"]) == 1
    assert graph.snapshot()["edges"] == []


def test_unsupported_languages_keep_file_evidence_without_invented_symbols(
    graph, tmp_path
):
    root = tmp_path / "repo"
    write(root, "main.ts", "function handler() { return true; }\n")
    result = graph.sync_repository("code", str(root), "commit-a")
    assert result["parse_statuses"] == {"unsupported_language": 1}
    assert len(graph.snapshot()["nodes"]) == 1
    assert graph.context_for(["main.ts"])["evidence"][0]["content"].startswith(
        "function handler"
    )


def test_context_filters_unrelated_code_graph_and_reserves_source_evidence_budget(
    graph, tmp_path
):
    root = tmp_path / "repo"
    selected_content = "".join(
        "def selected_%d():\n    return %d\n" % (number, number) for number in range(30)
    )
    write(root, "selected.py", selected_content)
    write(
        root,
        "unrelated.py",
        "".join(
            "def unrelated_%d():\n    return %d\n" % (number, number)
            for number in range(100)
        ),
    )
    graph.sync_repository("code", str(root), "commit-a")
    result = graph.context_for(["selected.py"], max_chars=12000)
    assert result["truncated"] is False
    assert result["code_graph_truncated"] is True
    assert result["evidence"][0]["content"] == selected_content
    assert any(node["kind"] == "symbol" for node in result["nodes"])
    assert all(node.get("path") != "unrelated.py" for node in result["nodes"])
    assert all(edge.get("file_id") != "code:unrelated.py" for edge in result["edges"])
    assert len(json.dumps(result, separators=(",", ":"))) <= 12000
