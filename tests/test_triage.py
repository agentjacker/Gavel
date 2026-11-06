"""Contextual risk regressions: provenance, composition, uncertainty and acceptance."""

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from gavel.triage import (
    analyze_with_model,
    attack_paths,
    decide,
    validate_analysis,
    validate_policy,
)


def timestamp(hours=0):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def policy(critical=None, acceptances=None):
    return validate_policy(
        {"critical_assets": critical or [], "acceptances": acceptances or []}
    )


def graph(nodes=None, edges=None):
    return {
        "revision": "current",
        "nodes": nodes or [{"id": "web", "exposure": "public"}],
        "edges": edges or [],
        "sources": [{"source_id": "repo", "synced_at": timestamp()}],
    }


def evidence(content="dangerous(input)\nreturn result\n"):
    digest = hashlib.sha256(content.encode()).hexdigest()
    return {
        "id": "repo:app.py@" + digest,
        "path": "app.py",
        "content_hash": digest,
        "source_id": "repo",
        "content": content,
        "start_line": 1,
        "end_line": 2,
    }


def raw_analysis(
    asset="web", name="primitive", requires=None, provides=None, content=None
):
    item = evidence(content) if content else evidence()
    value = {
        "validity": "supported",
        "summary": "The cited source supports a conditional security primitive.",
        "evidence": [
            {
                "id": item["id"],
                "start_line": 1,
                "end_line": 1,
                "quote": item["content"].splitlines()[0],
            }
        ],
        "primitives": [
            {
                "id": name,
                "asset_id": asset,
                "requires": requires or [],
                "provides": provides or ["read:" + asset],
                "evidence_ids": [item["id"]],
            }
        ],
        "missing_evidence": [],
    }
    return value, {"evidence": [item], "truncated": False}


def analysis(asset="web", name="primitive", requires=None, provides=None, content=None):
    value, context = raw_analysis(asset, name, requires, provides, content)
    return validate_analysis(value, context, asset)


def report(asset="web", name="report"):
    return {
        "id": name,
        "asset_id": asset,
        "title": "Security report",
        "description": "A conditional finding",
    }


def edge(
    name,
    source,
    target,
    requires=None,
    provides=None,
    state="observed",
    kind="connects",
):
    return {
        "id": name,
        "source": source,
        "target": target,
        "kind": kind,
        "state": state,
        "requires": requires or [],
        "provides": provides or [],
    }


def test_two_small_findings_compose_and_elevate_both_reports():
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "service"}, {"id": "db"}],
        [
            edge("front", "web", "service", ["token:web"]),
            edge("back", "service", "db", ["role:service"], ["read:db"]),
        ],
    )
    first = analysis("web", "token-leak", provides=["token:web"])
    second = analysis("service", "role-confusion", provides=["role:service"])
    first_report, second_report = report("web", "first"), report("service", "second")
    first_alone = decide(first_report, first, topology, policy(["db"]), [])
    second_alone = decide(second_report, second, topology, policy(["db"]), [])
    assert first_alone["priority"] == "schedule"
    assert second_alone["priority"] == "watch" and second_alone["latent"]
    combined_first = decide(
        first_report,
        first,
        topology,
        policy(["db"]),
        [{**second_report, "decision": second_alone}],
    )
    combined_second = decide(
        second_report,
        second,
        topology,
        policy(["db"]),
        [{**first_report, "decision": first_alone}],
    )
    assert combined_first["priority"] == combined_second["priority"] == "act"
    assert any(
        path["target"] == "db" and path["edges"] == ["front", "back"]
        for path in combined_first["attack_paths"]
    )
    assert "read:db" in combined_first["capabilities_gained"]
    assert combined_first["verification_level"] == "static_hypothesis"


@pytest.mark.parametrize("state", ["unknown", "blocked"])
def test_unknown_and_blocked_edges_never_grant_capabilities(state):
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "db"}],
        [
            edge("gate", "web", "db", ["token:web"], ["read:db"], state),
        ],
    )
    result = decide(
        report(), analysis(provides=["token:web"]), topology, policy(["db"]), []
    )
    assert result["priority"] != "act"
    assert not any(path["target"] == "db" for path in result["attack_paths"])
    assert "read:db" not in result["capabilities_gained"]
    assert result["blocked_paths"] == [
        {"edge_id": "gate", "state": state, "target": "db"}
    ]


def test_import_relation_and_absent_edges_are_not_attacker_movement():
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "db"}],
        [edge("imports", "web", "db", kind="imports")],
    )
    result = attack_paths("web", topology, [])
    assert [path["target"] for path in result["paths"]] == ["web"]


def test_static_code_graph_does_not_crowd_out_movement_evidence():
    syntax_edges = [
        edge("call-" + str(index), "web", "db", kind="code_call")
        for index in range(5001)
    ]
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "db"}],
        syntax_edges + [edge("real-route", "web", "db", ["token:web"], ["read:db"])],
    )
    result = decide(
        report(), analysis(provides=["token:web"]), topology, policy(["db"]), []
    )
    assert result["priority"] == "act"
    assert not result["missing_evidence"]


def test_baseline_critical_reach_does_not_inflate_unrelated_fingerprint():
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "db"}],
        [edge("existing", "web", "db")],
    )
    result = decide(
        report(), analysis(provides=["fingerprint:web"]), topology, policy(["db"]), []
    )
    assert result["priority"] == "schedule"
    assert result["capabilities_gained"] == ["fingerprint:web"]


def test_direct_impact_on_protected_public_asset_is_actionable_without_new_route():
    result = decide(
        report(), analysis(provides=["read:web"]), graph(), policy(["web"]), []
    )
    assert result["priority"] == "act"


def test_trusted_capability_grants_reach_new_nodes_and_privilege_on_reached_nodes():
    topology = graph(
        [
            {"id": "web", "exposure": "public"},
            {"id": "service", "exposure": "public"},
            {"id": "cache"},
            {"id": "db"},
        ],
        [
            edge(
                "grant",
                "web",
                "service",
                ["token:web"],
                ["access:cache", "read:service"],
            ),
            edge("move", "cache", "db"),
        ],
    )
    result = decide(
        report(),
        analysis(provides=["token:web"]),
        topology,
        policy(["service", "db"]),
        [],
    )
    assert {"access:cache", "read:service", "access:db"} <= set(
        result["capabilities_gained"]
    )
    assert result["priority"] == "act"
    assert next(path for path in result["attack_paths"] if path["target"] == "db")[
        "edges"
    ] == ["grant", "move"]


def test_unmet_preconditions_remain_latent_without_being_assumed():
    result = decide(
        report(),
        analysis(requires=["session:web"], provides=["admin:web"]),
        graph(),
        policy(["web"]),
        [],
    )
    assert result["priority"] == "watch" and result["disposition"] == "monitor"
    assert result["latent"] and result["applicability"] == "conditional"
    assert "session:web" in result["missing_prerequisites"]
    assert "admin:web" not in result["capabilities_gained"]


def test_stale_peer_finding_cannot_enable_a_chain():
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "db"}],
        [edge("move", "web", "db", ["token:web"])],
    )
    peer_decision = {
        "validity": "supported",
        "graph_revision": "old",
        "primitives": analysis(name="token", provides=["token:web"])["primitives"],
    }
    result = decide(
        report(),
        analysis(name="read", provides=["read:web"]),
        topology,
        policy(["db"]),
        [{"id": "peer", "decision": peer_decision}],
    )
    assert result["priority"] != "act"


@pytest.mark.parametrize("age", [-48, 2])
def test_stale_or_future_context_forces_review(age):
    topology = graph()
    topology["sources"][0]["synced_at"] = timestamp(age)
    result = decide(report(), analysis(), topology, policy(), [])
    assert result["disposition"] == "review" and result["applicability"] == "unknown"
    assert result["validity"] == "supported"
    assert any("Stale" in reason for reason in result["missing_evidence"])


def test_missing_context_and_truncated_retrieval_remain_unresolved():
    value, context = raw_analysis()
    context["truncated"] = True
    checked = validate_analysis(value, context, "web")
    topology = graph()
    topology["sources"] = []
    result = decide(report(), checked, topology, policy(), [])
    assert result["disposition"] == "review"
    assert "Retrieved context was truncated" in result["missing_evidence"]
    assert "No organization context has been synchronized" in result["missing_evidence"]


@pytest.mark.parametrize(
    "change",
    [
        "id",
        "quote",
        "range",
        "bool-range",
        "uncited",
        "no-primitives",
        "scope",
        "unscoped",
        "extra-fields",
    ],
)
def test_forged_or_unscoped_model_evidence_is_rejected(change):
    value, context = raw_analysis()
    if change == "id":
        value["evidence"][0]["id"] = "forged"
    elif change == "quote":
        value["evidence"][0]["quote"] = "not in the file"
    elif change == "range":
        value["evidence"][0]["start_line"] = 3
    elif change == "bool-range":
        value["evidence"][0]["start_line"] = True
    elif change == "uncited":
        value["primitives"][0]["evidence_ids"] = []
    elif change == "no-primitives":
        value["primitives"] = []
    elif change == "scope":
        value["primitives"][0]["provides"] = ["access:database"]
    elif change == "unscoped":
        value["primitives"][0]["provides"] = ["admin"]
    else:
        value["primitives"][0]["fingerprint"] = "attacker-supplied"
    with pytest.raises(ValueError):
        validate_analysis(value, context, "web")


def acceptance(checked, expiry=24):
    primitive = checked["primitives"][0]
    return {
        "asset_id": primitive["asset_id"],
        "primitive_id": primitive["id"],
        "evidence_fingerprint": primitive["fingerprint"],
        "reason": "Reviewed business tolerance",
        "expires_at": timestamp(expiry),
    }


def test_acceptance_requires_evidence_fingerprint():
    rule = acceptance(analysis())
    del rule["evidence_fingerprint"]
    with pytest.raises(ValueError):
        policy(acceptances=[rule])


def test_acceptance_matches_exact_evidence_and_expires():
    checked = analysis()
    accepted = decide(
        report(), checked, graph(), policy(acceptances=[acceptance(checked)]), []
    )
    assert accepted["disposition"] == "accepted" and accepted["validity"] == "supported"
    expired = decide(
        report(), checked, graph(), policy(acceptances=[acceptance(checked, -1)]), []
    )
    assert expired["disposition"] == "fix"
    changed_source = analysis(content="dangerous_new(input)\nreturn result\n")
    changed = decide(
        report(), changed_source, graph(), policy(acceptances=[acceptance(checked)]), []
    )
    assert changed["disposition"] == "fix"
    changed_precondition = analysis(requires=["session:web"])
    changed = decide(
        report(),
        changed_precondition,
        graph(),
        policy(acceptances=[acceptance(checked)]),
        [],
    )
    assert changed["disposition"] != "accepted"


def test_fingerprint_is_stable_for_reordering_but_binds_exact_ranges():
    one = analysis(provides=["read:web", "write:web"])
    two = analysis(provides=["write:web", "read:web"])
    assert one["primitives"][0]["fingerprint"] == two["primitives"][0]["fingerprint"]
    value, context = raw_analysis(provides=["read:web", "write:web"])
    value["evidence"][0]["end_line"] = 2
    three = validate_analysis(value, context, "web")
    assert one["primitives"][0]["fingerprint"] != three["primitives"][0]["fingerprint"]


def test_new_protected_chain_reopens_previously_accepted_primitive():
    checked = analysis(provides=["token:web"])
    tolerance = policy(["db"], [acceptance(checked)])
    before = decide(report(), checked, graph(), tolerance, [])
    assert before["disposition"] == "accepted"
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "db"}],
        [edge("new-path", "web", "db", ["token:web"])],
    )
    after = decide(report(), checked, topology, tolerance, [])
    assert after["disposition"] == "fix" and after["priority"] == "act"


def test_unrelated_unmet_peer_does_not_make_actionable_own_finding_latent():
    peer = {
        "id": "other",
        "decision": {
            "graph_revision": "current",
            "validity": "supported",
            "primitives": analysis(
                "web", "conditional", ["session:web"], ["other:web"]
            )["primitives"],
        },
    }
    result = decide(report(), analysis(), graph(), policy(), [peer])
    assert result["disposition"] == "fix" and not result["latent"]


def test_exploration_bound_does_not_look_like_complete_negative_evidence():
    topology = graph()
    topology["edges"] = [edge("edge-" + str(i), "web", "web") for i in range(5001)]
    result = decide(report(), analysis(), topology, policy(), [])
    assert result["disposition"] == "review"
    assert any("bound" in item for item in result["missing_evidence"])


class ModelResponse:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    def iter_content(self, size):
        yield self.payload


@pytest.mark.parametrize("failure", ["network", "json", "truncated", "quote", "size"])
def test_model_transport_and_output_errors_stay_uncertain(monkeypatch, failure):
    import requests

    value, context = raw_analysis()

    def fake_post(url, **kwargs):
        assert [item["role"] for item in kwargs["json"]["messages"]] == [
            "system",
            "user",
        ]
        assert kwargs["allow_redirects"] is False
        assert "tools" not in kwargs["json"]
        if failure == "network":
            raise requests.Timeout("secret internal endpoint details")
        if failure == "json":
            return ModelResponse(b"not-json")
        if failure == "size":
            return ModelResponse(b"x" * (128 * 1024 + 1))
        if failure == "quote":
            value["evidence"][0]["quote"] = "invented"
        return ModelResponse(
            json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": (
                                "length" if failure == "truncated" else "stop"
                            ),
                            "message": {"content": json.dumps(value)},
                        }
                    ]
                }
            ).encode()
        )

    monkeypatch.setattr(requests, "post", fake_post)
    result = analyze_with_model(
        report(),
        context,
        {"base_url": "http://model/v1", "model": "operator-configured"},
    )
    assert result["validity"] == "uncertain" and not result["primitives"]
    assert "secret" not in json.dumps(result)


def test_missing_model_is_an_explicit_review_outcome():
    result = analyze_with_model(report(), {"evidence": []}, {})
    assert result["validity"] == "uncertain"
    assert result["missing_evidence"]


def test_unresolved_peer_cannot_supply_assumed_attack_capabilities():
    topology = graph(
        [{"id": "web", "exposure": "public"}, {"id": "db"}],
        [edge("move", "web", "db", ["token:web"])],
    )
    peer_decision = {
        "validity": "supported",
        "graph_revision": "current",
        "missing_evidence": ["Credential scope is unknown"],
        "primitives": analysis(name="token", provides=["token:web"])["primitives"],
    }
    result = decide(
        report(),
        analysis(name="read", provides=["read:web"]),
        topology,
        policy(["db"]),
        [{"id": "peer", "decision": peer_decision}],
    )
    assert result["priority"] != "act"
    assert "access:db" not in result["capabilities_gained"]
