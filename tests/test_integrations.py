"""Notification ownership and markup boundaries without outbound requests."""

from gavel.integrations import send_event


class Response:
    status_code = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def event():
    return {
        "report_id": "abc123",
        "event_id": "stable",
        "asset_id": "customer-api",
        "owner": "platform-team",
        "priority": "act",
        "disposition": "fix",
    }


def test_slack_uses_plain_text_and_includes_owner_and_asset(monkeypatch):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr("requests.post", post)
    monkeypatch.setenv(
        "SLACK_WEBHOOK", "https://hooks.slack.com/services/test/test/test"
    )
    send_event("slack", {"url_env": "SLACK_WEBHOOK"}, event())
    body = calls[0][1]["json"]
    assert body["blocks"][0]["text"]["type"] == "plain_text"
    assert "platform-team" in body["text"] and "customer-api" in body["text"]
    assert body["unfurl_links"] is False
    assert calls[0][1]["allow_redirects"] is False
    assert calls[0][1]["headers"]["Idempotency-Key"] == "stable"


def test_jira_assigns_only_company_mapped_owner(monkeypatch):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr("requests.post", post)
    monkeypatch.setenv("JIRA_EMAIL", "operator@example.test")
    monkeypatch.setenv("JIRA_TOKEN", "local-test-token")
    settings = {
        "base_url": "https://jira.example.test",
        "project_key": "SEC",
        "email_env": "JIRA_EMAIL",
        "token_env": "JIRA_TOKEN",
        "owner_map": {"platform-team": "configured-account"},
    }
    send_event("jira", settings, event())
    assert calls[0][0] == "https://jira.example.test/rest/api/3/issue"
    fields = calls[0][1]["json"]["fields"]
    assert fields["assignee"] == {"accountId": "configured-account"}
    assert fields["project"] == {"key": "SEC"}
    assert calls[0][1]["allow_redirects"] is False
