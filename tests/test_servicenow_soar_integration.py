from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from user_notify.ariel import AqlTimeoutError, ArielClient
from user_notify.enrichment import build_aql, new_artifacts
from user_notify.notify import NotificationError, notify_user, render
from user_notify.profiles import ATYPICAL_TRAVEL, MFA_FRAUD, SOURCE_IP, USERNAME


def json_response(body):
    response = MagicMock()
    response.json.return_value = body
    return response


def test_build_aql():
    aql = build_aql(USERNAME, 4512, datetime(2026, 1, 1, 10, 0), datetime(2026, 1, 1, 10, 20))
    assert aql == (
        'SELECT "M365 Defender Account Name" AS "value" FROM events WHERE INOFFENSE(4512) '
        'AND "M365 Defender Account Name" IS NOT NULL GROUP BY "value" '
        "START '2026-01-01 10:00:00' STOP '2026-01-01 10:20:00'"
    )


def test_ariel_search_polls_and_times_out():
    client = ArielClient(
        "qradar.example.com", "token", poll_interval=1, timeout=2, sleep=lambda _: None
    )
    client.session = MagicMock()
    client.session.post.return_value = json_response({"search_id": "abc"})
    client.session.get.side_effect = [
        json_response({"status": "EXECUTE"}),
        json_response({"status": "COMPLETED"}),
        json_response({"events": [{"value": "alice"}]}),
    ]
    assert client.search("SELECT 1") == [{"value": "alice"}]

    client.session.get.side_effect = None
    client.session.get.return_value = json_response({"status": "EXECUTE"})
    with pytest.raises(AqlTimeoutError):
        client.search("SELECT 1")


def test_new_artifacts_skip_existing_and_set_ip_role():
    values = {"source_ip": ["192.0.2.7", "192.0.2.8"], "username": ["alice"]}
    existing = [{"type": "IP Address", "value": "192.0.2.8"}]
    artifacts = new_artifacts([SOURCE_IP, USERNAME], values, existing)
    assert [a["value"] for a in artifacts] == ["192.0.2.7", "alice"]
    assert artifacts[0]["properties"][0] == {"name": "source", "value": "true"}


def test_render_escapes_and_fills_missing_values():
    body = render(
        ATYPICAL_TRAVEL, {"username": "<b>alice</b>", "country": "NL"}, "01.01.2026 10:00:00", 4512
    )
    assert "&lt;b&gt;alice&lt;/b&gt;" in body
    assert "IP address N/A" in body


class FakeSoar:
    def __init__(self, incident, artifacts=()):
        self.incident = incident
        self.artifacts = list(artifacts)
        self.posted = []
        self.updates = []

    def get(self, uri):
        return self.artifacts if uri.endswith("/artifacts") else self.incident

    def post(self, uri, body):
        self.posted.append(body)

    def get_put(self, uri, apply):
        incident = {"properties": {}}
        apply(incident)
        self.updates.append(incident["properties"])


class FakeAriel:
    def __init__(self, answers):
        self.answers = answers

    def search(self, aql):
        for prop, rows in self.answers.items():
            if f'"{prop}"' in aql:
                return [{"value": value} for value in rows]
        return []


INCIDENT = {"id": 2101, "discovered_date": 1767261600000, "properties": {"qradar_id": 4512}}


def test_notify_user_end_to_end():
    soar = FakeSoar(INCIDENT)
    ariel = FakeAriel(
        {
            "sourceip": ["192.0.2.7"],
            "M365 Defender Account Name": ["alice"],
            "M365 Defender UPN": ["alice@example.com"],
            "MS365 Defender Country Letter Code": ["NL"],
        }
    )
    servicenow = MagicMock()
    servicenow.create_record.return_value = {"number": "SN0001"}

    result = notify_user(
        2101, ATYPICAL_TRAVEL, soar, ariel, servicenow, window=timedelta(minutes=10)
    )

    assert result.recipient == "alice@example.com" and result.artifacts_added == 4
    _table, fields = servicenow.create_record.call_args.args
    assert fields["short_description"] == "Atypical Travel Detected"
    assert fields["u_user_email"] == "alice@example.com"
    assert "<b>NL</b>" in fields["u_body"]
    assert soar.updates == [{"qradar_user_email": "alice@example.com"}]


def test_profile_without_upn_uses_incident_property():
    incident = {
        **INCIDENT,
        "properties": {"qradar_id": 4512, "qradar_user_email": "bob@example.com"},
    }
    soar = FakeSoar(incident)
    result = notify_user(
        2101,
        MFA_FRAUD,
        soar,
        FakeAriel({"User Agent": ["Authenticator"]}),
        MagicMock(),
        dry_run=True,
    )
    assert result.recipient == "bob@example.com"
    assert soar.posted == [] and soar.updates == []


def test_missing_recipient_is_an_error():
    with pytest.raises(NotificationError, match="No recipient"):
        notify_user(2101, MFA_FRAUD, FakeSoar(INCIDENT), FakeAriel({}), MagicMock())
