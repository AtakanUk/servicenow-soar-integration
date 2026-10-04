"""End-to-end flow: offense -> user details -> artifacts -> ServiceNow notification."""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .enrichment import collect, new_artifacts
from .profiles import AlertProfile

log = logging.getLogger(__name__)


class NotificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServiceNowTarget:
    table: str = "u_security_notification"
    body_field: str = "u_body"
    recipient_field: str = "u_user_email"


@dataclass
class NotificationResult:
    recipient: str
    record: dict[str, Any] | None
    artifacts_added: int
    body: str


class _Defaults(dict):
    def __missing__(self, key: str) -> str:
        return "N/A"


def render(profile: AlertProfile, values: dict[str, str], event_time: str, offense_id: Any) -> str:
    safe = _Defaults(
        {key: html.escape(str(value)) for key, value in {**profile.defaults, **values}.items()}
    )
    safe["event_time"] = html.escape(event_time)
    safe["offense_id"] = html.escape(str(offense_id))
    return profile.template.format_map(safe)


def notify_user(
    incident_id: int,
    profile: AlertProfile,
    soar: Any,
    ariel: Any,
    servicenow: Any,
    target: ServiceNowTarget | None = None,
    recipient_property: str = "qradar_user_email",
    window: timedelta = timedelta(minutes=10),
    dry_run: bool = False,
) -> NotificationResult:
    target = target or ServiceNowTarget()
    incident = soar.get(f"/incidents/{incident_id}")
    properties = incident.get("properties") or {}
    offense_id = properties.get("qradar_id")
    if not offense_id:
        raise NotificationError(f"Incident {incident_id} has no QRadar offense ID")
    discovered = datetime.fromtimestamp(incident["discovered_date"] / 1000)

    collected = collect(ariel, offense_id, discovered, profile.fields, window)
    artifacts = new_artifacts(
        profile.fields, collected, soar.get(f"/incidents/{incident_id}/artifacts")
    )
    values = {key: found[0] for key, found in collected.items() if found}

    recipient = values.get(profile.recipient_key) or properties.get(recipient_property)
    if not recipient:
        raise NotificationError(
            f"No recipient found for incident {incident_id} (offense {offense_id})"
        )
    values.setdefault(profile.recipient_key, recipient)
    body = render(profile, values, f"{discovered:%d.%m.%Y %H:%M:%S}", offense_id)

    if dry_run:
        return NotificationResult(recipient, None, len(artifacts), body)

    for artifact in artifacts:
        soar.post(f"/incidents/{incident_id}/artifacts", artifact)
    if properties.get(recipient_property) != recipient:
        soar.get_put(
            f"/incidents/{incident_id}",
            lambda inc: inc["properties"].update({recipient_property: recipient}),
        )

    record = servicenow.create_record(
        target.table,
        {
            "short_description": profile.short_description,
            target.body_field: body,
            target.recipient_field: recipient,
        },
    )
    log.info(
        "Incident %s: notification %s created for %s",
        incident_id,
        record.get("number") or record.get("sys_id"),
        recipient,
    )
    return NotificationResult(recipient, record, len(artifacts), body)
