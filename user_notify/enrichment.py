"""Collects user details for an offense from QRadar and stores them as SOAR artifacts."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from .ariel import ArielClient
from .profiles import EventField

log = logging.getLogger(__name__)
AQL_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def build_aql(field: EventField, offense_id: int | str, start: datetime, stop: datetime) -> str:
    """Distinct non-empty values of one property among the offense's events in a time window."""
    return (
        f'SELECT "{field.aql_property}" AS "value" FROM events '
        f'WHERE INOFFENSE({int(offense_id)}) AND "{field.aql_property}" IS NOT NULL '
        f"GROUP BY \"value\" START '{start:{AQL_TIME_FORMAT}}' STOP '{stop:{AQL_TIME_FORMAT}}'"
    )


def collect(
    ariel: ArielClient,
    offense_id: int | str,
    discovered: datetime,
    fields: Iterable[EventField],
    window: timedelta = timedelta(minutes=10),
) -> dict[str, list[str]]:
    """Run one search per field around the time the incident was discovered."""
    start, stop = discovered - window, discovered + window
    values: dict[str, list[str]] = {}
    for field in fields:
        rows = ariel.search(build_aql(field, offense_id, start, stop))
        values[field.key] = [
            str(row["value"]) for row in rows if row.get("value") not in (None, "")
        ]
        log.info(
            "Offense %s: %s -> %d value(s)", offense_id, field.aql_property, len(values[field.key])
        )
    return values


def new_artifacts(
    fields: Iterable[EventField], values: dict[str, list[str]], existing: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Artifacts for the collected values that the incident does not have yet."""
    seen = {(str(a.get("type")), str(a.get("value"))) for a in existing}
    artifacts = []
    for field in fields:
        for value in values.get(field.key, []):
            if (field.artifact_type, value) in seen:
                continue
            seen.add((field.artifact_type, value))
            artifact: dict[str, Any] = {
                "type": field.artifact_type,
                "value": value,
                "description": field.artifact_description,
            }
            if field.ip_role:
                other = "destination" if field.ip_role == "source" else "source"
                artifact["properties"] = [
                    {"name": field.ip_role, "value": "true"},
                    {"name": other, "value": "false"},
                ]
            artifacts.append(artifact)
    return artifacts
