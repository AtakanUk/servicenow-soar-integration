"""Builds the clients from environment variables."""

from __future__ import annotations

import os
from typing import Any

from .ariel import ArielClient
from .notify import ServiceNowTarget
from .servicenow import ServiceNowClient


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Environment variable {name} is required")
    return value


def _verify(name: str) -> bool | str:
    value = os.environ.get(name, "true")
    return {"true": True, "false": False}.get(value.lower(), value)


def ariel_from_env() -> ArielClient:
    return ArielClient(
        _require("QRADAR_HOST"),
        _require("QRADAR_API_TOKEN"),
        verify=_verify("QRADAR_VERIFY_SSL"),
        timeout=float(os.environ.get("AQL_TIMEOUT_SECONDS", "300")),
    )


def servicenow_from_env() -> ServiceNowClient:
    return ServiceNowClient(
        _require("SERVICENOW_INSTANCE"),
        _require("SERVICENOW_USERNAME"),
        _require("SERVICENOW_PASSWORD"),
        verify=_verify("SERVICENOW_VERIFY_SSL"),
    )


def target_from_env() -> ServiceNowTarget:
    return ServiceNowTarget(
        table=os.environ.get("SERVICENOW_TABLE", ServiceNowTarget.table),
        body_field=os.environ.get("SERVICENOW_BODY_FIELD", ServiceNowTarget.body_field),
        recipient_field=os.environ.get(
            "SERVICENOW_RECIPIENT_FIELD", ServiceNowTarget.recipient_field
        ),
    )


def soar_from_env() -> Any:
    import resilient

    options: dict[str, Any] = {
        "host": _require("SOAR_HOST"),
        "port": int(os.environ.get("SOAR_PORT", "443")),
        "org": _require("SOAR_ORG"),
        "api_key_id": _require("SOAR_API_KEY_ID"),
        "api_key_secret": _require("SOAR_API_KEY_SECRET"),
    }
    if os.environ.get("SOAR_CAFILE"):
        options["cafile"] = os.environ["SOAR_CAFILE"]
    return resilient.get_client(options)
