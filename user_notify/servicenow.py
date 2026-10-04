"""ServiceNow Table API client."""

from __future__ import annotations

from typing import Any

import requests


class ServiceNowClient:
    def __init__(
        self,
        instance: str,
        username: str,
        password: str,
        verify: bool | str = True,
        timeout: int = 30,
    ) -> None:
        host = instance if "." in instance else f"{instance}.service-now.com"
        self.base_url = f"https://{host}/api/now/table"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify
        self.session.auth = (username, password)
        self.session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )

    def create_record(self, table: str, fields: dict[str, Any]) -> dict[str, Any]:
        """Insert a record and return it (``sys_id``, ``number``, ...)."""
        response = self.session.post(f"{self.base_url}/{table}", json=fields, timeout=self.timeout)
        response.raise_for_status()
        return response.json().get("result", {})

    def update_record(self, table: str, sys_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        response = self.session.patch(
            f"{self.base_url}/{table}/{sys_id}", json=fields, timeout=self.timeout
        )
        response.raise_for_status()
        return response.json().get("result", {})
