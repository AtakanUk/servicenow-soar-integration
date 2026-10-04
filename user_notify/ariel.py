"""QRadar Ariel (AQL) search client."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

import requests

log = logging.getLogger(__name__)


class AqlTimeoutError(TimeoutError):
    pass


class AqlFailedError(RuntimeError):
    pass


class ArielClient:
    def __init__(
        self,
        host: str,
        token: str,
        verify: bool | str = True,
        poll_interval: float = 2.0,
        timeout: float = 300.0,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = f"https://{host}/api/ariel"
        self.poll_interval = poll_interval
        self.timeout = timeout
        self._sleep = sleep
        self.session = session or requests.Session()
        self.session.verify = verify
        self.session.headers.update({"SEC": token, "Accept": "application/json"})

    def search(self, aql: str) -> list[dict[str, Any]]:
        """Run an AQL query and return the result rows (``events`` or ``flows``)."""
        response = self.session.post(
            f"{self.base_url}/searches", params={"query_expression": aql}, timeout=60
        )
        response.raise_for_status()
        search_id = response.json()["search_id"]

        waited = 0.0
        while True:
            status = self.session.get(f"{self.base_url}/searches/{search_id}", timeout=60)
            status.raise_for_status()
            state = status.json().get("status")
            if state == "COMPLETED":
                break
            if state in {"CANCELED", "ERROR"}:
                raise AqlFailedError(f"AQL search {search_id} ended with status {state}")
            if waited >= self.timeout:
                raise AqlTimeoutError(
                    f"AQL search {search_id} did not complete within {self.timeout:.0f}s"
                )
            self._sleep(self.poll_interval)
            waited += self.poll_interval

        results = self.session.get(f"{self.base_url}/searches/{search_id}/results", timeout=60)
        results.raise_for_status()
        body = results.json()
        return body.get("events") or body.get("flows") or []
