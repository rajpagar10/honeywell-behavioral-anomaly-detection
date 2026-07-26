"""Small typed client for the local Behavioral Security API."""

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class APIUnavailableError(RuntimeError):
    """Raised when the dashboard cannot reach a healthy backend."""


@dataclass(frozen=True, slots=True)
class SOCAPIClient:
    """Read and control the local SOC API."""

    base_url: str
    timeout_seconds: float = 5.0

    def get(self, path: str) -> Any:
        """Fetch and decode one JSON API resource."""

        return self._request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        """Send a JSON command and decode the response."""

        return self._request("POST", path, payload)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        """Execute one bounded HTTP request."""

        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            f"{self.base_url.rstrip('/')}{path}",
            data=body,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            detail = error.read().decode("utf-8")
            raise APIUnavailableError(f"API returned {error.code}: {detail}") from error
        except (URLError, TimeoutError) as error:
            raise APIUnavailableError(f"API unavailable at {self.base_url}") from error
