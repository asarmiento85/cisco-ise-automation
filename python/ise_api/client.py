"""Thin HTTP client around Cisco ISE ERS + OpenAPI endpoints.

Uses httpx under the hood. Handles:
  - basic auth + common headers
  - pagination on ERS list endpoints (page= / size=)
  - retry with backoff on 429 / transient 5xx
  - self-signed cert friendliness (verify toggle)

ERS base:     /ers/config/
OpenAPI base: /api/v1/
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urljoin

import httpx
from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

# Walk up from this file to find the nearest .env (repo root).
_HERE = Path(__file__).resolve()
for _parent in _HERE.parents:
    _candidate = _parent / ".env"
    if _candidate.exists():
        load_dotenv(_candidate)
        break


class ISESettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ISE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    host: str = Field(description="ISE PAN hostname or IP")
    port: int = 443
    username: str
    password: str
    verify_ssl: bool = False
    timeout: float = 30.0

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class ISEClient:
    """Minimal ISE REST client. Instantiate once, reuse the session."""

    def __init__(self, settings: ISESettings | None = None):
        self.s = settings or ISESettings()  # type: ignore[call-arg]
        self._client = httpx.Client(
            base_url=self.s.base_url,
            auth=(self.s.username, self.s.password),
            verify=self.s.verify_ssl,
            timeout=self.s.timeout,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    # ----- context mgmt -----
    def __enter__(self) -> "ISEClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    # ----- core request -----
    @retry(
        reraise=True,
        retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(4),
    )
    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code == 429 or resp.status_code >= 500:
            resp.raise_for_status()
        return resp

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, json: dict | None = None, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, json=json, **kwargs)

    def put(self, path: str, json: dict | None = None, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", path, json=json, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", path, **kwargs)

    # ----- ERS pagination helper -----
    def ers_paginate(self, resource: str, page_size: int = 100) -> Iterator[dict]:
        """Yield every item for an ERS collection (e.g. 'networkdevice')."""
        page = 1
        while True:
            r = self.get(
                urljoin("/ers/config/", resource),
                params={"size": page_size, "page": page},
            )
            r.raise_for_status()
            body = r.json()
            resources = (
                body.get("SearchResult", {}).get("resources", [])
            )
            if not resources:
                return
            yield from resources
            # next page link is present if more data
            next_link = body.get("SearchResult", {}).get("nextPage")
            if not next_link:
                return
            page += 1

    # ----- health -----
    def ping(self) -> bool:
        """Cheap liveness check — just hits ERS and returns True on 200."""
        try:
            r = self.get("/ers/config/networkdevice", params={"size": 1})
            return r.status_code == 200
        except httpx.HTTPError:
            return False
