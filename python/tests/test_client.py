"""Smoke tests that don't require a live ISE."""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from ise_api.client import ISEClient, ISESettings


@pytest.fixture
def settings() -> ISESettings:
    return ISESettings(host="ise.test", username="u", password="p", verify_ssl=False)  # type: ignore[call-arg]


def test_ping_ok(httpx_mock: HTTPXMock, settings: ISESettings) -> None:
    httpx_mock.add_response(
        url="https://ise.test:443/ers/config/networkdevice?size=1",
        status_code=200,
        json={"SearchResult": {"total": 0, "resources": []}},
    )
    with ISEClient(settings) as c:
        assert c.ping() is True


def test_ping_fails_on_401(httpx_mock: HTTPXMock, settings: ISESettings) -> None:
    httpx_mock.add_response(
        url="https://ise.test:443/ers/config/networkdevice?size=1",
        status_code=401,
    )
    with ISEClient(settings) as c:
        # ping returns True only on 200
        assert c.ping() is False


def test_ers_paginate_stops_on_empty(httpx_mock: HTTPXMock, settings: ISESettings) -> None:
    httpx_mock.add_response(
        url="https://ise.test:443/ers/config/networkdevice?size=100&page=1",
        json={"SearchResult": {"resources": []}},
    )
    with ISEClient(settings) as c:
        items = list(c.ers_paginate("networkdevice"))
    assert items == []
