"""Endpoint (client device) operations via ERS."""

from __future__ import annotations

from ise_api.client import ISEClient


def list_endpoints(client: ISEClient) -> list[dict]:
    return list(client.ers_paginate("endpoint"))


def get_endpoint_by_mac(client: ISEClient, mac: str) -> dict | None:
    r = client.get(f"/ers/config/endpoint/name/{mac}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json().get("ERSEndPoint")


def create_endpoint(
    client: ISEClient,
    *,
    mac: str,
    group_id: str,
    description: str = "Managed by ise-automation",
    static_group_assignment: bool = True,
) -> dict:
    payload = {
        "ERSEndPoint": {
            "name": mac,
            "description": description,
            "mac": mac,
            "groupId": group_id,
            "staticGroupAssignment": static_group_assignment,
            "staticProfileAssignment": False,
        }
    }
    r = client.post("/ers/config/endpoint", json=payload)
    r.raise_for_status()
    return payload["ERSEndPoint"]
