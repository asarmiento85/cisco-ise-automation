"""Network Device (NAD) operations via ERS."""

from __future__ import annotations

from typing import Any, Iterable

from ise_api.client import ISEClient


def list_nads(client: ISEClient) -> list[dict]:
    return list(client.ers_paginate("networkdevice"))


def get_nad_by_name(client: ISEClient, name: str) -> dict | None:
    r = client.get(f"/ers/config/networkdevice/name/{name}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json().get("NetworkDevice")


def create_nad(
    client: ISEClient,
    *,
    name: str,
    ip: str,
    mask: int = 32,
    shared_secret: str,
    location_ndg: str = "Location#All Locations#Lab",
    device_type_ndg: str = "Device Type#All Device Types#Switch",
    description: str = "Managed by ise-automation",
    coa_port: int = 1700,
) -> dict:
    payload: dict[str, Any] = {
        "NetworkDevice": {
            "name": name,
            "description": description,
            "authenticationSettings": {
                "networkProtocol": "RADIUS",
                "radiusSharedSecret": shared_secret,
                "enableKeyWrap": False,
                "dtlsRequired": False,
                "enabled": True,
            },
            "profileName": "Cisco",
            "coaPort": coa_port,
            "NetworkDeviceIPList": [{"ipaddress": ip, "mask": mask}],
            "NetworkDeviceGroupList": [
                location_ndg,
                device_type_ndg,
                "IPSEC#Is IPSEC Device#No",
            ],
        }
    }
    r = client.post("/ers/config/networkdevice", json=payload)
    r.raise_for_status()
    return payload["NetworkDevice"]


def delete_nad(client: ISEClient, name: str) -> bool:
    nad = get_nad_by_name(client, name)
    if not nad:
        return False
    r = client.delete(f"/ers/config/networkdevice/{nad['id']}")
    return r.status_code in (200, 204)


def bulk_create_nads(client: ISEClient, rows: Iterable[dict]) -> list[dict]:
    """Rows are dicts with keys: name, ip, shared_secret, (optional) description."""
    results = []
    for row in rows:
        results.append(
            create_nad(
                client,
                name=row["name"],
                ip=row["ip"],
                shared_secret=row["shared_secret"],
                description=row.get("description", "Managed by ise-automation"),
            )
        )
    return results
