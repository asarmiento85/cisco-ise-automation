"""OpenAPI-backed policy operations (policy sets, authZ/authN rules).

Note: policy endpoints live under /api/v1/policy/* in ISE 3.x OpenAPI.
"""

from __future__ import annotations

from ise_api.client import ISEClient


def list_policy_sets(client: ISEClient) -> list[dict]:
    r = client.get("/api/v1/policy/network-access/policy-set")
    r.raise_for_status()
    return r.json().get("response", [])


def list_authz_rules(client: ISEClient, policy_set_id: str) -> list[dict]:
    r = client.get(
        f"/api/v1/policy/network-access/policy-set/{policy_set_id}/authorization"
    )
    r.raise_for_status()
    return r.json().get("response", [])


def list_authn_rules(client: ISEClient, policy_set_id: str) -> list[dict]:
    r = client.get(
        f"/api/v1/policy/network-access/policy-set/{policy_set_id}/authentication"
    )
    r.raise_for_status()
    return r.json().get("response", [])
