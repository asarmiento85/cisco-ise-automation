"""Deep read-only audit of a Cisco ISE deployment.

Two stages:

  collect(client) -> dict     # everything we could pull, raw
  analyze(data)   -> list     # heuristic findings derived from the dict

All HTTP is GETs. Endpoints that don't exist on the deployment (older patch,
disabled persona, feature off) are skipped silently and noted in `coverage`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from ise_api.client import ISEClient

# ---------------------------------------------------------------------------
# Credential redaction
# ---------------------------------------------------------------------------
# ISE's ERS API returns several credential fields in PLAINTEXT to authenticated
# admins (this is by design — same as what the GUI shows when editing a NAD).
# We strip them before persisting any report output so JSON/HTML/PDF artifacts
# are safe to share.

_SECRET_FIELD_NAMES = {
    "radiusSharedSecret",
    "sharedSecret",
    "secondRadiusSharedSecret",
    "keyEncryptionKey",
    "messageAuthenticatorCodeKey",
    "password",
    "enablePassword",
    "snmpRoCommunity",
    "snmpRwCommunity",
    "tacacsSharedSecret",
    "privateKey",
}
_REDACTED = "<REDACTED>"


def _redact(obj):
    """Recursively replace any value whose key matches _SECRET_FIELD_NAMES."""
    if isinstance(obj, dict):
        return {k: (_REDACTED if k in _SECRET_FIELD_NAMES else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _try(fn: Callable[[], Any], coverage: dict, key: str) -> Any:
    """Run fn, record success/failure in coverage map, return result or None."""
    try:
        out = fn()
        coverage[key] = {"ok": True, "count": _count(out)}
        return out
    except httpx.HTTPStatusError as e:
        coverage[key] = {"ok": False, "status": e.response.status_code}
        return None
    except httpx.HTTPError as e:
        coverage[key] = {"ok": False, "error": str(e)[:120]}
        return None
    except Exception as e:  # noqa: BLE001
        coverage[key] = {"ok": False, "error": f"{type(e).__name__}: {e}"[:120]}
        return None


class _NotifyingCoverage(dict):
    """Coverage map that reports each completed endpoint to a callback.

    Every collector call records its result via `coverage[key] = {...}`, so
    hooking __setitem__ gives per-endpoint progress with no changes to the
    collection logic. Callback signature: cb(endpoint_key, completed_count).
    """

    def __init__(self, progress_cb: Callable[[str, int], None] | None = None):
        super().__init__()
        self._cb = progress_cb

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)
        if self._cb is not None:
            try:
                self._cb(key, len(self))
            except Exception:  # noqa: BLE001 — progress must never break collection
                pass


def _count(x: Any) -> int | None:
    if x is None:
        return None
    if isinstance(x, (list, tuple)):
        return len(x)
    if isinstance(x, dict):
        return len(x)
    return None


def _ers_list(c: ISEClient, resource: str) -> list[dict]:
    return list(c.ers_paginate(resource))


def _ers_count(c: ISEClient, resource: str, filter_q: str | None = None) -> int:
    """Cheap total-count from an ERS collection without pulling every record.

    ERS SearchResult includes a 'total' field. We request size=1 to keep the
    payload tiny — useful for large tables like endpoints where we want the
    count but never the MAC addresses.
    """
    params: dict[str, Any] = {"size": 1}
    if filter_q:
        params["filter"] = filter_q
    r = c.get(f"/ers/config/{resource}", params=params)
    r.raise_for_status()
    return int(r.json().get("SearchResult", {}).get("total", 0))


def _ers_detail(c: ISEClient, resource: str, items: list[dict]) -> list[dict]:
    out: list[dict] = []
    for item in items:
        rid = item.get("id")
        if not rid:
            out.append(item)
            continue
        r = c.get(f"/ers/config/{resource}/{rid}")
        if r.status_code != 200:
            out.append(item)
            continue
        body = r.json()
        wrapped = next(iter(body.values())) if isinstance(body, dict) and body else item
        out.append(wrapped if isinstance(wrapped, dict) else item)
    return out


def _openapi_get(c: ISEClient, path: str) -> Any:
    r = c.get(path)
    r.raise_for_status()
    body = r.json()
    if isinstance(body, dict) and "response" in body:
        return body["response"]
    return body


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


def collect(c: ISEClient, progress_cb: Callable[[str, int], None] | None = None) -> dict[str, Any]:
    coverage: dict[str, Any] = _NotifyingCoverage(progress_cb)
    data: dict[str, Any] = {
        "meta": {
            "pan": c.s.base_url,
            "user": c.s.username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "coverage": coverage,
    }

    # --- deployment / system ---
    data["nodes"] = _try(lambda: _openapi_get(c, "/api/v1/deployment/node"), coverage, "deployment.nodes") or []
    data["patches"] = _try(lambda: _openapi_get(c, "/api/v1/patch"), coverage, "system.patches") or []
    data["hotpatches"] = _try(lambda: _openapi_get(c, "/api/v1/hotpatch"), coverage, "system.hotpatches") or []
    data["license_smart"] = _try(lambda: _openapi_get(c, "/api/v1/license/system/smart-state"), coverage, "system.license.smart") or {}
    data["license_tier"] = _try(lambda: _openapi_get(c, "/api/v1/license/system/tier-state"), coverage, "system.license.tier") or []
    data["repositories"] = _try(lambda: _openapi_get(c, "/api/v1/repository"), coverage, "system.repositories") or []
    data["backup_schedule_config"] = _try(lambda: _openapi_get(c, "/api/v1/backup-restore/config-backup/schedule"), coverage, "system.backup.config_schedule") or {}

    # --- NADs ---
    nads_summary = _try(lambda: _ers_list(c, "networkdevice"), coverage, "nads.list") or []
    data["nads"] = _try(lambda: _ers_detail(c, "networkdevice", nads_summary), coverage, "nads.detail") or nads_summary
    data["ndgs"] = _try(lambda: _ers_list(c, "networkdevicegroup"), coverage, "nads.groups") or []

    # --- identity ---
    data["user_identity_groups"] = _try(lambda: _ers_list(c, "identitygroup"), coverage, "identity.user_groups") or []
    data["endpoint_identity_groups"] = _try(lambda: _ers_list(c, "endpointgroup"), coverage, "identity.endpoint_groups") or []
    internal_users = _try(lambda: _ers_list(c, "internaluser"), coverage, "identity.internal_users") or []
    # Don't persist full user records (PII); keep only safe metadata
    data["internal_users"] = [
        {"name": u.get("name"), "enabled": u.get("enabled"), "identityGroups": u.get("identityGroups"), "changePassword": u.get("changePassword")}
        for u in internal_users
    ]
    admins = _try(lambda: _ers_list(c, "adminuser"), coverage, "identity.admin_users") or []
    data["admin_users"] = _try(lambda: _ers_detail(c, "adminuser", admins), coverage, "identity.admin_users_detail") or admins
    data["identity_sequences"] = _try(lambda: _ers_list(c, "idstoresequence"), coverage, "identity.sequences") or []
    data["ad_join_points"] = _try(lambda: _openapi_get(c, "/api/v1/active-directory"), coverage, "identity.ad_join_points") or []
    data["external_radius"] = _try(lambda: _ers_list(c, "externalradiusserver"), coverage, "identity.external_radius") or []

    # --- policy: network access ---
    ap_summary = _try(lambda: _ers_list(c, "allowedprotocols"), coverage, "policy.allowed_protocols") or []
    # Pull detail so we can inspect which EAP / legacy methods are enabled.
    data["allowed_protocols"] = _try(lambda: _ers_detail(c, "allowedprotocols", ap_summary), coverage, "policy.allowed_protocols_detail") or ap_summary
    data["authz_profiles_summary"] = _try(lambda: _ers_list(c, "authorizationprofile"), coverage, "policy.authz_profiles") or []
    data["authz_profiles"] = _try(lambda: _ers_detail(c, "authorizationprofile", data["authz_profiles_summary"]), coverage, "policy.authz_profiles_detail") or data["authz_profiles_summary"]
    data["dacls"] = _try(lambda: _ers_list(c, "downloadableacl"), coverage, "policy.dacls") or []

    policy_sets = _try(lambda: _openapi_get(c, "/api/v1/policy/network-access/policy-set"), coverage, "policy.network_access.sets") or []
    data["policy_sets"] = policy_sets
    ps_detail: list[dict] = []
    for ps in policy_sets:
        psid = ps.get("id")
        if not psid:
            continue
        auth = _try(lambda i=psid: _openapi_get(c, f"/api/v1/policy/network-access/policy-set/{i}/authentication"), coverage, f"policy.network_access.set[{psid}].auth")
        authz = _try(lambda i=psid: _openapi_get(c, f"/api/v1/policy/network-access/policy-set/{i}/authorization"), coverage, f"policy.network_access.set[{psid}].authz")
        excp = _try(lambda i=psid: _openapi_get(c, f"/api/v1/policy/network-access/policy-set/{i}/exception"), coverage, f"policy.network_access.set[{psid}].exception")
        ps_detail.append({"policy_set": ps, "authentication": auth or [], "authorization": authz or [], "exception": excp or []})
    data["policy_sets_detail"] = ps_detail

    # Network access conditions library
    data["nac_conditions"] = _try(lambda: _openapi_get(c, "/api/v1/policy/network-access/condition"), coverage, "policy.network_access.conditions") or []

    # --- policy: device admin (TACACS+) ---
    da_sets = _try(lambda: _openapi_get(c, "/api/v1/policy/device-admin/policy-set"), coverage, "policy.device_admin.sets") or []
    data["device_admin_sets"] = da_sets
    da_detail: list[dict] = []
    for ps in da_sets:
        psid = ps.get("id")
        if not psid:
            continue
        auth = _try(lambda i=psid: _openapi_get(c, f"/api/v1/policy/device-admin/policy-set/{i}/authentication"), coverage, f"policy.device_admin.set[{psid}].auth")
        authz = _try(lambda i=psid: _openapi_get(c, f"/api/v1/policy/device-admin/policy-set/{i}/authorization"), coverage, f"policy.device_admin.set[{psid}].authz")
        da_detail.append({"policy_set": ps, "authentication": auth or [], "authorization": authz or []})
    data["device_admin_sets_detail"] = da_detail
    data["tacacs_command_sets"] = _try(lambda: _openapi_get(c, "/api/v1/policy/device-admin/command-sets"), coverage, "policy.device_admin.command_sets") or []
    data["tacacs_profiles"] = _try(lambda: _openapi_get(c, "/api/v1/policy/device-admin/shell-profiles"), coverage, "policy.device_admin.shell_profiles") or []

    # --- profiler ---
    data["profiler_policies"] = _try(lambda: _ers_list(c, "profilerprofile"), coverage, "profiler.policies") or []

    # --- TrustSec ---
    data["sgts"] = _try(lambda: _ers_list(c, "sgt"), coverage, "trustsec.sgt") or []
    data["sgacls"] = _try(lambda: _ers_list(c, "sgacl"), coverage, "trustsec.sgacl") or []
    data["egress_matrix_cells"] = _try(lambda: _ers_list(c, "egressmatrixcell"), coverage, "trustsec.egress_matrix") or []

    # --- guest ---
    data["guest_types"] = _try(lambda: _ers_list(c, "guesttype"), coverage, "guest.types") or []
    data["sponsor_groups"] = _try(lambda: _ers_list(c, "sponsorgroup"), coverage, "guest.sponsor_groups") or []
    data["portals"] = _try(lambda: _ers_list(c, "portal"), coverage, "guest.portals") or []

    # --- certificates ---
    node_host = (data["nodes"][0].get("hostname") if data["nodes"] else c.s.host)
    data["pan_hostname"] = node_host
    data["system_certs"] = _try(lambda: _openapi_get(c, f"/api/v1/certs/system-certificate/{node_host}"), coverage, "certs.system") or []
    data["trusted_certs"] = _try(lambda: _openapi_get(c, "/api/v1/certs/trusted-certificate"), coverage, "certs.trusted") or []

    # --- per-node detail (version / patch / replication consistency) ---
    # ERS 'node' gives per-node version + replication role; OpenAPI deployment/node
    # gives persona/status. We pull both and reconcile in the analyzer.
    data["ers_nodes"] = _try(lambda: _ers_list(c, "node"), coverage, "deployment.ers_nodes") or []

    # --- RADIUS server sequences ---
    data["radius_sequences"] = _try(lambda: _ers_list(c, "radiusserversequence"), coverage, "identity.radius_sequences") or []

    # --- endpoint DB stats (count only; we never pull endpoint records / MACs) ---
    data["endpoint_count"] = _try(lambda: _ers_count(c, "endpoint"), coverage, "identity.endpoint_count")
    data["unknown_endpoint_count"] = _try(
        lambda: _ers_count(c, "endpoint", filter_q="groupId.EQ.aa0e8b20-8bff-11e6-996c-525400b48521"),
        coverage, "identity.unknown_endpoint_count",
    )

    # --- security settings (best-effort; routes vary by version) ---
    data["security_settings"] = _try(lambda: _openapi_get(c, "/api/v1/system-settings/security"), coverage, "security.settings")
    data["admin_password_policy"] = _try(lambda: _openapi_get(c, "/api/v1/system-settings/admin-access/authentication/password-policy"), coverage, "security.admin_password_policy")
    data["admin_session_settings"] = _try(lambda: _openapi_get(c, "/api/v1/system-settings/admin-access/session/timeout"), coverage, "security.admin_session")
    data["fips_status"] = _try(lambda: _openapi_get(c, "/api/v1/system-settings/fips"), coverage, "security.fips")

    # --- logging targets / data retention (best-effort) ---
    data["logging_targets"] = _try(lambda: _openapi_get(c, "/api/v1/system-settings/logging/remote-logging-target"), coverage, "logging.remote_targets")
    data["mnt_retention"] = _try(lambda: _openapi_get(c, "/api/v1/system-settings/data-retention"), coverage, "logging.data_retention")

    # --- posture / client provisioning feed (best-effort) ---
    data["posture_settings"] = _try(lambda: _openapi_get(c, "/api/v1/posture/global-setting"), coverage, "posture.global_settings")

    # --- pxGrid (best-effort) ---
    data["pxgrid_settings"] = _try(lambda: _openapi_get(c, "/api/v1/pxgrid/settings"), coverage, "pxgrid.settings")

    # --- profiler feed service (best-effort) ---
    data["profiler_feed"] = _try(lambda: _openapi_get(c, "/api/v1/profiler/profiler-feed-status"), coverage, "profiler.feed_status")

    # Scrub credential fields the ERS API returns in plaintext.
    # Coverage map is metadata-only, so leave it alone.
    cov = data.pop("coverage")
    data = _redact(data)
    data["coverage"] = cov
    return data


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


_SEVERITIES = ("high", "med", "low", "info")

_CERT_DATE_FORMATS = (
    "%a %b %d %H:%M:%S %Z %Y",       # Thu Jun 19 17:24:35 UTC 2025
    "%a, %d %b %Y %H:%M:%S %Z",      # RFC1123
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
)


def _parse_cert_date(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in _CERT_DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _finding(severity: str, category: str, msg: str, ref: str | None = None, rec_key: str | None = None) -> dict:
    return {
        "severity": severity,
        "category": category,
        "msg": msg,
        "ref": ref or "",
        "rec_key": rec_key or "",
    }


def analyze(data: dict[str, Any]) -> list[dict]:
    f: list[dict] = []
    now = datetime.now(timezone.utc)

    # --- certs ---
    for cert in data.get("system_certs", []):
        exp = _parse_cert_date(cert.get("expirationDate"))
        used = cert.get("usedBy") or "-"
        name = (cert.get("friendlyName") or "").strip()
        if exp:
            days = (exp - now).days
            if days < 0:
                f.append(_finding("high", "Certificates", f"PAN cert '{name}' EXPIRED {abs(days)} days ago — services: {used}.", "system_certs", "REC-CERT-001"))
            elif days < 30:
                f.append(_finding("high", "Certificates", f"PAN cert '{name}' expires in {days} days — services: {used}.", "system_certs", "REC-CERT-001"))
            elif days < 60:
                f.append(_finding("med", "Certificates", f"PAN cert '{name}' expires in {days} days.", "system_certs", "REC-CERT-001"))
        if "sha1" in str(cert.get("signatureAlgorithm", "")).lower():
            f.append(_finding("med", "Certificates", f"PAN cert '{name}' uses SHA-1 signature.", "system_certs", "REC-CERT-002"))
        if cert.get("selfSigned"):
            f.append(_finding("low", "Certificates", f"PAN cert '{name}' is self-signed — fine for lab, replace for prod.", "system_certs", "REC-CERT-003"))

    expiring_trusted = 0
    for tc in data.get("trusted_certs", []):
        exp = _parse_cert_date(tc.get("expirationDate"))
        if exp and (exp - now).days < 30:
            expiring_trusted += 1
    if expiring_trusted:
        f.append(_finding("med", "Certificates", f"{expiring_trusted} trusted certs expire within 30 days.", "trusted_certs", "REC-CERT-004"))

    # --- NAD hygiene ---
    nad_ips: dict[str, list[str]] = {}
    for n in data.get("nads", []):
        name = n.get("name", "-")
        ips = n.get("NetworkDeviceIPList") or []
        groups = n.get("NetworkDeviceGroupList") or []
        if not ips:
            f.append(_finding("high", "NAD inventory", f"NAD '{name}' has no IP — orphan entry.", "nads", "REC-NAD-001"))
        for ip in ips:
            ipa = ip.get("ipaddress")
            if ipa:
                nad_ips.setdefault(ipa, []).append(name)
        if not any(g.startswith("Location#") for g in groups):
            f.append(_finding("low", "NAD inventory", f"NAD '{name}' missing Location NDG.", "nads", "REC-NAD-003"))
        if not any(g.startswith("Device Type#") for g in groups):
            f.append(_finding("low", "NAD inventory", f"NAD '{name}' missing Device Type NDG.", "nads", "REC-NAD-003"))
        coa = n.get("coaPort")
        if coa and coa != 1700:
            f.append(_finding("info", "NAD inventory", f"NAD '{name}' uses CoA port {coa} (non-default).", "nads", "REC-NAD-004"))
    for ipa, names in nad_ips.items():
        if len(names) > 1:
            f.append(_finding("high", "NAD inventory", f"Duplicate IP {ipa} on NADs: {', '.join(names)}.", "nads", "REC-NAD-002"))

    # --- admins ---
    admin_count = 0
    super_count = 0
    for a in data.get("admin_users", []):
        if str(a.get("name", "")).startswith("~internal"):
            continue
        admin_count += 1
        if a.get("name") == "admin" and a.get("enabled"):
            f.append(_finding("med", "Admin access", "Default 'admin' account enabled — confirm MFA + rotation policy.", "admin_users", "REC-ADMIN-001"))
        groups = a.get("adminGroups") or []
        if isinstance(groups, str):
            groups = [groups]
        if any("Super Admin" in str(g) for g in groups):
            super_count += 1
    if super_count > 3:
        f.append(_finding("med", "Admin access", f"{super_count} Super Admin accounts — minimize membership.", "admin_users", "REC-ADMIN-002"))

    # --- backups ---
    # Only assert "missing" when the endpoint actually answered — an API
    # failure (e.g. Open API disabled → 302) is absence of evidence, not
    # evidence of absence.
    cov = data.get("coverage", {})

    def _cov_ok(key: str) -> bool:
        v = cov.get(key)
        return isinstance(v, dict) and bool(v.get("ok"))

    if data.get("repositories"):
        if any((r.get("protocol") or "").upper() == "FTP" for r in data["repositories"]):
            f.append(_finding("med", "Backups", "Backup repo uses FTP — switch to SFTP/HTTPS for credential & data integrity.", "repositories", "REC-BACKUP-002"))
    elif _cov_ok("system.repositories"):
        f.append(_finding("high", "Backups", "No backup repository configured — DR posture broken.", "repositories", "REC-BACKUP-001"))
    sched = data.get("backup_schedule_config") or {}
    if _cov_ok("system.backup.config_schedule") and isinstance(sched, dict) and not sched.get("scheduleOptions"):
        f.append(_finding("med", "Backups", "No scheduled configuration backup detected.", "backup_schedule_config", "REC-BACKUP-003"))

    # --- API service availability (meta-finding) ---
    # A burst of HTTP 302s on OpenAPI routes means the Open API service is
    # disabled: those requests bounce to the GUI login page. Surface it as a
    # finding so the operator knows the report is partial and how to fix it.
    redirected = [
        k for k, v in cov.items()
        if isinstance(v, dict) and not v.get("ok") and str(v.get("status")) == "302"
    ]
    if len(redirected) >= 3:
        f.append(_finding(
            "high", "API access",
            f"{len(redirected)} API endpoints redirected to the login page (HTTP 302) — the Open API "
            f"service is disabled on this deployment, so deployment/policy-set/certificate/system "
            f"sections of this report are missing. Enable it and re-run for full coverage.",
            "coverage", "REC-API-001",
        ))

    # --- policy ---
    used_authz_names: set[str] = set()
    for ps in data.get("policy_sets_detail", []):
        for rule in ps.get("authorization", []) or []:
            r = rule.get("rule", {})
            profiles = rule.get("profile", []) or []
            for p in profiles:
                used_authz_names.add(p)
            if r.get("state", "").lower() == "disabled":
                continue
            cond = r.get("condition") or {}
            # Catch-all: condition empty/true with PermitAccess
            if (not cond or cond.get("conditionType") == "ConditionAttributes" and not cond.get("attributeName")) and "PermitAccess" in profiles:
                f.append(_finding("high", "Policy", f"Authz rule '{r.get('name')}' in set '{ps['policy_set'].get('name')}' grants PermitAccess with empty/true condition.", "policy_sets_detail", "REC-POLICY-001"))
    all_authz = {p.get("name") for p in data.get("authz_profiles", [])}
    unused = sorted(n for n in all_authz if n and n not in used_authz_names and n not in {"DenyAccess", "PermitAccess", "Cisco_WebAuth", "Cisco_Temporal_Onboard"})
    if unused:
        f.append(_finding("low", "Policy", f"{len(unused)} authz profiles defined but not referenced by any active rule: {', '.join(unused[:8])}{'…' if len(unused)>8 else ''}.", "authz_profiles", "REC-POLICY-002"))

    # --- TACACS device admin ---
    if data.get("device_admin_sets_detail"):
        per_cmd_rules = 0
        for ps in data["device_admin_sets_detail"]:
            for rule in ps.get("authorization", []) or []:
                if rule.get("commands"):
                    per_cmd_rules += 1
        if per_cmd_rules:
            f.append(_finding("med", "Device admin", f"{per_cmd_rules} TACACS+ authz rules use per-command authorization — high-blast-radius failure mode if TACACS is unreachable.", "device_admin_sets_detail", "REC-TACACS-001"))

    # --- TrustSec dormancy ---
    if data.get("sgts") and not data.get("egress_matrix_cells"):
        f.append(_finding("info", "TrustSec", f"{len(data['sgts'])} SGTs defined but egress matrix is empty — TrustSec configured but not enforced.", "sgts", "REC-TRUSTSEC-001"))

    # --- profiler sprawl ---
    if len(data.get("profiler_policies", [])) > 600:
        f.append(_finding("info", "Profiler", f"{len(data['profiler_policies'])} profiler policies — normal for stock feed; verify custom additions are tracked.", "profiler_policies", "REC-PROFILER-001"))

    # --- internal users ---
    must_change = sum(1 for u in data.get("internal_users", []) if u.get("changePassword"))
    if must_change:
        f.append(_finding("low", "Identity", f"{must_change} internal users flagged 'must change password'.", "internal_users", "REC-IDENTITY-001"))

    # =====================================================================
    # MIGRATION-CRITICAL CHECKS
    # =====================================================================

    # --- weak / deprecated authentication methods in Allowed Protocols ---
    # These flags are exactly what migrates forward unchanged from old ISE.
    _WEAK_METHODS = {
        "allowPapAscii": ("PAP/ASCII", "med"),
        "allowChap": ("CHAP", "med"),
        "allowMsChapV1": ("MS-CHAPv1", "high"),
        "allowEapMd5": ("EAP-MD5", "high"),
        "allowLeap": ("LEAP", "high"),
        "allowPreferredEapProtocol": (None, None),  # not weak; ignore
    }
    for ap in data.get("allowed_protocols", []):
        ap_name = ap.get("name", "?")
        enabled_weak = []
        for flag, (label, sev) in _WEAK_METHODS.items():
            if label and ap.get(flag) is True:
                enabled_weak.append((label, sev))
        if enabled_weak:
            worst = "high" if any(s == "high" for _, s in enabled_weak) else "med"
            labels = ", ".join(sorted(lbl for lbl, _ in enabled_weak))
            f.append(_finding(worst, "Weak auth methods", f"Allowed Protocols '{ap_name}' permits deprecated method(s): {labels}. Common migration carryover.", "allowed_protocols", "REC-AUTH-001"))
        # EAP-FAST anonymous PAC provisioning is another legacy carryover
        eapfast = ap.get("eapFast") or {}
        if isinstance(eapfast, dict) and eapfast.get("allowEapFast") and eapfast.get("eapFastAllowAnonymProvisioning"):
            f.append(_finding("med", "Weak auth methods", f"Allowed Protocols '{ap_name}' allows EAP-FAST anonymous PAC provisioning (unauthenticated). Review post-migration.", "allowed_protocols", "REC-AUTH-001"))
        # TLS 1.0 / 1.1 for EAP-TLS
        eaptls = ap.get("eapTls") or {}
        if isinstance(eaptls, dict):
            tls_versions = eaptls.get("allowedTlsVersions") or eaptls.get("eapTlsAllowTlsVersions")
            if tls_versions and any(v in str(tls_versions) for v in ("1.0", "1.1", "TLSV1_0", "TLSV1_1")):
                f.append(_finding("high", "Weak auth methods", f"Allowed Protocols '{ap_name}' permits TLS 1.0/1.1 for EAP-TLS.", "allowed_protocols", "REC-TLS-001"))

    # --- node version / replication consistency (post-migration) ---
    node_versions = set()
    for n in data.get("ers_nodes", []):
        ver = n.get("nodeServiceTypes") and None  # placeholder; version field varies
        ver = n.get("softwareVersion") or n.get("version") or n.get("patchVersion")
        if ver:
            node_versions.add(str(ver))
        repl = (n.get("replicationStatus") or n.get("nodeStatus") or "").upper()
        if repl and repl not in ("CONNECTED", "REPLICATION_OK", "SYNC_COMPLETED", "ACTIVE"):
            f.append(_finding("high", "Node health", f"Node '{n.get('hostName') or n.get('name')}' replication/status = '{repl}' — verify sync after migration.", "ers_nodes", "REC-NODE-001"))
    if len(node_versions) > 1:
        f.append(_finding("high", "Node health", f"Nodes report MIXED software versions: {', '.join(sorted(node_versions))}. All nodes must match after migration.", "ers_nodes", "REC-NODE-002"))

    # --- broken certificate chain heuristic ---
    trusted_subjects = []
    for tc in data.get("trusted_certs", []):
        subj = (tc.get("subject") or tc.get("friendlyName") or "")
        trusted_subjects.append(str(subj))
    trusted_blob = " | ".join(trusted_subjects)
    for cert in data.get("system_certs", []):
        if cert.get("selfSigned"):
            continue
        issuer = (cert.get("issuedBy") or cert.get("issuer") or "").strip()
        name = (cert.get("friendlyName") or "").strip()
        if issuer:
            # crude CN extraction
            cn = issuer
            if "CN=" in issuer:
                cn = issuer.split("CN=", 1)[1].split(",")[0].strip()
            if cn and cn not in trusted_blob:
                f.append(_finding("med", "Certificates", f"System cert '{name}' issuer '{cn}' not found in Trusted Certificates store — possible broken chain post-migration.", "system_certs", "REC-CERT-005"))

    # --- stale external references (servers / repos pointing at old infra) ---
    stale_targets = []
    for s in data.get("external_radius", []):
        stale_targets.append(("External RADIUS", s.get("name"), s.get("hostIP") or s.get("ipaddress")))
    for r in data.get("repositories", []):
        stale_targets.append(("Repository", r.get("name"), r.get("serverName")))
    for lt in (data.get("logging_targets") or []):
        if isinstance(lt, dict):
            stale_targets.append(("Logging target", lt.get("name"), lt.get("host") or lt.get("ipAddress")))
    if stale_targets:
        listed = "; ".join(f"{t}:{n}->{h}" for t, n, h in stale_targets[:6])
        more = "…" if len(stale_targets) > 6 else ""
        f.append(_finding("info", "Stale references", f"{len(stale_targets)} external target(s) reference remote hosts — verify each still exists post-migration: {listed}{more}", "external_radius", "REC-STALE-001"))

    # --- leftover default / sample artifacts ---
    leftovers = []
    for ps in data.get("policy_sets", []):
        nm = (ps.get("name") or "")
        if nm.strip().lower() in ("default", "sample", "wired", "wireless") and ps.get("isDefault"):
            leftovers.append(f"policy set '{nm}'")
    for sg in data.get("sponsor_groups", []):
        nm = (sg.get("name") or "")
        if "sample" in nm.lower() or nm in ("ALL_ACCOUNTS", "GROUP_ACCOUNTS", "OWN_ACCOUNTS"):
            leftovers.append(f"sponsor group '{nm}'")
    if leftovers:
        f.append(_finding("low", "Cleanup", f"{len(leftovers)} default/sample artifact(s) present — confirm intended post-migration: {', '.join(leftovers[:6])}{'…' if len(leftovers)>6 else ''}.", "policy_sets", "REC-CLEANUP-001"))

    # =====================================================================
    # SECURITY HARDENING CHECKS
    # =====================================================================

    # --- TLS / cipher posture (best-effort; route may not exist) ---
    ss = data.get("security_settings")
    if isinstance(ss, dict) and ss:
        allowed_tls = str(ss.get("allowedTLSVersions") or ss.get("tlsVersions") or "")
        if any(v in allowed_tls for v in ("1.0", "1.1", "TLSV1_0", "TLSV1_1")):
            f.append(_finding("high", "Security settings", f"Admin/EAP TLS settings permit TLS 1.0/1.1: '{allowed_tls}'.", "security_settings", "REC-TLS-001"))
        if ss.get("allowSHA1Ciphers") or ss.get("allowSha1Ciphers"):
            f.append(_finding("med", "Security settings", "SHA-1 cipher suites are allowed.", "security_settings", "REC-TLS-001"))
    fips = data.get("fips_status")
    if isinstance(fips, dict) and fips.get("isEnabled") is False:
        f.append(_finding("info", "Security settings", "FIPS mode is disabled (expected for most deployments; flag only if compliance requires it).", "fips_status", "REC-FIPS-001"))

    # --- admin password policy ---
    pp = data.get("admin_password_policy")
    if isinstance(pp, dict) and pp:
        min_len = pp.get("minLength") or pp.get("minimumLength")
        if isinstance(min_len, int) and min_len < 12:
            f.append(_finding("med", "Admin access", f"Admin password minimum length is {min_len} (recommend ≥12-14).", "admin_password_policy", "REC-ADMIN-003"))
    sess = data.get("admin_session_settings")
    if isinstance(sess, dict) and sess:
        timeout = sess.get("sessionTimeout") or sess.get("timeout")
        if isinstance(timeout, int) and timeout > 60:
            f.append(_finding("low", "Admin access", f"Admin GUI session timeout is {timeout} min (recommend ≤30-60).", "admin_session_settings", "REC-ADMIN-004"))

    # --- logging / retention ---
    lt = data.get("logging_targets")
    if isinstance(lt, list) and not lt and "logging.remote_targets" in data.get("coverage", {}) and data["coverage"]["logging.remote_targets"].get("ok"):
        f.append(_finding("med", "Logging", "No remote logging (syslog) target configured — security events stay only on MnT.", "logging_targets", "REC-LOG-001"))

    # =====================================================================
    # OPERATIONAL DEPTH CHECKS
    # =====================================================================

    # --- profiler feed freshness ---
    pf = data.get("profiler_feed")
    if isinstance(pf, dict) and pf:
        if pf.get("isEnabled") is False or pf.get("enabled") is False:
            f.append(_finding("low", "Profiler", "Profiler feed auto-update is disabled — endpoint classification will drift over time.", "profiler_feed", "REC-PROFILER-002"))

    # --- pxGrid ---
    px = data.get("pxgrid_settings")
    if isinstance(px, dict) and px and px.get("autoApprove") is True:
        f.append(_finding("med", "pxGrid", "pxGrid auto-approve is enabled — any client can register without manual approval.", "pxgrid_settings", "REC-PXGRID-001"))

    # --- endpoint DB stats ---
    ep = data.get("endpoint_count")
    unk = data.get("unknown_endpoint_count")
    if isinstance(ep, int) and isinstance(unk, int) and ep > 0:
        pct = int(100 * unk / ep)
        if pct > 25:
            f.append(_finding("low", "Endpoints", f"{unk}/{ep} endpoints ({pct}%) are in the Unknown group — profiling gaps or stale data carried through migration.", "unknown_endpoint_count", "REC-ENDPOINT-001"))

    # --- RADIUS server sequences pointing at external proxies ---
    if data.get("radius_sequences"):
        f.append(_finding("info", "Identity", f"{len(data['radius_sequences'])} RADIUS server sequence(s) present — confirm external proxy targets still valid post-migration.", "radius_sequences", "REC-STALE-001"))

    # sort severity
    order = {s: i for i, s in enumerate(_SEVERITIES)}
    f.sort(key=lambda x: (order.get(x["severity"], 99), x["category"]))
    return f


# ---------------------------------------------------------------------------
# Top-level summary
# ---------------------------------------------------------------------------


def summarize(data: dict[str, Any], findings: list[dict]) -> dict[str, Any]:
    sev = {s: 0 for s in _SEVERITIES}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    coverage = data.get("coverage", {})
    ok = sum(1 for v in coverage.values() if isinstance(v, dict) and v.get("ok"))
    total = len(coverage)
    return {
        "counts": {
            "nodes": len(data.get("nodes", [])),
            "nads": len(data.get("nads", [])),
            "ndgs": len(data.get("ndgs", [])),
            "endpoint_groups": len(data.get("endpoint_identity_groups", [])),
            "user_groups": len(data.get("user_identity_groups", [])),
            "internal_users": len(data.get("internal_users", [])),
            "admin_users": len(data.get("admin_users", [])),
            "authz_profiles": len(data.get("authz_profiles", [])),
            "dacls": len(data.get("dacls", [])),
            "policy_sets": len(data.get("policy_sets", [])),
            "device_admin_sets": len(data.get("device_admin_sets", [])),
            "profiler_policies": len(data.get("profiler_policies", [])),
            "sgts": len(data.get("sgts", [])),
            "sgacls": len(data.get("sgacls", [])),
            "guest_types": len(data.get("guest_types", [])),
            "portals": len(data.get("portals", [])),
            "repositories": len(data.get("repositories", [])),
            "system_certs": len(data.get("system_certs", [])),
            "trusted_certs": len(data.get("trusted_certs", [])),
            "allowed_protocols": len(data.get("allowed_protocols", [])),
            "radius_sequences": len(data.get("radius_sequences", [])),
            "endpoint_count": data.get("endpoint_count") if isinstance(data.get("endpoint_count"), int) else "n/a",
            "unknown_endpoint_count": data.get("unknown_endpoint_count") if isinstance(data.get("unknown_endpoint_count"), int) else "n/a",
        },
        "severity": sev,
        "endpoint_coverage": {"ok": ok, "total": total, "pct": int(100 * ok / total) if total else 0},
    }
