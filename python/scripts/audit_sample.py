"""Sample read-only audit against a live ISE PAN.

What it does (all GETs, nothing mutating):
  * Deployment node info (OpenAPI)
  * Network devices + per-NAD detail (IPs, profile, NDG membership)
  * Network device groups
  * Endpoint identity groups + counts
  * Internal user count + admin users
  * Authorization profiles + downloadable ACLs
  * Allowed protocols
  * System certificates (PAN) — names + expiry only
  * Backup repositories
  * Heuristic findings (stale entries, defaults still present, etc.)

Run: uv run python -m scripts.audit_sample
Outputs: console report + JSON dump under ./audit-output/
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ise_api import ISEClient

console = Console()
OUT_DIR = Path("audit-output")


def _safe_get(c: ISEClient, path: str, **kwargs: Any) -> dict | list | None:
    try:
        r = c.get(path, **kwargs)
        if r.status_code == 200:
            return r.json()
        console.print(f"[yellow]  {path} -> HTTP {r.status_code}[/]")
        return None
    except httpx.HTTPError as e:
        console.print(f"[red]  {path} -> {e}[/]")
        return None


def _ers_collect(c: ISEClient, resource: str, detail: bool = False) -> list[dict]:
    items = list(c.ers_paginate(resource))
    if not detail:
        return items
    out: list[dict] = []
    for item in items:
        rid = item.get("id")
        if not rid:
            out.append(item)
            continue
        body = _safe_get(c, f"/ers/config/{resource}/{rid}") or {}
        # ERS detail responses wrap the object under a capitalized key
        wrapped = next(iter(body.values())) if isinstance(body, dict) and body else item
        out.append(wrapped if isinstance(wrapped, dict) else item)
    return out


def deployment_info(c: ISEClient) -> list[dict]:
    body = _safe_get(c, "/api/v1/deployment/node") or {}
    return body.get("response", []) if isinstance(body, dict) else []


def cert_summary(c: ISEClient, node_hostname: str) -> list[dict]:
    body = _safe_get(c, f"/api/v1/certs/system-certificate/{node_hostname}") or {}
    return body.get("response", []) if isinstance(body, dict) else []


def repositories(c: ISEClient) -> list[dict]:
    body = _safe_get(c, "/api/v1/repository") or {}
    return body.get("response", []) if isinstance(body, dict) else []


def render_report(data: dict[str, Any]) -> None:
    nodes = data["nodes"]
    nads = data["nads"]
    ndgs = data["ndgs"]
    eigs = data["endpoint_identity_groups"]
    authz = data["authz_profiles"]
    dacls = data["dacls"]
    protos = data["allowed_protocols"]
    admins = data["admin_users"]
    certs = data["certs"]
    repos = data["repos"]
    findings = data["findings"]

    console.rule("[bold cyan]ISE Read-Only Audit Sample")
    console.print(Panel.fit(
        f"PAN: [bold]{data['pan']}[/]\n"
        f"Run at: {data['timestamp']}\n"
        f"User: {data['user']} (audit account)",
        title="Connection",
    ))

    # Deployment
    t = Table(title=f"Deployment nodes ({len(nodes)})")
    for col in ("hostname", "personas", "roles", "nodeStatus"):
        t.add_column(col)
    for n in nodes:
        personas = ",".join(n.get("personas", []) or [])
        roles = ",".join(n.get("roles", []) or [])
        t.add_row(n.get("hostname", "-"), personas or "-", roles or "-", n.get("nodeStatus", "-"))
    console.print(t)

    # NADs
    t = Table(title=f"Network devices ({len(nads)})")
    for col in ("name", "ip/mask", "profile", "NDGs", "CoA port"):
        t.add_column(col)
    for n in nads:
        ips = n.get("NetworkDeviceIPList") or []
        ip_str = ", ".join(f"{i.get('ipaddress')}/{i.get('mask')}" for i in ips) or "-"
        groups = n.get("NetworkDeviceGroupList") or []
        # Compact group display
        compact = ", ".join(g.split("#")[-1] for g in groups[:3]) + ("…" if len(groups) > 3 else "")
        t.add_row(
            n.get("name", "-"),
            ip_str,
            n.get("profileName", "-"),
            compact,
            str(n.get("coaPort", "-")),
        )
    console.print(t)

    # NDG groups
    t = Table(title=f"Network device groups ({len(ndgs)})")
    t.add_column("name")
    t.add_column("ndgtype")
    for g in ndgs[:20]:
        t.add_row(g.get("name", "-"), g.get("othername") or g.get("ndgtype", "-"))
    if len(ndgs) > 20:
        t.add_row("…", f"+{len(ndgs)-20} more")
    console.print(t)

    # Endpoint identity groups (with counts when available)
    t = Table(title=f"Endpoint identity groups ({len(eigs)})")
    t.add_column("name")
    t.add_column("description")
    for g in eigs[:20]:
        t.add_row(g.get("name", "-"), (g.get("description") or "-")[:60])
    if len(eigs) > 20:
        t.add_row("…", f"+{len(eigs)-20} more")
    console.print(t)

    # Authz profiles + dACLs
    t = Table(title=f"Authorization profiles ({len(authz)})")
    t.add_column("name")
    t.add_column("type")
    for p in authz[:25]:
        t.add_row(p.get("name", "-"), p.get("profileName") or p.get("authzProfileType", "-"))
    if len(authz) > 25:
        t.add_row("…", f"+{len(authz)-25} more")
    console.print(t)

    t = Table(title=f"Downloadable ACLs ({len(dacls)})")
    t.add_column("name")
    t.add_column("type")
    for d in dacls[:15]:
        t.add_row(d.get("name", "-"), d.get("daclType", "-"))
    console.print(t)

    # Allowed protocols
    t = Table(title=f"Allowed-protocol service definitions ({len(protos)})")
    t.add_column("name")
    for p in protos:
        t.add_row(p.get("name", "-"))
    console.print(t)

    # Admin users
    t = Table(title=f"Admin users ({len(admins)})")
    t.add_column("name")
    t.add_column("enabled")
    for a in admins:
        t.add_row(a.get("name", "-"), str(a.get("enabled", "-")))
    console.print(t)

    # Certs
    t = Table(title=f"System certificates on PAN ({len(certs)})")
    for col in ("friendlyName", "expirationDate", "usedBy"):
        t.add_column(col)
    for cert in certs[:15]:
        used = cert.get("usedBy") or cert.get("keyUsage") or "-"
        t.add_row(
            (cert.get("friendlyName") or "-")[:50],
            cert.get("expirationDate", "-"),
            used if isinstance(used, str) else ",".join(used),
        )
    console.print(t)

    # Repos
    t = Table(title=f"Backup repositories ({len(repos)})")
    for col in ("name", "protocol", "path"):
        t.add_column(col)
    for r in repos:
        t.add_row(r.get("name", "-"), r.get("protocol", "-"), (r.get("path") or "-")[:60])
    console.print(t)

    # Findings
    console.rule("[bold yellow]Heuristic findings")
    if not findings:
        console.print("[green]No obvious issues from this slice.[/]")
    for f in findings:
        sev_color = {"high": "red", "med": "yellow", "low": "blue"}.get(f["severity"], "white")
        console.print(f"[{sev_color}]\\[{f['severity'].upper()}][/] {f['msg']}")


def derive_findings(data: dict[str, Any]) -> list[dict]:
    findings: list[dict] = []

    # NAD hygiene
    for n in data["nads"]:
        if not n.get("NetworkDeviceIPList"):
            findings.append({"severity": "high", "msg": f"NAD '{n.get('name')}' has NO IP — orphan/broken entry."})
        groups = n.get("NetworkDeviceGroupList") or []
        if not any(g.startswith("Location#") for g in groups):
            findings.append({"severity": "low", "msg": f"NAD '{n.get('name')}' missing Location NDG."})
        if not any(g.startswith("Device Type#") for g in groups):
            findings.append({"severity": "low", "msg": f"NAD '{n.get('name')}' missing Device Type NDG."})

    # Default admin still enabled
    for a in data["admin_users"]:
        if a.get("name") == "admin" and a.get("enabled"):
            findings.append({"severity": "med", "msg": "Default 'admin' account enabled — confirm MFA + rotation policy."})

    # Cert expiry within 60 days
    now = datetime.now(timezone.utc)
    for cert in data["certs"]:
        exp_str = cert.get("expirationDate")
        if not exp_str:
            continue
        exp = None
        for fmt in (
            "%a %b %d %H:%M:%S %Z %Y",       # Thu Jun 19 17:24:35 UTC 2025
            "%a, %d %b %Y %H:%M:%S %Z",      # RFC1123
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                exp = datetime.strptime(exp_str, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        if exp:
            days = (exp - now).days
            if days < 0:
                findings.append({
                    "severity": "high",
                    "msg": f"Cert '{cert.get('friendlyName','').strip()}' EXPIRED {abs(days)} days ago (used: {cert.get('usedBy','-')}).",
                })
            elif days < 60:
                findings.append({
                    "severity": "high",
                    "msg": f"Cert '{cert.get('friendlyName','').strip()}' expires in {days} days.",
                })

    # No backup repository
    if not data["repos"]:
        findings.append({"severity": "med", "msg": "No backup repository configured — DR posture?"})

    # Authz profile sprawl
    if len(data["authz_profiles"]) > 50:
        findings.append({"severity": "low", "msg": f"{len(data['authz_profiles'])} authz profiles — review for duplicates/unused."})

    return findings


def main() -> int:
    OUT_DIR.mkdir(exist_ok=True)
    with ISEClient() as c:
        console.print(f"[bold]Connecting to[/] {c.s.base_url} as [cyan]{c.s.username}[/]")
        if not c.ping():
            console.print("[red]ERS unreachable.[/]")
            return 1

        data: dict[str, Any] = {
            "pan": c.s.base_url,
            "user": c.s.username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        console.print("• Pulling deployment nodes…")
        data["nodes"] = deployment_info(c)
        console.print("• Pulling NADs (with detail)…")
        data["nads"] = _ers_collect(c, "networkdevice", detail=True)
        console.print("• Pulling NDGs…")
        data["ndgs"] = _ers_collect(c, "networkdevicegroup")
        console.print("• Pulling endpoint identity groups…")
        data["endpoint_identity_groups"] = _ers_collect(c, "endpointgroup")
        console.print("• Pulling authorization profiles…")
        data["authz_profiles"] = _ers_collect(c, "authorizationprofile")
        console.print("• Pulling downloadable ACLs…")
        data["dacls"] = _ers_collect(c, "downloadableacl")
        console.print("• Pulling allowed protocols…")
        data["allowed_protocols"] = _ers_collect(c, "allowedprotocols")
        console.print("• Pulling admin users…")
        data["admin_users"] = _ers_collect(c, "adminuser", detail=True)
        console.print("• Pulling certs…")
        node_host = (data["nodes"][0].get("hostname") if data["nodes"] else c.s.host)
        data["certs"] = cert_summary(c, node_host)
        console.print("• Pulling repositories…")
        data["repos"] = repositories(c)

        data["findings"] = derive_findings(data)

        # Write JSON dump for offline review
        out_path = OUT_DIR / f"audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        out_path.write_text(json.dumps(data, indent=2, default=str))
        render_report(data)
        console.print(f"\n[dim]Full JSON written to {out_path}[/]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
