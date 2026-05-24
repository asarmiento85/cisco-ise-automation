"""Restore selected ISE config from a snapshot directory.

Usage:
    uv run python -m scripts.restore_config --snapshot backups/latest --resource networkdevice
    uv run python -m scripts.restore_config --snapshot backups/2026-05-24T05-10-00Z --dry-run

Strategy:
  - For each resource in the snapshot JSON, attempt POST first; on 4xx
    (typically because it already exists), fall back to PUT against the
    existing object's id.
  - --dry-run prints what would change without making API calls.
  - --resource limits to a single ERS resource type.

This is intentionally conservative: it never deletes anything. Add deletes
manually if you actually need them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console

from ise_api import ISEClient

console = Console()

# Map ERS resource name -> top-level JSON key inside each detail object.
ERS_WRAPPER = {
    "networkdevice": "NetworkDevice",
    "networkdevicegroup": "NetworkDeviceGroup",
    "identitygroup": "IdentityGroup",
    "endpointgroup": "EndPointGroup",
    "endpoint": "ERSEndPoint",
    "downloadableacl": "DownloadableAcl",
    "authorizationprofile": "AuthorizationProfile",
    "tacacsprofile": "TacacsProfile",
    "tacacscommandsets": "TacacsCommandSets",
    "activedirectory": "ERSActiveDirectory",
    "internaluser": "InternalUser",
    "allowedprotocols": "AllowedProtocols",
}

# Resources to skip on restore (node info, runtime state, etc.)
SKIP_DEFAULT = {"node"}


def _restore_resource(
    c: ISEClient,
    resource: str,
    items: list[dict],
    *,
    dry_run: bool,
) -> tuple[int, int, int]:
    """Returns (created, updated, skipped)."""
    wrapper = ERS_WRAPPER.get(resource)
    if not wrapper:
        console.print(f"  [yellow]{resource}: no wrapper mapping, skipping[/]")
        return 0, 0, len(items)

    created = updated = skipped = 0
    for raw in items:
        body = raw.get(wrapper) or raw  # snapshot may be unwrapped
        if not isinstance(body, dict) or "name" not in body:
            skipped += 1
            continue

        name = body["name"]
        if dry_run:
            console.print(f"  [dim]{resource}/{name}: would POST or PUT[/]")
            continue

        # Try POST (create) first.
        post_body = {wrapper: {k: v for k, v in body.items() if k not in ("id", "link")}}
        r = c.post(f"/ers/config/{resource}", json=post_body)
        if r.status_code == 201:
            console.print(f"  [green]created {resource}/{name}[/]")
            created += 1
            continue

        # Fall back: GET existing id and PUT.
        g = c.get(f"/ers/config/{resource}/name/{name}")
        if g.status_code != 200:
            console.print(f"  [red]{resource}/{name}: POST {r.status_code}, GET {g.status_code}[/]")
            skipped += 1
            continue

        existing_id = g.json().get(wrapper, {}).get("id")
        if not existing_id:
            skipped += 1
            continue
        put_body = {wrapper: {**body, "id": existing_id}}
        p = c.put(f"/ers/config/{resource}/{existing_id}", json=put_body)
        if p.status_code in (200, 204):
            console.print(f"  [cyan]updated {resource}/{name}[/]")
            updated += 1
        else:
            console.print(f"  [red]{resource}/{name}: PUT {p.status_code}[/]")
            skipped += 1
    return created, updated, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--snapshot", required=True, help="path to snapshot dir (or backups/latest)")
    ap.add_argument("--resource", help="restore only this ERS resource (e.g. networkdevice)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    snap = Path(args.snapshot).resolve()
    if not snap.exists():
        console.print(f"[red]Snapshot path does not exist: {snap}[/]")
        return 2

    resources_to_restore: list[tuple[str, Path]] = []
    if args.resource:
        f = snap / f"ers_{args.resource}.json"
        if not f.exists():
            console.print(f"[red]No snapshot for {args.resource} in {snap}[/]")
            return 2
        resources_to_restore.append((args.resource, f))
    else:
        for f in sorted(snap.glob("ers_*.json")):
            res = f.stem.removeprefix("ers_")
            if res in SKIP_DEFAULT:
                continue
            resources_to_restore.append((res, f))

    console.print(f"[bold]Restoring from {snap}[/] ({'dry-run' if args.dry_run else 'live'})")
    with ISEClient() as c:
        if not args.dry_run and not c.ping():
            console.print("[red]ISE unreachable.[/]")
            return 1
        total_created = total_updated = total_skipped = 0
        for resource, f in resources_to_restore:
            items = json.loads(f.read_text())
            if not items:
                continue
            console.print(f"\n[bold]{resource}[/] ({len(items)} items)")
            c_, u_, s_ = _restore_resource(c, resource, items, dry_run=args.dry_run)
            total_created += c_
            total_updated += u_
            total_skipped += s_

    console.print(
        f"\n[bold]Summary:[/] created={total_created}  "
        f"updated={total_updated}  skipped={total_skipped}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
