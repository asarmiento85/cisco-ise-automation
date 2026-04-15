"""Quick ISE reachability + inventory summary.

Run: uv run python -m scripts.health_check
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ise_api import ISEClient
from ise_api.nads import list_nads

console = Console()


def main() -> int:
    with ISEClient() as c:
        console.print(f"[bold]ISE PAN:[/] {c.s.base_url}")
        ok = c.ping()
        console.print(f"ERS reachable: {'[green]yes[/]' if ok else '[red]no[/]'}")
        if not ok:
            return 1

        nads = list_nads(c)
        table = Table(title=f"Network Devices ({len(nads)})")
        table.add_column("Name")
        table.add_column("IP")
        table.add_column("Profile")
        for nad in nads:
            ip = (
                nad.get("NetworkDeviceIPList", [{}])[0].get("ipaddress")
                if nad.get("NetworkDeviceIPList")
                else "-"
            )
            table.add_row(nad.get("name", "-"), ip or "-", nad.get("profileName", "-"))
        console.print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
