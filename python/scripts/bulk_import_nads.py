"""Bulk-create NADs from a CSV.

CSV header: name,ip,shared_secret,description

Run: uv run python -m scripts.bulk_import_nads path/to/nads.csv
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from rich.console import Console

from ise_api import ISEClient
from ise_api.nads import bulk_create_nads

console = Console()


def main(path: str) -> int:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]CSV not found:[/] {path}")
        return 2
    with p.open() as fh:
        rows = list(csv.DictReader(fh))
    console.print(f"Importing {len(rows)} NADs…")
    with ISEClient() as c:
        results = bulk_create_nads(c, rows)
    console.print(f"[green]Created:[/] {len(results)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(1)
    raise SystemExit(main(sys.argv[1]))
