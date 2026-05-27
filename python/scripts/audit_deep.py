"""Deep read-only ISE audit with HTML + PDF output.

Usage:
  uv run python -m scripts.audit_deep                # html + json
  uv run python -m scripts.audit_deep --pdf          # also write pdf
  uv run python -m scripts.audit_deep --out reports  # custom output dir

All API calls are GETs. No state is changed on the PAN.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import typer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console

from ise_api import ISEClient
from ise_api.audit import analyze, collect, summarize
from ise_api.recommendations import build_recommendations

console = Console()
app = typer.Typer(add_completion=False, help=__doc__)

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def render_html(data: dict, findings: list[dict], summary: dict, recommendations: list[dict]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template("report.html.j2")
    return tmpl.render(
        meta=data["meta"],
        coverage=data["coverage"],
        summary=summary,
        findings=findings,
        recommendations=recommendations,
        nodes=data.get("nodes", []),
        nads=data.get("nads", []),
        ndgs=data.get("ndgs", []),
        admin_users=data.get("admin_users", []),
        ad_join_points=data.get("ad_join_points", []),
        identity_sequences=data.get("identity_sequences", []),
        policy_sets_detail=data.get("policy_sets_detail", []),
        device_admin_sets_detail=data.get("device_admin_sets_detail", []),
        authz_profiles=data.get("authz_profiles", []),
        dacls=data.get("dacls", []),
        sgts=data.get("sgts", []),
        sgacls=data.get("sgacls", []),
        egress_matrix_cells=data.get("egress_matrix_cells", []),
        guest_types=data.get("guest_types", []),
        sponsor_groups=data.get("sponsor_groups", []),
        portals=data.get("portals", []),
        profiler_policies=data.get("profiler_policies", []),
        system_certs=data.get("system_certs", []),
        trusted_certs=data.get("trusted_certs", []),
        repositories=data.get("repositories", []),
        backup_schedule_config=data.get("backup_schedule_config", {}),
        pan_hostname=data.get("pan_hostname", "-"),
        patches=data.get("patches", []),
        license_smart=data.get("license_smart", {}),
    )


def render_pdf(html: str, out: Path) -> None:
    from weasyprint import HTML
    HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(target=str(out))


@app.command()
def main(
    out: Path = typer.Option(Path("audit-output"), "--out", help="Output directory"),
    pdf: bool = typer.Option(False, "--pdf", help="Also write a PDF (requires weasyprint)"),
    json_only: bool = typer.Option(False, "--json-only", help="Skip rendering; just dump raw JSON"),
) -> None:
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    with ISEClient() as c:
        console.print(f"[bold]Connecting to[/] {c.s.base_url} as [cyan]{c.s.username}[/]")
        if not c.ping():
            console.print("[red]ERS unreachable.[/]")
            raise typer.Exit(1)

        console.print("• Collecting…")
        data = collect(c)
        console.print(f"  [dim]coverage:[/] {sum(1 for v in data['coverage'].values() if v.get('ok'))}/{len(data['coverage'])} endpoints OK")

        console.print("• Analyzing…")
        findings = analyze(data)
        summary = summarize(data, findings)
        recommendations = build_recommendations(findings)
        console.print(f"  [dim]recommendations:[/] {len(recommendations)} (P1={sum(1 for r in recommendations if r['priority']=='P1')}, P2={sum(1 for r in recommendations if r['priority']=='P2')}, P3={sum(1 for r in recommendations if r['priority']=='P3')})")

        # Always write JSON dump
        json_path = out / f"audit-{stamp}.json"
        json_path.write_text(json.dumps({"data": data, "findings": findings, "summary": summary, "recommendations": recommendations}, indent=2, default=str))
        console.print(f"  JSON   → [cyan]{json_path}[/]")

        if json_only:
            return

        console.print("• Rendering HTML…")
        html = render_html(data, findings, summary, recommendations)
        html_path = out / f"audit-{stamp}.html"
        html_path.write_text(html)
        console.print(f"  HTML   → [cyan]{html_path}[/]")

        if pdf:
            console.print("• Rendering PDF…")
            pdf_path = out / f"audit-{stamp}.pdf"
            try:
                render_pdf(html, pdf_path)
                console.print(f"  PDF    → [cyan]{pdf_path}[/]")
            except Exception as e:  # noqa: BLE001
                console.print(f"  [red]PDF render failed:[/] {e}")
                console.print("  [yellow]Workaround:[/] open the HTML in a browser and File → Print → Save as PDF.")

        # Summary line
        sev = summary["severity"]
        console.print(
            f"\n[bold]Done.[/] Findings: "
            f"[red]{sev['high']} high[/] · [yellow]{sev['med']} med[/] · "
            f"[blue]{sev['low']} low[/] · [dim]{sev['info']} info[/]"
        )


if __name__ == "__main__":
    app()
