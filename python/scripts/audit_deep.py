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


def _normalize_patches(p) -> list[str]:
    """ISE's patch endpoint shape varies by version (list of dicts, wrapped
    dict, or string). Some versions even return the list AS a string of
    Python-repr (single quotes), so parse that too. Flatten to display
    strings so the template never shows a raw repr."""
    prefix: list[str] = []
    if isinstance(p, dict):
        ver = p.get("iseVersion")
        if ver:
            prefix.append(f"ISE {ver}")
        inner = (
            p.get("patchDetails") or p.get("patches") or p.get("response")
            or p.get("patchVersion") or p.get("installedPatchVersion")
        )
        if inner is None:
            return prefix
        p = inner
    if isinstance(p, str):
        s = p.strip()
        if s.startswith(("[", "{")):
            import ast
            try:
                p = ast.literal_eval(s)  # safe: literals only
            except (ValueError, SyntaxError):
                return prefix + [s]
            if isinstance(p, dict):
                p = [p]
        else:
            return prefix + ([s] if s else [])
    out: list[str] = prefix
    for item in p or []:
        if isinstance(item, dict):
            label = f"Patch {item.get('patchVersion') or item.get('patchNumber') or '?'}"
            if item.get("installDate"):
                label += f" — installed {item['installDate']}"
            out.append(label)
        else:
            out.append(str(item))
    return out


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
        patches=_normalize_patches(data.get("patches")),
        license_smart=data.get("license_smart", {}),
        # migration / security / operational additions
        allowed_protocols=data.get("allowed_protocols", []),
        ers_nodes=data.get("ers_nodes", []),
        security_settings=data.get("security_settings"),
        admin_password_policy=data.get("admin_password_policy"),
        admin_session_settings=data.get("admin_session_settings"),
        fips_status=data.get("fips_status"),
        logging_targets=data.get("logging_targets"),
        posture_settings=data.get("posture_settings"),
        pxgrid_settings=data.get("pxgrid_settings"),
        profiler_feed=data.get("profiler_feed"),
        radius_sequences=data.get("radius_sequences", []),
    )


def render_pdf(html: str, out: Path) -> None:
    from weasyprint import HTML
    HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(target=str(out))


# ---------------------------------------------------------------------------
# Interactive single-file app shell
# ---------------------------------------------------------------------------
# Layered onto the already-rendered report HTML so we maintain ONE template.
# Everything is inline (no CDN, no external requests) so the file works when
# double-clicked from disk (file://) with no network and no server.

_APP_STYLE = """
<style id="app-style">
  @media screen {
    body { padding-top: 92px; }
    #app-toolbar {
      position: fixed; top: 0; left: 0; right: 0; z-index: 1000;
      background: #0b3d91; color: #fff; padding: 8px 14px;
      box-shadow: 0 2px 8px rgba(0,0,0,.25);
      font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    #app-toolbar .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    #app-toolbar .title { font-weight: 700; font-size: 14px; margin-right: 6px; }
    #app-toolbar .pan { font-size: 11px; opacity: .8; font-family: monospace; }
    #app-toolbar select, #app-toolbar input {
      font-size: 12px; padding: 4px 8px; border-radius: 5px; border: none;
    }
    #app-toolbar input { width: 200px; }
    #app-toolbar .chip {
      cursor: pointer; user-select: none; font-size: 11px; font-weight: 600;
      padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(255,255,255,.5);
      color: #fff; background: transparent;
    }
    #app-toolbar .chip.active { background: #fff; color: #0b3d91; }
    #app-toolbar .chip[data-sev="high"].active { background:#fee2e2; color:#dc2626; }
    #app-toolbar .chip[data-sev="med"].active  { background:#fef3c7; color:#d97706; }
    #app-toolbar .chip[data-sev="low"].active  { background:#dbeafe; color:#2563eb; }
    #app-toolbar .chip[data-sev="info"].active { background:#f3f4f6; color:#4b5563; }
    #app-toolbar button {
      cursor: pointer; font-size: 12px; font-weight: 600; padding: 5px 12px;
      border-radius: 5px; border: none; background: #fff; color: #0b3d91;
    }
    #app-toolbar .spacer { flex: 1; }
    h2 { scroll-margin-top: 100px; }
    .rec.collapsed > *:not(.rec-head) { display: none; }
    .rec .rec-head { cursor: pointer; }
    .rec .rec-head::after { content: " ▾"; opacity:.5; font-size: 10px; }
    .rec.collapsed .rec-head::after { content: " ▸"; }
    tr.app-hidden, .rec.app-hidden { display: none !important; }
    #app-emptymsg { display:none; color:#6b7280; font-style:italic; margin:8px 0; }
  }
  @media print {
    #app-toolbar, #app-emptymsg { display: none !important; }
    body { padding-top: 0 !important; }
    .rec.collapsed > * { display: revert !important; }
    tr.app-hidden, .rec.app-hidden { display: revert !important; }
  }
</style>
"""

_APP_TOOLBAR = """
<div id="app-toolbar">
  <div class="row">
    <span class="title">ISE Audit</span>
    <span class="pan" id="app-pan"></span>
    <span class="spacer"></span>
    <select id="app-nav" title="Jump to section"></select>
    <input id="app-search" type="search" placeholder="Search findings & recs…" />
    <button id="app-print">Print / Save PDF</button>
  </div>
  <div class="row" style="margin-top:6px;">
    <span style="font-size:11px;opacity:.8;">Filter:</span>
    <span class="chip active" data-sev="all">All</span>
    <span class="chip active" data-sev="high">High</span>
    <span class="chip active" data-sev="med">Med</span>
    <span class="chip active" data-sev="low">Low</span>
    <span class="chip active" data-sev="info">Info</span>
  </div>
</div>
<p id="app-emptymsg">No findings match the current filter / search.</p>
"""

_APP_SCRIPT = """
<script>
(function () {
  "use strict";
  function sevOf(row) {
    var pill = row.querySelector('span.pill[class*="sev-"]');
    if (!pill) return null;
    var m = pill.className.match(/sev-(high|med|low|info)/);
    return m ? m[1] : null;
  }
  // Findings rows = table rows that carry a severity pill
  var findingRows = Array.prototype.filter.call(
    document.querySelectorAll('table tr'), function (r) { return sevOf(r) !== null; }
  );
  var recCards = Array.prototype.slice.call(document.querySelectorAll('.rec'));

  // PAN label
  var panEl = document.querySelector('.cover .mono');
  if (panEl) document.getElementById('app-pan').textContent = panEl.textContent;

  // Section nav from h2 headings
  var nav = document.getElementById('app-nav');
  var opt0 = document.createElement('option');
  opt0.textContent = 'Jump to section…'; opt0.value = '';
  nav.appendChild(opt0);
  Array.prototype.forEach.call(document.querySelectorAll('h2'), function (h, i) {
    var id = 'sec-' + i; h.id = id;
    var o = document.createElement('option');
    o.value = id; o.textContent = h.textContent.trim();
    nav.appendChild(o);
  });
  nav.addEventListener('change', function () {
    var el = document.getElementById(nav.value);
    if (el) el.scrollIntoView({behavior: 'smooth'});
    nav.value = '';
  });

  // State
  var active = {high: true, med: true, low: true, info: true};
  var query = '';
  var emptyMsg = document.getElementById('app-emptymsg');

  function apply() {
    var shown = 0;
    findingRows.forEach(function (r) {
      var sev = sevOf(r);
      var okSev = active[sev];
      var okText = !query || r.textContent.toLowerCase().indexOf(query) !== -1;
      var show = okSev && okText;
      r.classList.toggle('app-hidden', !show);
      if (show) shown++;
    });
    recCards.forEach(function (c) {
      var okText = !query || c.textContent.toLowerCase().indexOf(query) !== -1;
      c.classList.toggle('app-hidden', !okText);
    });
    emptyMsg.style.display = (shown === 0) ? 'block' : 'none';
  }

  // Severity chips
  Array.prototype.forEach.call(document.querySelectorAll('#app-toolbar .chip'), function (chip) {
    chip.addEventListener('click', function () {
      var sev = chip.getAttribute('data-sev');
      if (sev === 'all') {
        var turnOn = !chip.classList.contains('active');
        ['high','med','low','info'].forEach(function (s) { active[s] = turnOn; });
      } else {
        active[sev] = !active[sev];
      }
      // sync chip visuals
      document.querySelectorAll('#app-toolbar .chip').forEach(function (ch) {
        var s = ch.getAttribute('data-sev');
        if (s === 'all') {
          ch.classList.toggle('active', active.high && active.med && active.low && active.info);
        } else {
          ch.classList.toggle('active', active[s]);
        }
      });
      apply();
    });
  });

  // Search
  var search = document.getElementById('app-search');
  search.addEventListener('input', function () { query = search.value.toLowerCase().trim(); apply(); });

  // Print
  document.getElementById('app-print').addEventListener('click', function () { window.print(); });

  // Collapsible rec cards
  recCards.forEach(function (c) {
    var head = c.querySelector('.rec-head');
    if (head) head.addEventListener('click', function () { c.classList.toggle('collapsed'); });
  });
})();
</script>
"""


def inject_app_chrome(html: str, extra_toolbar_html: str = "") -> str:
    """Layer the interactive toolbar + JS onto rendered report HTML.

    Produces a single self-contained file (no external requests) suitable for
    double-clicking from disk. The toolbar is hidden when printing.

    extra_toolbar_html, if given, is inserted just before the Print button —
    used by the local web server to add JSON/HTML download links.
    """
    toolbar = _APP_TOOLBAR
    if extra_toolbar_html:
        toolbar = toolbar.replace(
            '<button id="app-print">', extra_toolbar_html + '<button id="app-print">'
        )
    if "</head>" in html:
        html = html.replace("</head>", _APP_STYLE + "</head>", 1)
    # toolbar right after <body ...>
    body_idx = html.find("<body")
    if body_idx != -1:
        gt = html.find(">", body_idx)
        if gt != -1:
            html = html[: gt + 1] + toolbar + html[gt + 1 :]
    if "</body>" in html:
        html = html.replace("</body>", _APP_SCRIPT + "</body>", 1)
    return html


def _emit_reports(
    data: dict,
    findings: list,
    summary: dict,
    recommendations: list,
    out: Path,
    stamp: str,
    *,
    pdf: bool,
    app_html: bool,
) -> None:
    """Render HTML / PDF / interactive app from already-collected data."""
    console.print("• Rendering HTML…")
    html = render_html(data, findings, summary, recommendations)
    html_path = out / f"audit-{stamp}.html"
    html_path.write_text(html)
    console.print(f"  HTML   → [cyan]{html_path}[/]")

    if app_html:
        console.print("• Building self-contained app (index.html)…")
        app_doc = inject_app_chrome(html)
        index_path = out / "index.html"
        index_path.write_text(app_doc)
        console.print(f"  APP    → [cyan]{index_path}[/]  [dim](double-click to open; works offline)[/]")

    if pdf:
        console.print("• Rendering PDF…")
        pdf_path = out / f"audit-{stamp}.pdf"
        try:
            render_pdf(html, pdf_path)
            console.print(f"  PDF    → [cyan]{pdf_path}[/]")
        except Exception as e:  # noqa: BLE001
            console.print(f"  [red]PDF render failed:[/] {e}")
            console.print("  [yellow]Workaround:[/] open the HTML in a browser and File → Print → Save as PDF.")

    sev = summary["severity"]
    console.print(
        f"\n[bold]Done.[/] Findings: "
        f"[red]{sev['high']} high[/] · [yellow]{sev['med']} med[/] · "
        f"[blue]{sev['low']} low[/] · [dim]{sev['info']} info[/]"
    )


@app.command()
def main(
    out: Path = typer.Option(Path("audit-output"), "--out", help="Output directory"),
    pdf: bool = typer.Option(False, "--pdf", help="Also write a PDF (requires weasyprint)"),
    app_html: bool = typer.Option(False, "--app", help="Also write a self-contained interactive index.html"),
    json_only: bool = typer.Option(False, "--json-only", help="Skip rendering; just dump raw JSON"),
    from_json: Path = typer.Option(None, "--from-json", help="Render from a saved audit JSON dump instead of querying ISE"),
) -> None:
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # ---- offline render path: no ISE connection ----
    if from_json is not None:
        console.print(f"[bold]Rendering from saved dump:[/] {from_json}")
        payload = json.loads(Path(from_json).read_text())
        data = payload["data"]
        findings = payload.get("findings") or analyze(data)
        summary = payload.get("summary") or summarize(data, findings)
        recommendations = payload.get("recommendations") or build_recommendations(findings)
        _emit_reports(data, findings, summary, recommendations, out, stamp, pdf=pdf, app_html=app_html or True)
        return

    # ---- live path: query ISE ----
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

        _emit_reports(data, findings, summary, recommendations, out, stamp, pdf=pdf, app_html=app_html)


if __name__ == "__main__":
    app()
