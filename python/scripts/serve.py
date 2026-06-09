"""Local web UI for running the ISE audit — no CORS, no cloud, no scripting.

The customer downloads the repo, runs ONE command, and a browser form opens
on http://127.0.0.1:<port>. They enter the ISE PAN host + a read-only ERS
account, click Run, and the report renders in the browser.

Why this design:
  * The Flask backend (Python) makes the ISE API calls server-side, so the
    browser never talks to ISE directly — that's what sidesteps CORS and the
    self-signed admin cert.
  * The server binds to 127.0.0.1 ONLY. Nothing is exposed on the network.
  * Credentials are used transiently to read ISE and are NEVER written to
    disk or logged. Only the redacted report/JSON is held in memory for the
    download buttons.

Run:
    uv run --extra web python -m scripts.serve
    uv run --extra web python -m scripts.serve --port 9000 --no-browser
"""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser

import httpx
from flask import Flask, Response, redirect, request

from ise_api.audit import analyze, collect, summarize
from ise_api.client import ISEClient, ISESettings
from ise_api.recommendations import build_recommendations
from scripts.audit_deep import inject_app_chrome, render_html


def _preflight(settings: ISESettings) -> tuple[bool, str]:
    """Fast reachability + auth check (no retries) so a wrong host/cred fails
    in seconds rather than after the client's full retry/backoff cycle."""
    url = f"{settings.base_url}/ers/config/networkdevice"
    try:
        r = httpx.get(
            url, params={"size": 1}, auth=(settings.username, settings.password),
            verify=settings.verify_ssl, timeout=6.0, headers={"Accept": "application/json"},
        )
    except httpx.ConnectError:
        return False, "Could not connect to the host. Check the IP/hostname, port, and that the PAN is reachable from this machine."
    except httpx.ConnectTimeout:
        return False, "Connection timed out. The host may be unreachable or a firewall is blocking the port."
    except httpx.HTTPError as e:
        return False, f"Connection error: {type(e).__name__}."
    if r.status_code == 401:
        return False, "Authentication failed (401). Check the username and password."
    if r.status_code == 403:
        return False, "Authorized but forbidden (403). The account needs the ERS Operator (read-only) role, and ERS must be enabled."
    if r.status_code != 200:
        return False, f"Unexpected response (HTTP {r.status_code}). Confirm ERS is enabled under API Settings."
    return True, ""

app = Flask(__name__)

# In-memory holder for the most recent run's downloadable artifacts.
# Single-user localhost app — a module global is fine. Never holds creds.
_LAST: dict[str, bytes] = {}

_BRAND = "#0b3d91"

_FORM_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ISE Read-Only Audit</title>
<style>
  :root { --brand: %BRAND%; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         background: #f3f4f6; margin: 0; color: #111827; }
  .wrap { max-width: 560px; margin: 6vh auto; padding: 0 16px; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 6px 24px rgba(0,0,0,.08); overflow: hidden; }
  .head { background: var(--brand); color: #fff; padding: 22px 26px; }
  .head h1 { margin: 0; font-size: 20px; }
  .head p { margin: 6px 0 0; opacity: .85; font-size: 13px; }
  form { padding: 22px 26px; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 14px 0 4px; color: #374151; }
  input[type=text], input[type=number], input[type=password] {
    width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px;
  }
  .row { display: flex; gap: 12px; }
  .row .col-host { flex: 3; } .row .col-port { flex: 1; }
  .check { display: flex; align-items: center; gap: 8px; margin-top: 16px; font-size: 13px; color: #374151; }
  .check input { width: 16px; height: 16px; }
  button { margin-top: 22px; width: 100%; background: var(--brand); color: #fff; border: none;
           padding: 13px; border-radius: 8px; font-size: 15px; font-weight: 700; cursor: pointer; }
  button:disabled { opacity: .6; cursor: default; }
  .note { font-size: 12px; color: #6b7280; margin-top: 16px; line-height: 1.5; }
  .note strong { color: #374151; }
  #spinner { display: none; text-align: center; padding: 26px; font-size: 14px; color: #374151; }
  #spinner .bar { height: 6px; background: #e5e7eb; border-radius: 999px; overflow: hidden; margin: 14px 0; }
  #spinner .bar > div { height: 100%; width: 40%; background: var(--brand); border-radius: 999px;
                        animation: slide 1.2s infinite ease-in-out; }
  @keyframes slide { 0%{margin-left:-40%} 100%{margin-left:100%} }
</style></head>
<body>
  <div class="wrap"><div class="card">
    <div class="head">
      <h1>Cisco ISE — Read-Only Audit</h1>
      <p>Runs locally. Read-only. Nothing is changed on your ISE.</p>
    </div>
    <form id="f" method="POST" action="/run" onsubmit="go()">
      <div class="row">
        <div class="col-host">
          <label for="host">PAN host / IP</label>
          <input id="host" name="host" type="text" placeholder="ise-pan.your-domain.com" required autofocus/>
        </div>
        <div class="col-port">
          <label for="port">Port</label>
          <input id="port" name="port" type="number" value="443" required/>
        </div>
      </div>
      <label for="username">ERS username (read-only account)</label>
      <input id="username" name="username" type="text" placeholder="audit-readonly" required/>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required/>
      <div class="check">
        <input id="verify_ssl" name="verify_ssl" type="checkbox"/>
        <label for="verify_ssl" style="margin:0;font-weight:400;">Verify TLS certificate (leave off for self-signed ISE)</label>
      </div>
      <button id="btn" type="submit">Run Audit</button>
    </form>
    <div id="spinner">
      Running audit against the PAN… this typically takes 20–60 seconds.
      <div class="bar"><div></div></div>
      Collecting deployment, policy, identity, certs, TrustSec…
    </div>
    <div style="padding: 0 26px 22px;">
      <p class="note">
        <strong>Privacy:</strong> this tool runs entirely on this machine
        (127.0.0.1). Your credentials are used only to read your ISE over its
        API and are <strong>never stored, logged, or sent anywhere else</strong>.
        Shared secrets, SNMP communities, and passwords that ISE returns are
        redacted from the report. All calls are HTTP GETs — read-only.
      </p>
    </div>
  </div></div>
  <script>
    function go(){
      document.getElementById('btn').disabled = true;
      document.getElementById('btn').textContent = 'Running…';
      document.getElementById('f').style.display = 'none';
      document.getElementById('spinner').style.display = 'block';
    }
  </script>
</body></html>
""".replace("%BRAND%", _BRAND)


def _error_page(msg: str) -> str:
    safe = (msg or "").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Audit error</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f3f4f6;margin:0}}
.w{{max-width:560px;margin:8vh auto;background:#fff;border-radius:12px;box-shadow:0 6px 24px rgba(0,0,0,.08);overflow:hidden}}
.h{{background:#dc2626;color:#fff;padding:20px 26px;font-size:18px;font-weight:700}}
.b{{padding:22px 26px;color:#374151;font-size:14px;line-height:1.6}}
a{{color:{_BRAND};font-weight:600}}</style></head>
<body><div class="w"><div class="h">Audit could not complete</div>
<div class="b"><p>{safe}</p>
<p>Common causes:</p><ul>
<li>Host / port wrong, or the PAN isn't reachable from this machine</li>
<li>ERS API not enabled (Administration → System → Settings → API Settings)</li>
<li>Credentials wrong, or the account lacks the ERS Operator role</li>
<li>TLS verification on against a self-signed cert — try unchecking it</li>
</ul>
<p><a href="/">&larr; Back to the form</a></p></div></div></body></html>"""


_DOWNLOAD_LINKS = (
    f'<a href="/download/json" download style="text-decoration:none;">'
    f'<button type="button" style="background:#fff;color:{_BRAND};">Download JSON</button></a>'
    f'<a href="/download/html" download style="text-decoration:none;">'
    f'<button type="button" style="background:#fff;color:{_BRAND};">Download HTML</button></a>'
)


@app.get("/")
def index() -> str:
    return _FORM_PAGE


@app.post("/run")
def run():
    host = (request.form.get("host") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    try:
        port = int(request.form.get("port") or 443)
    except ValueError:
        port = 443
    verify = bool(request.form.get("verify_ssl"))

    if not host or not username:
        return _error_page("Host and username are required."), 400

    try:
        settings = ISESettings(  # type: ignore[call-arg]
            host=host, port=port, username=username, password=password, verify_ssl=verify
        )
        # Fast pre-flight so bad host/creds fail in ~6s, not after full retries.
        ok, why = _preflight(settings)
        if not ok:
            return _error_page(why)
        with ISEClient(settings) as c:
            data = collect(c)
        findings = analyze(data)
        summary = summarize(data, findings)
        recs = build_recommendations(findings)

        html = render_html(data, findings, summary, recs)
        report = inject_app_chrome(html, extra_toolbar_html=_DOWNLOAD_LINKS)

        # Stash redacted artifacts for the download buttons. NO credentials here.
        _LAST.clear()
        _LAST["json"] = json.dumps(
            {"data": data, "findings": findings, "summary": summary, "recommendations": recs},
            indent=2, default=str,
        ).encode()
        _LAST["html"] = report.encode()
        return report
    except Exception as e:
        return _error_page(f"{type(e).__name__}: {e}")
    finally:
        # Defensive: drop the password reference promptly.
        password = ""


@app.get("/download/json")
def download_json():
    if "json" not in _LAST:
        return redirect("/")
    return Response(
        _LAST["json"], mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=ise-audit.json"},
    )


@app.get("/download/html")
def download_html():
    if "html" not in _LAST:
        return redirect("/")
    return Response(
        _LAST["html"], mimetype="text/html",
        headers={"Content-Disposition": "attachment; filename=ise-audit.html"},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Local ISE audit web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (keep 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open the browser")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print(f"\n  ISE Audit web UI → {url}")
    print("  Read-only. Runs locally. Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    # threaded=True so the long collect() doesn't block the spinner page load
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
