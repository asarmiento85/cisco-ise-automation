# ISE Audit Tool — Download & Run Quick Start

This guide covers exactly two things: **getting the tool onto your machine**
and **running the audit in your browser**. No scripting knowledge needed.

The audit is **read-only** — every call it makes to ISE is an HTTP GET. It
cannot change your configuration. It runs entirely on your machine: nothing
is uploaded anywhere, and your credentials are never stored or logged.

> ISE-side preparation (enabling the ERS API, creating a read-only audit
> account) is covered separately in
> [02-customer-audit-runbook.md](02-customer-audit-runbook.md). If your ISE
> admin has already done that, you only need this page.

---

## What you need before starting

- A workstation that can reach the ISE Primary Admin Node (PAN) over HTTPS
  (port 443). If you can open the ISE admin page in your browser, you're good.
- The ISE hostname or IP, and a username/password for an account with API
  (ERS) read access. Ask your ISE admin for a read-only **ERS Operator**
  account — the tool never needs full admin rights.
- macOS, Windows, or Linux. No admin rights required for the install below.

---

## Step 1 — Install `uv` (one-time, ~1 minute)

`uv` is a small tool that downloads Python and the audit's dependencies
automatically — you don't need to install Python yourself.

**macOS / Linux** — open Terminal and paste:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows** — open PowerShell and paste:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Then **close and reopen** your terminal so the `uv` command is available.

To confirm it worked:

```bash
uv --version
```

---

## Step 2 — Download the audit tool

**Option A — with git:**

```bash
git clone https://github.com/asarmiento85/cisco-ise-automation.git
cd cisco-ise-automation
```

**Option B — no git needed:**

1. Open <https://github.com/asarmiento85/cisco-ise-automation>
2. Click the green **Code** button → **Download ZIP**
3. Unzip it, then open a terminal in the unzipped folder

---

## Step 3 — Start the audit web app

```bash
cd python
uv run --extra web python -m scripts.serve
```

The first run takes ~30 seconds while dependencies download; after that it
starts instantly. Your browser opens `http://127.0.0.1:8765` automatically —
if it doesn't, open that address yourself.

You'll see this form:

```
┌─────────────────────────────────────────────┐
│  Cisco ISE — Read-Only Audit                │
│  Runs locally. Read-only. Nothing is        │
│  changed on your ISE.                       │
├─────────────────────────────────────────────┤
│  PAN host / IP        [                ]    │
│  Port                 [ 443 ]               │
│  ERS username         [                ]    │
│  Password             [                ]    │
│  □ Verify TLS certificate                   │
│                                             │
│            [ Run Audit ]                    │
└─────────────────────────────────────────────┘
```

---

## Step 4 — Fill in the form and run

| Field | What to enter |
|---|---|
| **PAN host / IP** | Your ISE Primary Admin Node, e.g. `ise-pan.example.com` or `10.1.2.3` |
| **Port** | `443` unless your admin says otherwise |
| **ERS username** | The read-only audit account (e.g. `audit-readonly`) |
| **Password** | Its password |
| **Verify TLS certificate** | Leave **unchecked** if ISE uses a self-signed certificate (most do). Check it only if ISE has a CA-signed admin certificate. |

Click **Run Audit**. After a quick connection check (a few seconds), a live
progress screen appears — a percentage bar, the section currently being
collected (network devices, policies, certificates, …), a running checklist
of completed sections, and an elapsed timer. The audit takes **20–60 seconds**
on most deployments; when it finishes, the page opens the full report
automatically. As long as the progress counter is moving (or the current
section is shown), it's working — don't close the page.

---

## Step 5 — Save and share the results

Use the buttons in the report's top toolbar:

| Button | What you get | Typical use |
|---|---|---|
| **Download JSON** | Raw structured data (secrets redacted) | Send to your consultant for analysis |
| **Download HTML** | The whole interactive report as one file | Share internally; works offline, just double-click |
| **Print / Save PDF** | Print dialog → "Save as PDF" | Formal copy for management / records |

The report itself is interactive while you have it open: filter findings by
severity, search, jump between sections, and collapse/expand recommendations.

---

## Step 6 — Stop the tool

Go back to the terminal and press **Ctrl+C**. That's it — there's nothing
else running and nothing to uninstall. (To remove the tool completely, just
delete the folder.)

---

## Troubleshooting

The error page explains most failures in plain language. Quick reference:

| Message | What it means | Fix |
|---|---|---|
| *Could not connect to the host* | Wrong IP/hostname, or no network path | Check the address; confirm you can reach the ISE admin page in a browser; check VPN |
| *Connection timed out* | Host unreachable or firewall blocking 443 | Same as above |
| *Authentication failed (401)* | Wrong username or password | Re-check credentials |
| *Authorized but forbidden (403)* | Account lacks API access, or ERS is disabled | Ask your ISE admin — the account needs the **ERS Operator** role and ERS must be enabled under **Administration → System → Settings → API Settings** |
| Port already in use when starting | Another copy is still running | Run with another port: `uv run --extra web python -m scripts.serve --port 8766` |

If the report shows lower "endpoint coverage" than 100%, that's normal —
features you haven't configured (posture, pxGrid, TrustSec, AD) don't expose
their API endpoints. The report's final section lists exactly what responded.

---

## Privacy & safety summary

Worth repeating, because it's the part security teams ask about:

- **Read-only.** Every ISE call is an HTTP GET. The tool has no code paths
  that modify ISE configuration.
- **Local only.** The web page is served from your own machine
  (`127.0.0.1`). Nothing listens on your network; nothing is sent to any
  cloud service.
- **Credentials are transient.** Used once to query ISE, held only in
  memory, never written to disk or logged.
- **Secrets are redacted.** RADIUS/TACACS shared secrets, SNMP community
  strings, and password fields are replaced with `<REDACTED>` before any
  report is written.
- **Auditable.** The tool is open source — your security team can read every
  line before you run it.
