# Customer-Run ISE Audit — Step-by-Step Runbook

This guide is for customers (or partners) who want to **run a read-only audit against their own Cisco ISE deployment** and hand the results to a consultant — without giving the consultant any access to their environment.

**What the audit does:**
- Reads configuration via ISE's ERS and OpenAPI interfaces (every call is a `GET`)
- Generates a structured report: deployment topology, NAD inventory, policy sets, certificates, identity sources, TrustSec, backups, etc.
- Derives findings (expired certs, orphan NADs, risky TACACS patterns, missing backups, etc.)
- Maps each finding to a prioritized recommendation (P1 / P2 / P3) with effort, risk, and remediation steps
- Outputs three formats at the same timestamp: JSON, HTML, PDF

**What the audit does *not* do:**
- Make any configuration changes (no POST, PUT, PATCH, or DELETE — all calls are `GET`)
- Pull endpoint MAC addresses, session data, or live RADIUS / TACACS logs
- Capture credentials, certificate private keys, or password hashes (these aren't exposed by the API; the script additionally redacts any plaintext shared-secret fields ISE *does* return)
- Send anything to the internet — the script only talks to your PAN

---

## 0. Prerequisites

| Requirement | Detail |
|---|---|
| ISE version | 3.1 or later (3.3+ for best OpenAPI coverage) |
| Network access | A workstation that can reach your PAN on TCP/443 |
| Time | ~15 min setup, ~30 sec runtime, ~10 min review |
| Skills | Comfortable with a terminal and clicking through the ISE admin UI |

You will need:
- An ISE administrator able to create an admin user (one-time setup)
- A workstation (macOS, Linux, or Windows with WSL2) — used only to run the audit
- Python 3.11+ on that workstation

---

## 1. Enable the ERS API on the PAN (if not already enabled)

ERS is disabled by default in newer ISE installations.

1. Log in to the ISE admin UI as a Super Admin
2. Navigate to **Administration → System → Settings → ERS Settings**
3. Set **ERS Setting for Primary Administration Node** → **Enable ERS for Read/Write**
   - "Read/Write" is required even though we only read, because of how the role binding works in some versions. We'll restrict actual access via RBAC in the next step.
4. (Optional but recommended) Enable **CSRF Check for Enhanced Security** — has no effect on this script
5. Click **Save**

---

## 2. Create a dedicated read-only audit account

You do **not** want to use your personal admin credentials or the default `admin` account for this. Create a fresh, scoped, throwaway account.

1. Navigate to **Administration → System → Admin Access → Administrators → Admin Users**
2. Click **+ Add → Create an Admin User**
3. Fill in:

   | Field | Value |
   |---|---|
   | Name | `audit-readonly` (or `consultant-ro-audit`) |
   | Status | Enabled |
   | Password Type | Internal |
   | Password | A strong random string — store it in your password manager, you'll need it once |
   | Re-Enter Password | (same) |
   | Inactive Account Never Disabled | **uncheck** — let it auto-disable if forgotten |

4. Under **Admin Groups**, assign **ONE** of these (pick based on your security policy):

   | Group | Coverage | When to use |
   |---|---|---|
   | **Read Only Admin** (recommended) | Full audit coverage — every section of the report populates | Standard recommendation |
   | **ERS Operator** | Reduced coverage — some policy-set and certificate detail will be missing | Only if your security policy forbids any GUI access |

5. Click **Save**

> **Important:** "Read Only Admin" sounds broad, but it is genuinely read-only — the role cannot perform any write operation, GUI or API. If your security team wants to verify, they can: the role definition is at **Administration → System → Admin Access → Authorization → Permissions → RBAC Policy**, where you'll see all permissions for that group are "Menu Access: read-only" or "Data Access: read-only".

---

## 3. (Optional) Restrict access to a known source IP

If your security policy requires API access to be source-IP restricted:

1. Navigate to **Administration → System → Admin Access → Settings → Access → IP Access**
2. Switch from **Allow all IP addresses to connect** to **Allow only listed IP addresses**
3. Add the IP address of the workstation that will run the audit
4. Click **Save**

You can remove the entry after the audit is done.

---

## 4. Install the tooling on the audit workstation

Open a terminal on the workstation that will run the audit (the one with the IP you allowlisted).

### Install Python 3.11+ if you don't have it

```bash
# macOS
brew install python@3.12

# Ubuntu / Debian
sudo apt update && sudo apt install -y python3.12 python3.12-venv

# RHEL / Rocky / Alma
sudo dnf install -y python3.12

# Windows
# Use WSL2 with Ubuntu, or install Python 3.12 from python.org
```

### Install `uv` (fast Python package manager)

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Clone the audit tooling

```bash
git clone https://github.com/asarmiento85/cisco-ise-automation.git
cd cisco-ise-automation/python
```

> **Verify before running:** The entire audit pipeline is open source. Before running anything, you can read [`python/ise_api/audit.py`](https://github.com/asarmiento85/cisco-ise-automation/blob/main/python/ise_api/audit.py) and [`python/scripts/audit_deep.py`](https://github.com/asarmiento85/cisco-ise-automation/blob/main/python/scripts/audit_deep.py) to confirm every API call is a `GET`. Your security team is welcome to do the same.

### Install dependencies

```bash
uv sync --extra report
```

This installs `httpx`, `pydantic`, `jinja2`, and `weasyprint` (for PDF rendering) into an isolated virtual environment.

---

## 5. Configure the connection

Still in the `cisco-ise-automation` directory:

```bash
cp .env.example .env
```

Open `.env` in any text editor and fill in:

```
ISE_HOST=ise-pan.your-domain.com    # or the IP of your Primary Admin Node
ISE_PORT=443
ISE_USERNAME=audit-readonly          # the account you created in Step 2
ISE_PASSWORD=<the strong password>
ISE_VERIFY_SSL=false                 # set to true if your PAN has a public-CA cert
```

> The `.env` file is in `.gitignore` — it will never be committed back to the repo. Delete it after you're done if you want to be extra cautious.

---

## 6. Run the audit

### Option A — browser form (easiest, no CLI knowledge needed)

> A standalone, end-user version of this option — covering just download,
> run, and troubleshooting with no ISE-admin steps — is in
> [03-audit-quickstart.md](03-audit-quickstart.md). Hand that page to the
> person running the audit if someone else handled the ISE-side setup.

```bash
cd python
uv run --extra web python -m scripts.serve
```

Your browser opens `http://127.0.0.1:8765` with a simple form. Enter the PAN
host, port, the read-only ERS account from step 2, leave "Verify TLS" off if
your ISE uses a self-signed admin certificate, and click **Run Audit**. The
report appears in the browser after 20–60 seconds, with **Download JSON** /
**Download HTML** buttons in the toolbar and Print → Save-as-PDF for a PDF
copy.

Notes:
- The page is served from your own machine (`127.0.0.1` only) — nothing is
  exposed on the network and nothing leaves this machine.
- Credentials are used once to read ISE and are never stored or logged.
- A wrong host or password fails within seconds with a plain-English message.
- Stop the server with `Ctrl+C` when you're done.

### Option B — command line

```bash
cd python
uv run python -m scripts.audit_deep --pdf --app
```

The `--app` flag additionally writes a **self-contained `index.html`** — a
single file you can open by double-clicking in any browser. It works fully
offline (no server, no internet), and bundles an interactive view: filter by
severity, search findings, jump between sections, and Save-as-PDF from the
browser's print dialog. This is the easiest artifact to hand to someone who
just wants to *look* at the results without installing anything.

Expected output:

```
Connecting to https://ise-pan.your-domain.com:443 as audit-readonly
• Collecting…
  coverage: 48/52 endpoints OK
• Analyzing…
  recommendations: 14 (P1=3, P2=7, P3=4)
  JSON   → audit-output/audit-20260527-091422.json
• Rendering HTML…
  HTML   → audit-output/audit-20260527-091422.html
• Rendering PDF…
  PDF    → audit-output/audit-20260527-091422.pdf

Done. Findings: 2 high · 6 med · 4 low · 2 info
```

Total runtime is typically **20-40 seconds** depending on deployment size.

If you see anything other than `coverage: X/52 endpoints OK`, see Troubleshooting below.

---

## 7. Review and share the results

The audit drops three files in `python/audit-output/`:

| File | What's in it | Send to consultant? |
|---|---|---|
| `index.html` | Self-contained interactive app — double-click to open, works offline | Optional — easiest to browse |
| `audit-<ts>.pdf` | Print-ready 18-page report — the most readable | Yes — main deliverable |
| `audit-<ts>.html` | Same content, static browser view | Optional |
| `audit-<ts>.json` | Full structured dump — diffable across runs | Yes — required for offline analysis |

> The `index.html` is a fixed point-in-time snapshot with the data baked in.
> It does **not** connect to ISE when opened — it only renders data already
> collected during the run above. Safe to email or drop on a share.

### What's in the files (and what isn't)

The script applies a recursive redactor before writing anything. Plaintext fields that the ERS API normally returns to admins — RADIUS / TACACS shared secrets, SNMP community strings, repository passwords, internal user password hashes — are replaced with `<REDACTED>`. You can verify by grepping the JSON:

```bash
grep -c REDACTED audit-output/audit-*.json
```

A non-zero count means the redactor caught secrets. A zero count means your deployment doesn't expose any (typical for greenfield labs).

### What still appears in the reports

These are intentional — they're what makes the report useful:

- Network device names and IP addresses
- Administrator usernames (not passwords)
- Certificate friendly names, expirations, and services they're bound to
- Policy set / rule names
- NDG and identity group names
- Backup repository names and hosts (with passwords redacted)

If any of these are considered sensitive in your environment, **review the PDF before sharing it**. The HTML and JSON contain the same information in different formats.

### Sharing

Email or upload the PDF + JSON to your consultant via your normal secure file-transfer channel (encrypted email, customer portal, Box, etc.). The PDF is the human-readable deliverable; the JSON lets the consultant do follow-up analysis or diff against a future re-audit.

---

## 8. Clean up after the audit

When the engagement is over:

1. **Disable the audit account**
   - Administration → System → Admin Access → Administrators → Admin Users → select `audit-readonly` → **Disable** (or **Delete** if you don't want to re-use it)
2. **Remove the IP allowlist entry** (if you added one in Step 3)
3. **Optionally disable ERS** if you don't use it for anything else
   - Administration → System → Settings → ERS Settings → Disable
4. **On the audit workstation:**
   - Delete `.env` (contains the audit account password)
   - Delete `python/audit-output/` (or keep locally for diffing against the next audit)
5. Document the audit account credentials in your password vault for re-use next quarter (recommended — quarterly audits catch drift early)

---

## Troubleshooting

### `ERS unreachable`

ERS isn't enabled on the PAN, or your account doesn't have ERS access.
- Re-check Step 1 (Enable ERS for Read/Write on the PAN)
- Confirm the account is in **Read Only Admin** or **ERS Operator** (Step 2.4)

### `401 Unauthorized` on most endpoints

The account password is wrong, or it has been disabled.
- Test by browsing to `https://<your-pan>/admin/` and logging in with the same credentials

### `403 Forbidden` on OpenAPI endpoints (`/api/v1/...`)

The account is in **ERS Operator**, which doesn't include OpenAPI access in some ISE versions.
- Re-assign to **Read Only Admin** for full coverage, OR accept the reduced coverage (the report will note which sections are missing in the Endpoint Coverage Matrix on the last page)

### `SSL: CERTIFICATE_VERIFY_FAILED`

Your PAN is using a self-signed or internally-signed certificate.
- Set `ISE_VERIFY_SSL=false` in `.env` (default — this is fine for an audit)

### `coverage: 30/52 endpoints OK` (lower than expected)

Some endpoints 404 when:
- The feature isn't configured (no AD join, no scheduled backup) — these are noted, not problems
- The deployment is on an older ISE patch that pre-dates the OpenAPI route
- An IP allowlist or upstream firewall is blocking some calls — check `python/audit-output/audit-<ts>.json` under `coverage` for the specific endpoints that failed

### `weasyprint` install errors

The PDF renderer needs system libraries.
- macOS: `brew install pango cairo gdk-pixbuf libffi`
- Ubuntu: `sudo apt install libpango-1.0-0 libpangoft2-1.0-0`
- Workaround: skip PDF, just generate HTML — `uv run python -m scripts.audit_deep` (without `--pdf`). Then open the HTML in a browser and use **File → Print → Save as PDF**.

---

## Security FAQ

**Q: Does this script send any data to the internet?**
A: No. The only network calls are to your PAN over HTTPS. The repo is open source — verify in `python/ise_api/client.py` (only `base_url` is the PAN you configured).

**Q: Can a compromised audit account be used to attack ISE?**
A: The **Read Only Admin** role cannot make any changes via GUI or API. Combined with IP allowlisting (Step 3) and disabling the account after the audit (Step 8), the blast radius is minimal.

**Q: Are credentials in the report?**
A: No. The script's redactor (`ise_api/audit.py:_SECRET_FIELD_NAMES`) strips RADIUS / TACACS shared secrets, SNMP communities, passwords, encryption keys, and message-auth keys before persisting any output. You can verify with `grep REDACTED audit-output/*.json`.

**Q: What if my security team wants to review the script first?**
A: Encouraged. The two files that matter are [`python/ise_api/audit.py`](https://github.com/asarmiento85/cisco-ise-automation/blob/main/python/ise_api/audit.py) (the collector) and [`python/scripts/audit_deep.py`](https://github.com/asarmiento85/cisco-ise-automation/blob/main/python/scripts/audit_deep.py) (the CLI). Confirm every HTTP call is a `GET`. The Python library `httpx` underneath has well-known semantics — there is no hidden side channel.

**Q: Will running this audit affect production traffic?**
A: No. The audit reads configuration objects (not live session data). The load on the PAN is comparable to one user clicking through the admin UI for ~30 seconds. Total payload is under 1 MB.

**Q: Can we run it during business hours?**
A: Yes — no maintenance window needed. It's read-only and lightweight.

**Q: Can we run it ourselves on a recurring schedule (e.g. quarterly)?**
A: That's the recommended pattern. Re-run every quarter against the same audit account, compare the JSON outputs to detect drift. The recommendations catalog includes this as `REC-OPS-001`.

---

## Need help?

- Issues with the script itself → open a GitHub issue at https://github.com/asarmiento85/cisco-ise-automation/issues
- Questions about findings in your specific report → contact your consultant
- General questions about read-only ISE audits → see the blog post at https://blog.it-learn.io
