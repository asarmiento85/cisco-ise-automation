"""Remediation catalog and builder.

Each finding produced by `ise_api.audit.analyze` carries a `rec_key`
(e.g. "REC-CERT-001"). This module maps those keys to actionable
remediation plans with: rationale, GUI/CLI steps, effort estimate,
operational risk, and a priority (P1 / P2 / P3).

Plus a small set of always-on operational hygiene recommendations
(REC-OPS-*) that apply regardless of findings.
"""

from __future__ import annotations

from typing import Any

# Priority bands (consultant-facing; map to severity loosely)
#   P1 = act now           (this sprint / this week)
#   P2 = plan this quarter
#   P3 = opportunistic cleanup

REC_CATALOG: dict[str, dict[str, Any]] = {
    # -------------------- CERTIFICATES --------------------
    "REC-CERT-001": {
        "title": "Replace expired or near-expiry PAN system certificate",
        "category": "Certificates",
        "priority": "P1",
        "effort": "30–60 min",
        "risk": "Medium — brief services impact during cert bind",
        "rationale": (
            "Expired or imminent-expiry system certificates on the PAN break the management plane "
            "and any service bound to them (Admin, EAP authentication, RADIUS DTLS, pxGrid, Portal, "
            "ISE Messaging). When the cert used by EAP expires, all 802.1X EAP-TLS / PEAP / EAP-FAST "
            "sessions fail authentication — a deployment-wide outage."
        ),
        "steps": [
            "Identify all services bound to the expired cert (column 'Used by' in System Certificates).",
            "Generate a CSR: Administration → System → Certificates → System Certificates → Generate CSR. Match the existing CN/SAN and key length (RSA-2048 min, RSA-4096 preferred).",
            "Submit CSR to internal/public CA; obtain signed cert + full chain.",
            "Import the signed cert into the PAN, binding it to the same services as the old one.",
            "Distribute trusted root/intermediate to NADs and endpoints if a new chain is introduced (deploy via GPO / MDM / DHCP option 43 / NAC profile).",
            "In a maintenance window, mark the new cert as Default for each affected service, then revoke the old cert.",
            "Verify: monitor Live Logs, watch for EAP-TLS chain failures for ~24h.",
        ],
        "doc_refs": ["Cisco ISE 3.x Admin Guide — Certificates"],
    },
    "REC-CERT-002": {
        "title": "Re-issue SHA-1 certificates with SHA-256 signature",
        "category": "Certificates",
        "priority": "P2",
        "effort": "30 min per cert",
        "risk": "Low",
        "rationale": (
            "SHA-1 signatures are deprecated. Modern browsers and supplicants reject SHA-1 admin/portal "
            "certificates outright; EAP-TLS clients may also reject them depending on policy."
        ),
        "steps": [
            "Generate a fresh CSR with `-sha256` signature on your CA.",
            "Replace the SHA-1 cert per REC-CERT-001 steps.",
            "Confirm browser admin access works without certificate warnings.",
        ],
    },
    "REC-CERT-003": {
        "title": "Replace self-signed certificates with CA-signed (production only)",
        "category": "Certificates",
        "priority": "P3",
        "effort": "1 hour",
        "risk": "Low",
        "rationale": (
            "Self-signed certs are fine for lab/PoC but force endpoints and admins to trust each ISE "
            "node individually. CA-signed certs centralize trust and remove warning prompts."
        ),
        "steps": [
            "Choose CA (internal PKI for EAP, public CA for guest portal).",
            "Replace per REC-CERT-001.",
            "Push CA root to endpoint trust stores (GPO/MDM).",
        ],
    },
    "REC-CERT-004": {
        "title": "Refresh expiring trusted certificates before chain breakage",
        "category": "Certificates",
        "priority": "P2",
        "effort": "15–30 min",
        "risk": "Medium — chain breakage causes auth failures",
        "rationale": (
            "Trusted store certs build the validation chain for EAP, AD/LDAPS, external services, and "
            "SAML. When an intermediate or root in the store expires, the dependent chain breaks even "
            "if the leaf cert is still valid."
        ),
        "steps": [
            "Administration → System → Certificates → Trusted Certificates. Sort by expiration.",
            "Identify the purpose of each expiring cert (which services trust it).",
            "Import the renewed root/intermediate from the issuing CA BEFORE the old one expires.",
            "Keep the old + new in parallel during transition; remove old after verification.",
        ],
    },

    # -------------------- NAD INVENTORY --------------------
    "REC-NAD-001": {
        "title": "Remove orphan NAD entries (no IP configured)",
        "category": "NAD inventory",
        "priority": "P3",
        "effort": "5 min per NAD",
        "risk": "Very low — orphan NADs are non-functional anyway",
        "rationale": (
            "NAD records with no IP can't match any RADIUS / TACACS+ source and clutter the inventory. "
            "They often remain after device decommissions or failed imports."
        ),
        "steps": [
            "Export current NAD list (Administration → Network Resources → Network Devices → Export).",
            "Confirm each orphan really has no IP and isn't referenced by a NDG-only rule.",
            "Delete via GUI or ERS API.",
        ],
    },
    "REC-NAD-002": {
        "title": "Resolve duplicate NAD IP addresses",
        "category": "NAD inventory",
        "priority": "P1",
        "effort": "15 min",
        "risk": "High if not resolved — RADIUS may match the wrong NAD",
        "rationale": (
            "Two NAD records sharing the same IP/mask cause non-deterministic matching for RADIUS "
            "attributes, shared secrets, and NDG-based authorization. Auth/authz behavior diverges "
            "between sessions."
        ),
        "steps": [
            "Verify which NAD entry should own the IP (check device hostname, shared secret, NDG).",
            "Delete the stale entry, OR adjust the mask so each record owns a distinct range.",
            "Monitor Live Logs for failed auths from the affected IP for 24h.",
        ],
    },
    "REC-NAD-003": {
        "title": "Assign Location and Device Type NDGs to all NADs",
        "category": "NAD inventory",
        "priority": "P3",
        "effort": "5 min per NAD",
        "risk": "Very low",
        "rationale": (
            "Location and Device Type NDGs are the standard building blocks for scoping authorization "
            "policy. NADs missing them silently fall outside any rule keyed on those NDGs, leaving "
            "policy intent unmet."
        ),
        "steps": [
            "Bulk-import via CSV (Network Devices → Import) with NDG columns populated, OR",
            "Edit each NAD and add the appropriate Location + Device Type group.",
            "Verify policy sets that reference NDGs now match correctly.",
        ],
    },
    "REC-NAD-004": {
        "title": "Standardize CoA destination port across the fleet",
        "category": "NAD inventory",
        "priority": "P3",
        "effort": "5 min per NAD + matching switch config",
        "risk": "Medium — mismatched ports silently break CoA",
        "rationale": (
            "Mixed CoA ports (1700 vs 3799) are a common source of 'redirect works but CoA never "
            "fires' incidents — posture / change-of-authorization just silently fails."
        ),
        "steps": [
            "Decide on 1700 (Cisco-default) OR 3799 (RFC-default) and standardize.",
            "Update each non-conforming NAD record.",
            "Update switch / WLC `aaa server radius dynamic-author` config to match.",
        ],
    },

    # -------------------- ADMIN ACCESS --------------------
    "REC-ADMIN-001": {
        "title": "Harden the default 'admin' account",
        "category": "Admin access",
        "priority": "P2",
        "effort": "1–2 hours",
        "risk": "Low — keep one break-glass account",
        "rationale": (
            "Shared 'admin' credentials destroy accountability (no audit trail attribution) and present "
            "a known username for credential-stuffing attacks. Best practice is named admin accounts "
            "backed by AD/external auth, with the default 'admin' kept as a strict break-glass account."
        ),
        "steps": [
            "Create a named admin per administrator (Administration → Identity Management → Admin Users).",
            "Map them to appropriate RBAC roles (Super Admin only for the few who truly need it).",
            "Integrate Admin Access with AD: Administration → System → Admin Access → Authentication → Password-Based → AD.",
            "Enforce password policy: min 14 chars, complexity, 90-day rotation, lockout after 5 failures.",
            "Rotate the default 'admin' password to a vaulted random string; document break-glass procedure.",
            "Audit Admin Access logs monthly: Operations → Reports → Audit → Administrator Logins.",
        ],
    },
    "REC-ADMIN-002": {
        "title": "Reduce Super Admin membership",
        "category": "Admin access",
        "priority": "P2",
        "effort": "30 min",
        "risk": "Low",
        "rationale": (
            "Super Admin can read/write everything including secrets. Keep membership to 2–3 trusted "
            "engineers; others should use scoped roles (RBAC Custom Admin)."
        ),
        "steps": [
            "List current Super Admin members and validate each against current role.",
            "Move day-to-day admins to scoped roles (Identity Admin, Network Device Admin, Policy Admin).",
            "Document who holds Super Admin and the rotation schedule.",
        ],
    },

    # -------------------- BACKUPS --------------------
    "REC-BACKUP-001": {
        "title": "Configure a backup repository (no repo = no DR)",
        "category": "Backups",
        "priority": "P1",
        "effort": "30 min",
        "risk": "None to configure; high not to",
        "rationale": (
            "Without a backup repository, the deployment cannot snapshot config or operational data. "
            "Rebuilds after corruption or hardware failure become from-scratch reinstalls."
        ),
        "steps": [
            "Provision an SFTP server reachable from the PAN (and PSNs if you want per-node ops backups).",
            "Administration → System → Maintenance → Repository → Add. Use SFTP with key-based auth.",
            "Test the repo (Save → Validate).",
            "Run one immediate Config Backup to confirm end-to-end.",
        ],
    },
    "REC-BACKUP-002": {
        "title": "Migrate backup repository from FTP to SFTP/HTTPS",
        "category": "Backups",
        "priority": "P2",
        "effort": "30 min",
        "risk": "Low",
        "rationale": (
            "FTP transmits credentials and the backup payload in cleartext. The backup contains "
            "encrypted credentials, certs, and full policy — an FTP capture is an offline crack target."
        ),
        "steps": [
            "Stand up SFTP target with restricted user + key auth.",
            "Add new repo in ISE; run a manual Config Backup to validate.",
            "Update any Scheduled Backup to point at the new repo.",
            "Decommission the FTP repo + server.",
        ],
    },
    "REC-BACKUP-003": {
        "title": "Schedule automated configuration backups",
        "category": "Backups",
        "priority": "P1",
        "effort": "15 min",
        "risk": "None",
        "rationale": (
            "On-demand backups depend on human discipline. A scheduled cadence ensures recovery points "
            "exist regardless of operator activity."
        ),
        "steps": [
            "Administration → System → Backup & Restore → Schedule.",
            "Daily incremental + weekly full is the common pattern.",
            "Set an encryption passphrase and store it in the org password vault (NOT in the repo).",
            "Set retention to ~30 days (or per data-retention policy).",
            "Configure email alerts on backup failure.",
        ],
    },

    # -------------------- POLICY --------------------
    "REC-POLICY-001": {
        "title": "Remove catch-all PermitAccess authorization rules",
        "category": "Policy",
        "priority": "P1",
        "effort": "2–4 hours",
        "risk": "High — wrong condition = locked-out users",
        "rationale": (
            "Any authz rule that grants PermitAccess with an empty/true condition is effectively "
            "'allow all that reach this rule'. Combined with rule ordering, this often unintentionally "
            "grants full network access to any successful authentication — including failed-auth-then-"
            "matched-by-fallback flows. This is one of the most common findings in ISE audits."
        ),
        "steps": [
            "Identify the offending rule(s) and trace what conditions SHOULD restrict it (group membership, NDG, posture status, EAP method).",
            "Build the correct condition in a test policy set first.",
            "Use ISE's 'Policy Test' (Operations → Policy Test) with sample attributes to confirm match behavior.",
            "Reorder rules so the new restrictive rule sits above the catch-all, then disable the catch-all.",
            "Monitor Live Logs for 24–48h; re-enable only the catch-all you actually need (often: 'authenticated AD-domain-user → limited access').",
        ],
    },
    "REC-POLICY-002": {
        "title": "Clean up unused authorization profiles",
        "category": "Policy",
        "priority": "P3",
        "effort": "5 min per profile",
        "risk": "Very low",
        "rationale": (
            "Unused authz profiles inflate the policy element catalog, confuse operators, and increase "
            "the chance of accidentally referencing the wrong one in a new rule."
        ),
        "steps": [
            "Export current state for rollback.",
            "Confirm each profile is unreferenced (search across policy sets including exceptions).",
            "Delete via Policy → Policy Elements → Results → Authorization → Authorization Profiles.",
        ],
    },

    # -------------------- DEVICE ADMIN --------------------
    "REC-TACACS-001": {
        "title": "Refactor TACACS+ per-command authorization to deny-list shell profiles",
        "category": "Device admin",
        "priority": "P1",
        "effort": "4–8 hours per platform",
        "risk": "High — can lock admins out of network gear",
        "rationale": (
            "Per-command authorization is fragile: every command issued by an admin requires a "
            "real-time TACACS round-trip. If the TACACS service is unreachable (PSN issue, network "
            "partition, ACL drop) admins lose access to switches mid-session. The preferred pattern "
            "is privilege-level shell profiles plus a small command-set deny-list."
        ),
        "steps": [
            "Audit current per-command rules; group commands by intent (read-only, network-config, debug).",
            "Build 1–2 shell profiles: 'priv-1-readonly' and 'priv-15-fulladmin' (or a third 'config-only').",
            "Add a command-set DENY list for the small number of truly dangerous commands ('reload', 'format', 'no aaa').",
            "Test with a shadow lab account; verify behavior with TACACS up AND with TACACS forced down (this is the critical test).",
            "Cut over policy set by policy set; always keep a console enable secret as break-glass.",
            "Document break-glass on each NAD: `aaa authentication login CONSOLE local`.",
        ],
    },

    # -------------------- TRUSTSEC --------------------
    "REC-TRUSTSEC-001": {
        "title": "Activate the egress matrix or remove dormant SGTs",
        "category": "TrustSec",
        "priority": "P3",
        "effort": "Variable — full TrustSec rollout is multi-week",
        "risk": "Medium during rollout, low otherwise",
        "rationale": (
            "SGTs defined without an egress matrix produce metadata but enforce nothing. Either move "
            "forward with enforcement (SGACLs at switch egress / firewall) or remove the SGTs to "
            "reduce noise."
        ),
        "steps": [
            "Decide: are we using TrustSec or not?",
            "If yes: design SGACLs, populate matrix, propagate via SXP or inline tagging, enable enforcement on a pilot switch.",
            "If no: remove unreferenced SGT definitions from Work Centers → TrustSec → Components → Security Groups.",
        ],
    },

    # -------------------- PROFILER --------------------
    "REC-PROFILER-001": {
        "title": "Keep profiler feed current and track custom profiles separately",
        "category": "Profiler",
        "priority": "P3",
        "effort": "30 min one-time + monthly review",
        "risk": "Low",
        "rationale": (
            "A large profiler catalog is mostly Cisco's stock feed. The risk is when custom additions "
            "blend in with the feed and get clobbered by an update. Track them explicitly."
        ),
        "steps": [
            "Administration → Feed Service → Profiler. Enable automatic updates from Cisco.",
            "Tag any custom profiles with a 'Custom_' prefix or distinct description for grep-ability.",
            "Export the custom-only list quarterly and store in git.",
        ],
    },

    # -------------------- IDENTITY --------------------
    "REC-IDENTITY-001": {
        "title": "Force or cycle internal user password resets",
        "category": "Identity",
        "priority": "P3",
        "effort": "Variable",
        "risk": "Low",
        "rationale": (
            "Internal users flagged 'must change password' may be carrying initial / temporary "
            "credentials. They should be cycled or removed."
        ),
        "steps": [
            "Identify whether each account is still in use (last-login report).",
            "Contact owners to rotate, or disable accounts that should not exist.",
            "Consider migrating real users to AD/LDAP instead of internal store.",
        ],
    },
}

# Always-emitted operational hygiene recommendations — apply regardless of findings.
_GENERIC_RECS: list[dict[str, Any]] = [
    {
        "id": "REC-OPS-001",
        "title": "Establish a quarterly read-only audit cadence",
        "category": "Operations",
        "priority": "P2",
        "effort": "1 hour per audit",
        "risk": "None",
        "rationale": (
            "Drift is the dominant failure mode of healthy ISE deployments — small policy additions, "
            "expired certs, NAD churn. A scheduled audit catches drift before it becomes an incident."
        ),
        "steps": [
            "Schedule a recurring calendar invite (quarterly minimum, monthly preferred).",
            "Run `scripts/audit_deep.py --pdf` against the prod PAN.",
            "Compare findings against the prior quarter; treat new HIGH findings as P1 tickets.",
            "Archive the JSON dump in git or a runbook repo for diffability.",
        ],
        "addresses": [],
        "rec_key": "REC-OPS-001",
    },
    {
        "id": "REC-OPS-002",
        "title": "Document and test the break-glass procedure",
        "category": "Operations",
        "priority": "P1",
        "effort": "2 hours one-time + annual drill",
        "risk": "None to document; high not to",
        "rationale": (
            "When the PAN is unreachable, AD is broken, or TACACS dies, you need a documented and "
            "drilled path to recover admin access on every class of device — switches, WLC, firewalls, "
            "ISE itself. Most outages turn into multi-hour outages because no one remembers the "
            "console password."
        ),
        "steps": [
            "Document per-platform: console enable secret, local fallback user, recovery boot.",
            "Store secrets in the org vault (not on the wiki).",
            "Run a tabletop annually: 'TACACS is down for 4 hours — walk me through getting into a core switch'.",
        ],
        "addresses": [],
        "rec_key": "REC-OPS-002",
    },
    {
        "id": "REC-OPS-003",
        "title": "Subscribe to Cisco PSIRT advisories for ISE",
        "category": "Operations",
        "priority": "P2",
        "effort": "15 min",
        "risk": "None",
        "rationale": (
            "ISE PSIRT advisories include critical-severity items each year (auth bypass, command "
            "injection on the admin UI, etc.). Patch latency is unacceptable for an identity plane."
        ),
        "steps": [
            "Subscribe at tools.cisco.com/security/center → MySubscriptions → ISE.",
            "Route advisories to a security-eng channel.",
            "Track patch latency as a quarterly metric.",
        ],
        "addresses": [],
        "rec_key": "REC-OPS-003",
    },
    {
        "id": "REC-OPS-004",
        "title": "Verify patch and hotpatch latency against current train",
        "category": "Operations",
        "priority": "P2",
        "effort": "Patch window (2–4 hours)",
        "risk": "Medium during apply; high not to apply",
        "rationale": (
            "ISE major + patch latency is a primary risk indicator. Confirm the deployment is within "
            "two patches of the latest GA release on its train, and that hotpatches addressing "
            "PSIRT items are applied."
        ),
        "steps": [
            "Compare current patch (Administration → System → Maintenance → Patch Management) to the latest on cisco.com.",
            "Read release notes for breaking changes.",
            "Apply to PSN(s) first in a maintenance window, then secondary PAN, then primary PAN.",
        ],
        "addresses": [],
        "rec_key": "REC-OPS-004",
    },
]

_PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2}


def build_recommendations(findings: list[dict]) -> list[dict]:
    """Map findings → recommendations; merge duplicates; append generic hygiene recs."""
    by_key: dict[str, dict] = {}
    for f in findings:
        key = f.get("rec_key")
        if not key or key not in REC_CATALOG:
            continue
        if key not in by_key:
            by_key[key] = {
                "id": key,
                **REC_CATALOG[key],
                "addresses": [],
                "rec_key": key,
            }
        by_key[key]["addresses"].append(f["msg"])

    recs = list(by_key.values()) + _GENERIC_RECS
    recs.sort(key=lambda r: (_PRIORITY_RANK.get(r.get("priority", "P3"), 9), r["category"], r["id"]))
    return recs
