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
    "REC-POLICY-003": {
        "title": "Retire stale / never-hit policy rules and sets",
        "category": "Policy",
        "priority": "P3",
        "effort": "1–3 hours",
        "risk": "Low — disable before deleting; verify over a full hit window",
        "rationale": (
            "Each ISE rule carries a hit counter. Enabled rules with zero hits — and whole policy sets "
            "with no recorded activity — are dead weight: they slow evaluation, obscure the rules that "
            "actually matter, and accumulate across migrations. The counter is cumulative since the "
            "last reset, so confirm against a representative window before removing, but a long-running "
            "node with 0 hits on a rule is a strong cleanup signal."
        ),
        "steps": [
            "In each policy set, note the rules reporting 0 hits over a meaningful period (Policy → Policy Sets shows the Hits column).",
            "Disable (don't delete) the suspects first; leave them disabled for a billing/auth cycle.",
            "If still 0 hits and no complaints, delete them.",
            "For an entire set with no activity, confirm the NADs that should hit it are pointed at ISE, then retire the set if genuinely unused.",
        ],
    },
    "REC-POLICY-004": {
        "title": "Resolve shadowed / unreachable authorization rules",
        "category": "Policy",
        "priority": "P2",
        "effort": "30 min per set",
        "risk": "Medium — fixing order changes who matches what",
        "rationale": (
            "A rule whose condition is identical to (or fully covered by) an earlier enabled rule in the "
            "same set can never match — ISE stops at the first hit. Shadowed rules are either dead "
            "(harmless clutter) or a sign the intended logic never takes effect, which is a silent "
            "policy bug."
        ),
        "steps": [
            "For each flagged rule, compare its condition to the earlier rule that shadows it.",
            "If the shadowed rule is intended to behave differently, reorder it above the broader rule or tighten the broader rule's condition.",
            "If it's redundant, remove it.",
            "Use Policy Test (Operations → Policy Test) to confirm the intended rule now matches.",
        ],
    },
    "REC-POLICY-005": {
        "title": "Consolidate duplicate authorization profiles",
        "category": "Policy",
        "priority": "P3",
        "effort": "15 min per group",
        "risk": "Low",
        "rationale": (
            "Multiple authorization profiles that push the exact same result (same VLAN / dACL / "
            "redirect) multiply maintenance: a change has to be made in several places and it's easy to "
            "update one and miss another. Consolidate to a single profile referenced everywhere."
        ),
        "steps": [
            "Pick one canonical profile from each duplicate group.",
            "Repoint the rules that use the others to the canonical profile.",
            "Delete the now-unreferenced duplicates.",
        ],
    },
    "REC-POLICY-006": {
        "title": "Fix broken policy references",
        "category": "Policy",
        "priority": "P2",
        "effort": "15 min per reference",
        "risk": "Medium — a rule referencing a missing object can fail unexpectedly",
        "rationale": (
            "A rule that references an authorization profile or security group that no longer exists is "
            "broken: depending on the object, ISE may fall through, deny, or error. These usually appear "
            "after an element was deleted while a rule still pointed at it."
        ),
        "steps": [
            "For each flagged rule, recreate the missing object or repoint the rule at the correct existing one.",
            "Confirm with Policy Test that the rule now resolves.",
            "Add a pre-delete check to your change process: search for references before removing any policy element.",
        ],
    },
    "REC-POLICY-007": {
        "title": "Remove test / temporary rules from production policy",
        "category": "Policy",
        "priority": "P1",
        "effort": "30 min",
        "risk": "High — a permissive test rule can grant unintended access fleet-wide",
        "rationale": (
            "Rules named like 'Test', 'Temp', or 'Allow All' that remain enabled in production are a "
            "classic source of over-permissioned access. When such a rule also carries a high hit count, "
            "it is actively carrying production traffic — meaning the intended, more specific rules below "
            "it may never be evaluated, and a broad SGT/profile is being handed out widely."
        ),
        "steps": [
            "Identify what the test rule grants and how many sessions depend on it (Hits column + Live Logs).",
            "Build/verify the correct specific rule(s) that should be matching that traffic instead.",
            "Reorder so the specific rules sit above, then disable the test rule and watch Live Logs.",
            "Once traffic shifts to the intended rules with no denials, delete the test rule.",
        ],
    },
    "REC-POLICY-008": {
        "title": "End every policy set with an explicit DenyAccess default",
        "category": "Policy",
        "priority": "P2",
        "effort": "5 min per set",
        "risk": "Low",
        "rationale": (
            "An explicit DenyAccess default rule makes the set's fail-closed behavior unambiguous and "
            "auditable. A set whose last rule is anything else (or which relies on implicit behavior) is "
            "harder to reason about and can mask an unintended permit."
        ),
        "steps": [
            "Open the policy set and check the final default rule.",
            "Set the default authorization result to DenyAccess unless there is a documented reason otherwise.",
            "Confirm upstream rules intentionally permit only what they should.",
        ],
    },

    # -------------------- DEVICE ADMIN --------------------
    "REC-TACACS-002": {
        "title": "Review TACACS+ rules with no shell profile or command set",
        "category": "Device admin",
        "priority": "P3",
        "effort": "10 min per rule",
        "risk": "Low",
        "rationale": (
            "A device-admin authorization rule that assigns neither a shell profile nor a command set "
            "grants nothing — it is either a misconfiguration (the admin forgot to attach a result) or "
            "leftover scaffolding. Either way it adds noise to the policy."
        ),
        "steps": [
            "For each flagged rule, decide the intended result and attach the correct shell profile and/or command set.",
            "If the rule serves no purpose, delete it.",
        ],
    },
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

    # -------------------- API ACCESS --------------------
    "REC-API-001": {
        "title": "Enable the Open API service for full audit coverage",
        "category": "API access",
        "priority": "P1",
        "effort": "5 min + re-run the audit",
        "risk": "None — enabling the service changes no policy; RBAC still gates every request",
        "rationale": (
            "ISE has two API services: ERS (legacy, /ers/...) and Open API (/api/v1/...). When Open "
            "API is disabled, its routes answer with an HTTP 302 redirect to the GUI login page, and "
            "everything the audit reads through it — deployment nodes, policy sets, system/trusted "
            "certificates, repositories, backup schedule, licensing, security settings — comes back "
            "empty. The audit report is then partial, and 'missing' items in those sections cannot "
            "be distinguished from unread ones."
        ),
        "steps": [
            "Log in to the ISE admin GUI as a Super Admin.",
            "Administration → System → Settings → API Settings → API Service Settings tab.",
            "Enable 'Open API (Read/Write)' — the toggle enables the service; the audit account's read-only RBAC still applies to every call.",
            "Save. The service activates within about a minute — no restart needed.",
            "Confirm the audit account (or its AD group) is also mapped to an admin group with GUI read access (e.g. Read Only Admin) — ERS Operator alone does not authorize /api/v1 calls.",
            "Re-run the audit and check the Endpoint Coverage Matrix — OpenAPI rows should now read OK.",
        ],
    },

    # -------------------- MIGRATION-CRITICAL --------------------
    "REC-AUTH-001": {
        "title": "Disable deprecated authentication methods carried over by migration",
        "category": "Weak auth methods",
        "priority": "P1",
        "effort": "1–2 hours + supplicant verification",
        "risk": "Medium — confirm no live clients depend on the weak method first",
        "rationale": (
            "Legacy methods — PAP, CHAP, MS-CHAPv1, EAP-MD5, LEAP, and EAP-FAST anonymous PAC "
            "provisioning — are cryptographically weak or unauthenticated, and are trivially "
            "downgraded or cracked. ISE migrations copy the Allowed Protocols definitions verbatim, "
            "so a deployment that enabled these years ago still has them enabled today. Most "
            "environments have long since moved every real client to PEAP/EAP-TLS and no longer "
            "need them — but nobody turned them off."
        ),
        "steps": [
            "For each flagged Allowed Protocols set: Policy → Policy Elements → Results → Authentication → Allowed Protocols.",
            "Before disabling: run Operations → RADIUS → Live Logs filtered on the weak method to confirm no live clients still use it.",
            "Disable PAP/ASCII, CHAP, MS-CHAPv1, EAP-MD5, LEAP unless a documented device class genuinely requires one.",
            "For EAP-FAST, disable anonymous in-band PAC provisioning; require authenticated provisioning.",
            "Re-test a representative client of each platform after the change.",
        ],
    },
    "REC-TLS-001": {
        "title": "Disable TLS 1.0/1.1 and SHA-1 ciphers",
        "category": "Security settings",
        "priority": "P1",
        "effort": "30–60 min",
        "risk": "Medium — very old endpoints/browsers may lose access",
        "rationale": (
            "TLS 1.0 and 1.1 are deprecated (RFC 8996) and SHA-1 ciphers are broken. Old ISE "
            "deployments commonly left them enabled for legacy supplicant compatibility, and the "
            "setting migrates forward. They weaken EAP-TLS, admin HTTPS, and portal TLS."
        ),
        "steps": [
            "Administration → System → Settings → Security Settings.",
            "Set the minimum TLS version to 1.2 (1.3 where supported) for both EAP and admin/portal.",
            "Disallow SHA-1 cipher suites.",
            "For EAP-TLS specifically, check the Allowed Protocols TLS-version setting too.",
            "Identify any endpoint still requiring TLS 1.0/1.1 (Live Logs) and remediate the endpoint, not ISE.",
        ],
    },
    "REC-NODE-001": {
        "title": "Resolve node replication / sync state",
        "category": "Node health",
        "priority": "P1",
        "effort": "Variable — may need TAC",
        "risk": "High — a desynced node serves stale policy",
        "rationale": (
            "A node not in a healthy replication state serves stale configuration to the endpoints "
            "it authenticates. Right after a migration this is a common transient that sometimes "
            "doesn't self-heal."
        ),
        "steps": [
            "Administration → System → Deployment → select the node → check Replication Status.",
            "Try a manual Syncup from the PAN.",
            "If it won't converge, deregister + re-register the node (maintenance window).",
            "Escalate to Cisco TAC if replication errors persist.",
        ],
    },
    "REC-NODE-002": {
        "title": "Bring all nodes to a single software version + patch level",
        "category": "Node health",
        "priority": "P1",
        "effort": "Patch window per node",
        "risk": "High — mixed versions are unsupported",
        "rationale": (
            "ISE does not support running mixed software/patch versions across a deployment beyond a "
            "brief upgrade window. Mixed versions cause replication failures and unpredictable policy "
            "evaluation. Post-migration this happens when one node's patch didn't apply."
        ),
        "steps": [
            "Administration → System → Maintenance → Patch Management — compare patch level across nodes.",
            "Apply the missing patch to the lagging node(s), PSNs first then secondary PAN then primary PAN.",
            "Confirm all nodes report identical version + patch.",
        ],
    },
    "REC-CERT-005": {
        "title": "Repair broken certificate trust chains",
        "category": "Certificates",
        "priority": "P1",
        "effort": "30 min per chain",
        "risk": "Medium — chain gaps cause intermittent auth failures",
        "rationale": (
            "A system certificate whose issuing CA is not present in the Trusted Certificates store "
            "produces an incomplete chain. Clients that strictly validate the chain (EAP-TLS, LDAPS, "
            "SAML) fail intermittently. Migrations frequently bring the leaf cert across but miss the "
            "intermediate/root."
        ),
        "steps": [
            "Identify the issuing CA of the flagged system cert (issuer field).",
            "Obtain the full chain (root + intermediates) from your PKI.",
            "Administration → System → Certificates → Trusted Certificates → Import the missing CA cert(s).",
            "Mark them trusted for the relevant purposes (Auth for EAP, ISE infrastructure, etc.).",
            "Re-test an EAP-TLS client to confirm the chain now validates.",
        ],
    },
    "REC-STALE-001": {
        "title": "Verify external references still point at live infrastructure",
        "category": "Stale references",
        "priority": "P2",
        "effort": "1–2 hours",
        "risk": "Low to verify; high if a dead target is in an active path",
        "rationale": (
            "External RADIUS servers, backup repositories, logging targets, and RADIUS server "
            "sequences all reference remote hosts by IP/name. After a migration (or a data-center "
            "move) some of these point at decommissioned hosts. A dead target in an active "
            "authentication or logging path causes timeouts and silent data loss."
        ),
        "steps": [
            "For each flagged reference, confirm the destination host still exists and is reachable from ISE.",
            "Remove or update references to retired infrastructure.",
            "For external RADIUS proxy targets, test an end-to-end auth through the sequence.",
            "For repositories, run a manual backup to validate.",
        ],
    },
    "REC-CLEANUP-001": {
        "title": "Remove leftover default / sample artifacts",
        "category": "Cleanup",
        "priority": "P3",
        "effort": "15–30 min",
        "risk": "Very low",
        "rationale": (
            "Default and sample objects (sample sponsor groups, unused default policy sets) clutter "
            "the config and occasionally shadow real intent. They ride through migrations untouched."
        ),
        "steps": [
            "Confirm each flagged object is genuinely unused (not referenced by any active policy).",
            "Delete sample sponsor groups and unused default policy sets.",
            "Keep one documented catch-all if your design relies on it.",
        ],
    },

    # -------------------- SECURITY HARDENING --------------------
    "REC-FIPS-001": {
        "title": "Confirm FIPS posture matches compliance requirements",
        "category": "Security settings",
        "priority": "P3",
        "effort": "Planning + maintenance window if enabling",
        "risk": "High to enable — FIPS restricts algorithms deployment-wide",
        "rationale": (
            "FIPS mode is off by default and most deployments are fine that way. Only flag this if the "
            "customer operates under FedRAMP / FISMA / similar mandates that require FIPS-validated "
            "crypto. Enabling FIPS disables non-compliant algorithms across the deployment and is a "
            "significant change."
        ),
        "steps": [
            "Confirm whether a compliance mandate actually requires FIPS.",
            "If yes: plan carefully — FIPS forces certificate, protocol, and password changes.",
            "Enable under Administration → System → Settings → FIPS Mode in a maintenance window.",
        ],
    },
    "REC-ADMIN-003": {
        "title": "Strengthen the admin password policy",
        "category": "Admin access",
        "priority": "P2",
        "effort": "15 min",
        "risk": "Low",
        "rationale": (
            "A short admin password minimum is a weak link for the identity plane's own management. "
            "Recommend ≥12–14 chars with complexity, history, and rotation."
        ),
        "steps": [
            "Administration → System → Admin Access → Authentication → Password Policy.",
            "Set minimum length ≥12 (14 preferred), enable complexity + history.",
            "Set a rotation interval consistent with org policy.",
        ],
    },
    "REC-ADMIN-004": {
        "title": "Tighten admin GUI session timeout",
        "category": "Admin access",
        "priority": "P3",
        "effort": "5 min",
        "risk": "Very low",
        "rationale": (
            "A long idle session timeout leaves authenticated admin sessions open on unattended "
            "workstations."
        ),
        "steps": [
            "Administration → System → Admin Access → Settings → Session.",
            "Set idle timeout to ≤30–60 min per policy.",
        ],
    },
    "REC-LOG-001": {
        "title": "Configure a remote logging (syslog) target",
        "category": "Logging",
        "priority": "P2",
        "effort": "30 min",
        "risk": "Low",
        "rationale": (
            "Without a remote syslog/SIEM target, security and audit events live only in the MnT "
            "database and age out per retention. A migration sometimes drops the old syslog target. "
            "Forwarding to a SIEM is essential for incident response and tamper-evidence."
        ),
        "steps": [
            "Administration → System → Logging → Remote Logging Targets → Add (your SIEM/syslog collector).",
            "Administration → System → Logging → Logging Categories → map AAA, admin, and posture categories to the target.",
            "Confirm events arrive at the SIEM.",
        ],
    },

    # -------------------- OPERATIONAL DEPTH --------------------
    "REC-PROFILER-002": {
        "title": "Enable the profiler feed auto-update",
        "category": "Profiler",
        "priority": "P3",
        "effort": "15 min",
        "risk": "Low",
        "rationale": (
            "With the feed disabled, new device fingerprints never arrive and endpoint classification "
            "degrades over time — more endpoints land in 'Unknown'. The setting is sometimes left off "
            "after a migration."
        ),
        "steps": [
            "Administration → System → Settings → Profiling, and Work Centers → Profiler → Feeds.",
            "Enable automatic feed updates from Cisco; set a schedule.",
            "Verify the last-update timestamp advances.",
        ],
    },
    "REC-PXGRID-001": {
        "title": "Disable pxGrid client auto-approve",
        "category": "pxGrid",
        "priority": "P2",
        "effort": "10 min",
        "risk": "Low",
        "rationale": (
            "pxGrid auto-approve lets any client that requests it register and subscribe to the "
            "context bus without manual vetting. Approve clients explicitly instead."
        ),
        "steps": [
            "Administration → pxGrid Services → Settings → uncheck automatic approval.",
            "Review currently registered clients; revoke any unrecognized ones.",
        ],
    },
    "REC-ENDPOINT-001": {
        "title": "Investigate high 'Unknown' endpoint ratio",
        "category": "Endpoints",
        "priority": "P3",
        "effort": "Variable",
        "risk": "Low",
        "rationale": (
            "A large share of endpoints in the Unknown group means profiling isn't classifying them — "
            "missing probes (DHCP/SNMP/RADIUS), a disabled feed, or stale endpoint records carried "
            "through the migration."
        ),
        "steps": [
            "Confirm profiling probes are enabled on PSNs (RADIUS, DHCP, SNMP, HTTP).",
            "Enable the profiler feed (see REC-PROFILER-002).",
            "Purge stale endpoints via Administration → Identity Management → Settings → Endpoint Purge.",
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
