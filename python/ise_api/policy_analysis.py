"""Static policy analysis from already-collected config.

Works entirely on the data `ise_api.audit.collect` already pulls — the OpenAPI
policy-set payloads carry per-rule `hitCounts`, `rank`, `state`, and the full
`condition` tree, so we can do real usage + structure analysis with no extra
access:

  * hit-based:   most-used rules, enabled rules that never fire (stale
                 candidates), whole policy sets with no recorded activity
  * structure:   duplicate / shadowed / unreachable rules (identical condition
                 earlier in the same set), missing explicit default-deny
  * hygiene:     test/temporary rules live in production, broken references
                 (profile / SGT that no longer exists), duplicate authorization
                 profiles, TACACS authz rules with neither shell profile nor
                 command set

`analyze_policies(data)` returns a structured dict for the report section.
`policy_findings(analysis)` returns findings (same shape as audit._finding).

NOTE on hit counts: ISE's per-rule counter is cumulative *since the last
reset* (node restart / manual clear), not all-time. The report says so; "0
hits" means "not since the counter was last cleared", a candidate to review,
not proof a rule never matched.
"""

from __future__ import annotations

import re
from typing import Any

_BUILTIN_PROFILES = {"PermitAccess", "DenyAccess", "Cisco_WebAuth", "Cisco_Temporal_Onboard", "NSP_Onboard"}
_TEST_NAME = re.compile(r"(?i)(?:^|[\s_\-])(test|temp|tmp|demo|poc|scratch|trial|delete|do[\s_-]?not[\s_-]?use|wip|sandbox)(?:$|[\s_\-])")
_TOP_N = 10


def _finding(severity: str, msg: str, rec_key: str) -> dict:
    return {"severity": severity, "category": "Policy analysis", "msg": msg, "ref": "policy_analysis", "rec_key": rec_key}


# ---------------------------------------------------------------------------
# Condition signature — canonical string so identical logic compares equal
# ---------------------------------------------------------------------------


def condition_signature(cond: Any) -> str:
    if not cond:
        return "ANY"  # default rule / empty condition matches everything
    if not isinstance(cond, dict):
        return str(cond)
    ctype = cond.get("conditionType", "")
    neg = "!" if cond.get("isNegate") else ""
    if ctype in ("ConditionAndBlock", "ConditionOrBlock"):
        op = "AND" if "And" in ctype else "OR"
        kids = sorted(condition_signature(c) for c in cond.get("children", []) or [])
        return f"{neg}{op}({','.join(kids)})"
    if ctype == "ConditionReference":
        return f"{neg}ref:{cond.get('name') or cond.get('id')}"
    if ctype == "ConditionAttributes":
        val = cond.get("attributeValue")
        if val is None:
            val = cond.get("dictionaryValue")
        return f"{neg}{cond.get('dictionaryName')}.{cond.get('attributeName')}{cond.get('operator')}={val}"
    return f"{neg}{ctype}:{cond.get('name') or cond.get('id') or ''}"


def _profile_signature(p: dict) -> str | None:
    """Signature over the *effects* of an authz profile. Returns None when the
    profile sets nothing meaningful (e.g. SGT-only profiles), so we don't flag
    a pile of empty profiles as duplicates."""
    vlan = p.get("vlan") or {}
    vlan_id = vlan.get("nameID") if isinstance(vlan, dict) else vlan
    dacl = p.get("daclName")
    redirect = (p.get("webRedirection") or {}).get("WebRedirectionType") if isinstance(p.get("webRedirection"), dict) else None
    voice = p.get("voiceDomainPermission")
    parts = [x for x in (vlan_id, dacl, redirect) if x]
    if not parts:
        return None
    return f"vlan={vlan_id};dacl={dacl};redirect={redirect};voice={voice}"


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def _iter_sets(data: dict):
    for ps in data.get("policy_sets_detail", []) or []:
        yield "Network access", ps
    for ps in data.get("device_admin_sets_detail", []) or []:
        yield "Device admin", ps


def analyze_policies(data: dict) -> dict:
    known_profiles = {p.get("name") for p in data.get("authz_profiles", []) or []} | _BUILTIN_PROFILES
    known_sgts = {s.get("name") for s in data.get("sgts", []) or []} | {None, "", "-"}

    sets_out: list[dict] = []
    top_rules: list[dict] = []
    stale_zero_hit: list[dict] = []
    test_rules: list[dict] = []
    shadowed: list[dict] = []
    broken_refs: list[dict] = []
    missing_default_deny: list[str] = []
    empty_tacacs: list[dict] = []
    inactive_sets: list[str] = []

    tot_rules = tot_enabled = tot_disabled = 0

    for kind, ps in _iter_sets(data):
        set_name = (ps.get("policy_set") or {}).get("name", "?")
        set_state = (ps.get("policy_set") or {}).get("state", "enabled")
        authz = ps.get("authorization", []) or []
        # order by rank when present
        authz = sorted(authz, key=lambda r: (r.get("rule") or {}).get("rank", 0))

        seen_sigs: dict[str, str] = {}
        enabled = disabled = 0
        set_hits = 0
        last_is_deny = False
        non_default_rules = 0

        for r in authz:
            rule = r.get("rule") or {}
            name = rule.get("name", "?")
            state = (rule.get("state") or "enabled").lower()
            hits = rule.get("hitCounts") or 0
            is_default = bool(rule.get("default"))
            profiles = r.get("profile") or []
            if isinstance(profiles, str):
                profiles = [profiles]
            sg = r.get("securityGroup")

            tot_rules += 1
            set_hits += hits
            if state == "enabled":
                enabled += 1
                tot_enabled += 1
            else:
                disabled += 1
                tot_disabled += 1

            top_rules.append({"set": set_name, "kind": kind, "rule": name, "hits": hits, "state": state})

            if is_default:
                last_is_deny = "DenyAccess" in profiles or (kind == "Device admin" and (r.get("profile") or "").__contains__("Deny"))
            else:
                non_default_rules += 1

            # test/temp rule live in prod
            if state == "enabled" and not is_default and _TEST_NAME.search(name):
                test_rules.append({"set": set_name, "kind": kind, "rule": name, "hits": hits,
                                   "profile": ", ".join(profiles) or (r.get("profile") if kind == "Device admin" else "-")})

            # stale: enabled, non-default, zero hits
            if state == "enabled" and not is_default and hits == 0:
                stale_zero_hit.append({"set": set_name, "kind": kind, "rule": name,
                                       "profile": ", ".join(profiles) or "-"})

            # shadow / duplicate within set (enabled, non-default)
            if state == "enabled" and not is_default:
                sig = condition_signature(rule.get("condition"))
                if sig in seen_sigs:
                    shadowed.append({"set": set_name, "kind": kind, "rule": name,
                                     "shadowed_by": seen_sigs[sig], "hits": hits})
                else:
                    seen_sigs[sig] = name

            # broken references (network access only — reliable element lists)
            if kind == "Network access":
                for prof in profiles:
                    if prof and prof not in known_profiles:
                        broken_refs.append({"set": set_name, "rule": name, "missing": prof, "kind": "authz profile"})
                if sg and sg not in known_sgts:
                    broken_refs.append({"set": set_name, "rule": name, "missing": sg, "kind": "security group"})

            # empty TACACS authz rule (no shell profile AND no command set)
            if kind == "Device admin" and not is_default:
                shell = r.get("profile")
                cmds = r.get("commands") or []
                if not shell and not cmds:
                    empty_tacacs.append({"set": set_name, "rule": name})

        if set_state != "disabled" and non_default_rules and set_hits == 0:
            inactive_sets.append(set_name)
        if set_state != "disabled" and not last_is_deny and authz:
            missing_default_deny.append(set_name)

        sets_out.append({
            "name": set_name, "kind": kind, "state": set_state,
            "authz_total": len(authz), "enabled": enabled, "disabled": disabled,
            "hits": set_hits,
            "mostly_disabled": len(authz) >= 4 and disabled > enabled,
            "has_default_deny": last_is_deny,
        })

    # A rule in an already-flagged inactive set is covered by the set-level
    # finding — don't double-count it as an individual stale rule.
    inactive_set_names = set(inactive_sets)
    stale_zero_hit = [s for s in stale_zero_hit if s["set"] not in inactive_set_names]

    # duplicate authz profiles (by effect signature)
    sig_to_names: dict[str, list[str]] = {}
    for p in data.get("authz_profiles", []) or []:
        sig = _profile_signature(p)
        if sig:
            sig_to_names.setdefault(sig, []).append(p.get("name"))
    duplicate_profiles = [{"signature": s, "names": sorted(n)} for s, n in sig_to_names.items() if len(n) > 1]

    top_rules.sort(key=lambda r: r["hits"], reverse=True)

    return {
        "stats": {
            "sets": len(sets_out), "rules": tot_rules,
            "enabled": tot_enabled, "disabled": tot_disabled,
        },
        "sets": sets_out,
        "top_rules": top_rules[:_TOP_N],
        "stale_zero_hit": stale_zero_hit,
        "test_rules": test_rules,
        "shadowed": shadowed,
        "duplicate_profiles": duplicate_profiles,
        "broken_refs": broken_refs,
        "missing_default_deny": missing_default_deny,
        "empty_tacacs": empty_tacacs,
        "inactive_sets": inactive_sets,
    }


def policy_findings(a: dict) -> list[dict]:
    f: list[dict] = []

    for t in a.get("test_rules", []):
        sev = "high" if t.get("hits", 0) > 0 else "med"
        hit_note = f" and has matched {t['hits']:,} times" if t.get("hits", 0) > 0 else " (no recorded hits)"
        f.append(_finding(sev,
            f"Rule '{t['rule']}' in set '{t['set']}' looks like a test/temporary rule but is ENABLED in production{hit_note} → {t['profile']}.",
            "REC-POLICY-007"))

    if a.get("shadowed"):
        s = a["shadowed"][0]
        more = f" (+{len(a['shadowed'])-1} more)" if len(a["shadowed"]) > 1 else ""
        f.append(_finding("med",
            f"{len(a['shadowed'])} enabled authorization rule(s) are unreachable — same condition as an earlier rule. e.g. '{s['rule']}' shadowed by '{s['shadowed_by']}' in '{s['set']}'{more}.",
            "REC-POLICY-004"))

    if a.get("broken_refs"):
        b = a["broken_refs"][0]
        more = f" (+{len(a['broken_refs'])-1} more)" if len(a["broken_refs"]) > 1 else ""
        f.append(_finding("med",
            f"{len(a['broken_refs'])} policy rule(s) reference an object that no longer exists. e.g. rule '{b['rule']}' → missing {b['kind']} '{b['missing']}'{more}.",
            "REC-POLICY-006"))

    for s in a.get("missing_default_deny", []):
        f.append(_finding("med",
            f"Policy set '{s}' does not end in an explicit DenyAccess default rule.",
            "REC-POLICY-008"))

    if a.get("duplicate_profiles"):
        d = a["duplicate_profiles"][0]
        f.append(_finding("low",
            f"{len(a['duplicate_profiles'])} group(s) of authorization profiles are functionally identical. e.g. {', '.join(d['names'])} push the same result.",
            "REC-POLICY-005"))

    if a.get("stale_zero_hit"):
        n = len(a["stale_zero_hit"])
        f.append(_finding("low",
            f"{n} enabled authorization rule(s) have 0 hits since the counter last reset — candidates for cleanup (verify against a full hit-count window first).",
            "REC-POLICY-003"))

    for s in a.get("inactive_sets", []):
        f.append(_finding("info",
            f"Policy set '{s}' shows no recorded activity (all rules at 0 hits) — confirm it is in use or retire it.",
            "REC-POLICY-003"))

    if a.get("empty_tacacs"):
        n = len(a["empty_tacacs"])
        f.append(_finding("low",
            f"{n} TACACS+ authorization rule(s) have neither a shell profile nor a command set — they grant nothing and may be misconfigured.",
            "REC-TACACS-002"))

    return f
