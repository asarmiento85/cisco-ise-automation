"""Tests for the static policy analysis (ise_api.policy_analysis)."""

from __future__ import annotations

from ise_api.policy_analysis import analyze_policies, condition_signature, policy_findings


def _authz(name, *, state="enabled", hits=0, default=False, profile=None, sg=None, condition=None):
    return {
        "rule": {"name": name, "state": state, "hitCounts": hits, "default": default, "rank": 0, "condition": condition},
        "profile": profile if profile is not None else [],
        "securityGroup": sg,
    }


def _net_set(name, rules, state="enabled"):
    return {"policy_set": {"name": name, "state": state}, "authentication": [], "authorization": rules, "exception": []}


def test_condition_signature_equal_for_same_logic():
    c1 = {"conditionType": "ConditionAttributes", "dictionaryName": "DEVICE", "attributeName": "Device Type",
          "operator": "equals", "attributeValue": "Switch"}
    c2 = dict(c1)
    assert condition_signature(c1) == condition_signature(c2)
    assert condition_signature(None) == "ANY"


def test_condition_signature_child_order_independent():
    a = {"conditionType": "ConditionAttributes", "dictionaryName": "D", "attributeName": "a", "operator": "eq", "attributeValue": "1"}
    b = {"conditionType": "ConditionAttributes", "dictionaryName": "D", "attributeName": "b", "operator": "eq", "attributeValue": "2"}
    s1 = condition_signature({"conditionType": "ConditionAndBlock", "children": [a, b]})
    s2 = condition_signature({"conditionType": "ConditionAndBlock", "children": [b, a]})
    assert s1 == s2


def test_test_rule_with_hits_is_high():
    cond = {"conditionType": "ConditionAttributes", "dictionaryName": "D", "attributeName": "x", "operator": "eq", "attributeValue": "1"}
    data = {"policy_sets_detail": [_net_set("Wireless", [
        _authz("Test Allow All", hits=103781, profile=["PermitAccess"], sg="ISE_CORP", condition=cond),
        _authz("Default", default=True, profile=["DenyAccess"]),
    ])], "authz_profiles": [], "sgts": [{"name": "ISE_CORP"}]}
    a = analyze_policies(data)
    assert a["test_rules"] and a["test_rules"][0]["hits"] == 103781
    findings = policy_findings(a)
    test_f = [f for f in findings if f["rec_key"] == "REC-POLICY-007"]
    assert test_f and test_f[0]["severity"] == "high"


def test_shadowed_rule_detected():
    cond = {"conditionType": "ConditionReference", "name": "Guest_Flow"}
    data = {"policy_sets_detail": [_net_set("S", [
        _authz("First", hits=5, profile=["PermitAccess"], condition=cond),
        _authz("Second", hits=0, profile=["PermitAccess"], condition=dict(cond)),
        _authz("Default", default=True, profile=["DenyAccess"]),
    ])], "authz_profiles": [], "sgts": []}
    a = analyze_policies(data)
    assert any(s["rule"] == "Second" for s in a["shadowed"])
    assert any(f["rec_key"] == "REC-POLICY-004" for f in policy_findings(a))


def test_broken_reference_detected():
    data = {"policy_sets_detail": [_net_set("S", [
        _authz("R", profile=["Ghost_Profile"], sg="Ghost_SGT", hits=1,
               condition={"conditionType": "ConditionAttributes", "dictionaryName": "D", "attributeName": "x", "operator": "eq", "attributeValue": "1"}),
        _authz("Default", default=True, profile=["DenyAccess"]),
    ])], "authz_profiles": [{"name": "Real_Profile"}], "sgts": [{"name": "Real_SGT"}]}
    a = analyze_policies(data)
    missing = {b["missing"] for b in a["broken_refs"]}
    assert "Ghost_Profile" in missing and "Ghost_SGT" in missing
    assert any(f["rec_key"] == "REC-POLICY-006" for f in policy_findings(a))


def test_missing_default_deny_flagged():
    data = {"policy_sets_detail": [_net_set("S", [
        _authz("Open", default=True, profile=["PermitAccess"]),  # default permits → no deny
    ])], "authz_profiles": [], "sgts": []}
    a = analyze_policies(data)
    assert "S" in a["missing_default_deny"]
    assert any(f["rec_key"] == "REC-POLICY-008" for f in policy_findings(a))


def test_inactive_set_and_stale_no_double_count():
    # whole set is inactive (all 0 hits) → set-level finding, not per-rule stale
    data = {"policy_sets_detail": [_net_set("Dead", [
        _authz("A", hits=0, profile=["PermitAccess"], condition={"conditionType": "ConditionReference", "name": "x"}),
        _authz("B", hits=0, profile=["PermitAccess"], condition={"conditionType": "ConditionReference", "name": "y"}),
        _authz("Default", default=True, profile=["DenyAccess"]),
    ])], "authz_profiles": [], "sgts": []}
    a = analyze_policies(data)
    assert "Dead" in a["inactive_sets"]
    assert not any(s["set"] == "Dead" for s in a["stale_zero_hit"])


def test_duplicate_profiles_only_when_meaningful():
    data = {"policy_sets_detail": [], "authz_profiles": [
        {"name": "A", "daclName": "PERMIT_ALL", "voiceDomainPermission": True},
        {"name": "B", "daclName": "PERMIT_ALL", "voiceDomainPermission": True},
        {"name": "Empty1"},  # no effect → must not be flagged
        {"name": "Empty2"},
    ], "sgts": []}
    a = analyze_policies(data)
    names = [tuple(d["names"]) for d in a["duplicate_profiles"]]
    assert ("A", "B") in names
    assert not any("Empty1" in d["names"] for d in a["duplicate_profiles"])


def test_empty_tacacs_rule_flagged():
    da = {"policy_set": {"name": "DevAdmin", "state": "enabled"},
          "authentication": [], "authorization": [
              {"rule": {"name": "Nothing", "state": "enabled", "hitCounts": 0, "default": False}, "profile": None, "commands": []},
              {"rule": {"name": "Default", "state": "enabled", "hitCounts": 0, "default": True}, "profile": "Deny All Shell Profile", "commands": ["DenyAllCommands"]},
          ]}
    data = {"device_admin_sets_detail": [da], "authz_profiles": [], "sgts": []}
    a = analyze_policies(data)
    assert any(e["rule"] == "Nothing" for e in a["empty_tacacs"])
    assert any(f["rec_key"] == "REC-TACACS-002" for f in policy_findings(a))
