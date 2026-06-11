"""Offline tests for the audit analyzer + recommendation builder.

No live ISE required — feeds a synthetic 'freshly-migrated, messy' dataset
through analyze() / summarize() / build_recommendations() and asserts the
migration / security / operational findings fire.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ise_api.audit import _redact, analyze, summarize
from ise_api.recommendations import build_recommendations

_NOW = datetime.now(timezone.utc)
_EXPIRED = (_NOW - timedelta(days=200)).strftime("%a %b %d %H:%M:%S UTC %Y")


@pytest.fixture
def migrated_data() -> dict:
    return {
        "meta": {"pan": "https://ise.test:443", "user": "audit-readonly", "timestamp": _NOW.isoformat()},
        "nodes": [{"hostname": "ise-pan", "personas": ["Administration"], "roles": ["PRIMARY"], "nodeStatus": "Connected"}],
        "pan_hostname": "ise-pan",
        "allowed_protocols": [
            {"name": "Default Network Access", "allowEapTls": True, "allowPeap": True, "allowMsChapV2": True,
             "allowChap": True, "allowMsChapV1": True, "allowEapMd5": True, "allowLeap": True,
             "eapFast": {"allowEapFast": True, "eapFastAllowAnonymProvisioning": True},
             "eapTls": {"allowedTlsVersions": "TLSV1_0,TLSV1_1,TLSV1_2"}},
            {"name": "Default Device Admin", "allowPapAscii": True},
        ],
        "ers_nodes": [
            {"hostName": "ise-pan", "softwareVersion": "3.3.0.430", "replicationStatus": "CONNECTED"},
            {"hostName": "ise-psn1", "softwareVersion": "3.2.0.542", "replicationStatus": "DISCONNECTED"},
        ],
        "system_certs": [
            {"friendlyName": "ise-pan.corp", "issuedBy": "CN=OldCorp-CA-2019, DC=corp", "selfSigned": False,
             "expirationDate": _EXPIRED, "usedBy": "Admin, EAP Authentication", "signatureAlgorithm": "SHA256withRSA"},
        ],
        "trusted_certs": [{"subject": "CN=NewCorp-CA-2024", "friendlyName": "NewCorp Root"}],
        "external_radius": [{"name": "old-token-server", "hostIP": "10.9.9.9"}],
        "repositories": [{"name": "ftp-backup", "protocol": "FTP", "serverName": "10.9.9.10", "path": "/"}],
        "logging_targets": [],
        "policy_sets": [{"name": "Default", "isDefault": True, "id": "ps-default"}],
        "policy_sets_detail": [],
        "sponsor_groups": [{"name": "ALL_ACCOUNTS"}, {"name": "Sample_Sponsor"}],
        "security_settings": {"allowedTLSVersions": "TLSV1_0,TLSV1_1,TLSV1_2", "allowSHA1Ciphers": True},
        "admin_password_policy": {"minLength": 6},
        "admin_session_settings": {"sessionTimeout": 120},
        "fips_status": {"isEnabled": False},
        "profiler_feed": {"isEnabled": False},
        "pxgrid_settings": {"autoApprove": True},
        "endpoint_count": 1000,
        "unknown_endpoint_count": 400,
        "radius_sequences": [{"name": "proxy-seq"}],
        "admin_users": [{"name": "admin", "enabled": True, "adminGroups": "Super Admin"}],
        "internal_users": [], "nads": [], "ndgs": [], "authz_profiles": [],
        "device_admin_sets_detail": [], "profiler_policies": [], "sgts": [], "egress_matrix_cells": [],
        "backup_schedule_config": {},
        "coverage": {"logging.remote_targets": {"ok": True, "count": 0}},
    }


def _keys(findings: list[dict]) -> set[str]:
    return {f.get("rec_key") for f in findings}


def test_migration_critical_findings_fire(migrated_data: dict) -> None:
    keys = _keys(analyze(migrated_data))
    for expected in ("REC-AUTH-001", "REC-TLS-001", "REC-NODE-001", "REC-NODE-002",
                     "REC-CERT-005", "REC-STALE-001", "REC-CLEANUP-001"):
        assert expected in keys, f"missing migration finding {expected}"


def test_security_hardening_findings_fire(migrated_data: dict) -> None:
    keys = _keys(analyze(migrated_data))
    for expected in ("REC-ADMIN-003", "REC-ADMIN-004", "REC-LOG-001"):
        assert expected in keys, f"missing security finding {expected}"


def test_operational_findings_fire(migrated_data: dict) -> None:
    keys = _keys(analyze(migrated_data))
    for expected in ("REC-PROFILER-002", "REC-PXGRID-001", "REC-ENDPOINT-001"):
        assert expected in keys, f"missing operational finding {expected}"


def test_weak_method_severity_is_high(migrated_data: dict) -> None:
    findings = analyze(migrated_data)
    weak = [f for f in findings if f["rec_key"] == "REC-AUTH-001" and "Network Access" in f["msg"]]
    assert weak and weak[0]["severity"] == "high"  # MS-CHAPv1/EAP-MD5/LEAP present


def test_every_finding_maps_to_a_recommendation(migrated_data: dict) -> None:
    findings = analyze(migrated_data)
    recs = build_recommendations(findings)
    rec_ids = {r["id"] for r in recs}
    for f in findings:
        if f.get("rec_key"):
            assert f["rec_key"] in rec_ids, f"finding {f['rec_key']} has no catalog entry"


def test_recommendations_sorted_by_priority(migrated_data: dict) -> None:
    recs = build_recommendations(analyze(migrated_data))
    ranks = {"P1": 0, "P2": 1, "P3": 2}
    seq = [ranks[r["priority"]] for r in recs]
    assert seq == sorted(seq), "recommendations not priority-ordered"


def test_summary_counts_present(migrated_data: dict) -> None:
    s = summarize(migrated_data, analyze(migrated_data))
    assert s["counts"]["endpoint_count"] == 1000
    assert s["counts"]["allowed_protocols"] == 2
    assert s["severity"]["high"] >= 4


def test_openapi_disabled_meta_finding() -> None:
    """A burst of 302s on coverage = Open API disabled → REC-API-001 fires."""
    data = {
        "coverage": {
            "deployment.nodes": {"ok": False, "status": 302},
            "certs.system": {"ok": False, "status": 302},
            "policy.network_access.sets": {"ok": False, "status": 302},
            "system.repositories": {"ok": False, "status": 302},
            "nads.list": {"ok": True, "count": 3},
        },
    }
    keys = _keys(analyze(data))
    assert "REC-API-001" in keys


def test_no_meta_finding_for_isolated_failures() -> None:
    """One or two failures (feature off, old patch) should NOT claim Open API is down."""
    data = {
        "coverage": {
            "posture.global_settings": {"ok": False, "status": 302},
            "nads.list": {"ok": True, "count": 3},
        },
    }
    assert "REC-API-001" not in _keys(analyze(data))


def test_backup_findings_gated_on_coverage() -> None:
    """Empty repositories must NOT be flagged when the endpoint never answered."""
    unread = {
        "repositories": [],
        "backup_schedule_config": {},
        "coverage": {
            "system.repositories": {"ok": False, "status": 302},
            "system.backup.config_schedule": {"ok": False, "status": 302},
        },
    }
    keys = _keys(analyze(unread))
    assert "REC-BACKUP-001" not in keys
    assert "REC-BACKUP-003" not in keys

    verified_empty = {
        "repositories": [],
        "backup_schedule_config": {},
        "coverage": {
            "system.repositories": {"ok": True, "count": 0},
            "system.backup.config_schedule": {"ok": True, "count": 0},
        },
    }
    keys = _keys(analyze(verified_empty))
    assert "REC-BACKUP-001" in keys
    assert "REC-BACKUP-003" in keys


def test_super_admin_count_handles_string_groups() -> None:
    """ERS returns adminGroups as a plain string — the sprawl counter must
    still see it (and not iterate it character by character)."""
    data = {
        "admin_users": [
            {"name": f"admin{i}", "enabled": True, "adminGroups": "Super Admin"}
            for i in range(5)
        ],
        "coverage": {},
    }
    keys = _keys(analyze(data))
    assert "REC-ADMIN-002" in keys


def test_normalize_patches_shapes() -> None:
    from scripts.audit_deep import _normalize_patches

    assert _normalize_patches([{"patchNumber": 4, "installDate": "Wed Nov 06"}]) == [
        "Patch 4 — installed Wed Nov 06"
    ]
    assert _normalize_patches({"patchDetails": [{"patchVersion": "3.3 P2"}]}) == ["Patch 3.3 P2"]
    assert _normalize_patches({"installedPatchVersion": "3.3 Patch 2"}) == ["3.3 Patch 2"]
    assert _normalize_patches(None) == []
    assert _normalize_patches("3.2 patch 6") == ["3.2 patch 6"]
    # raw repr never leaks
    assert all(not s.startswith("[{") for s in _normalize_patches([{"patchNumber": 1}]))


def test_redactor_strips_secrets() -> None:
    dirty = {"NetworkDevice": {"name": "sw1", "authenticationSettings": {"radiusSharedSecret": "S3cret!"}},
             "tacacs": {"sharedSecret": "T0ps3cret"}, "snmp": {"snmpRoCommunity": "public123"}}
    clean = _redact(dirty)
    blob = str(clean)
    assert "S3cret!" not in blob
    assert "T0ps3cret" not in blob
    assert "public123" not in blob
    assert blob.count("<REDACTED>") == 3
