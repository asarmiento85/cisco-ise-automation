"""Offline tests for the local audit web UI (scripts/serve.py).

Drives the real Flask app with the ISE-facing pieces monkeypatched, so the
whole form → run (background job) → progress → report → download flow is
verified without a live PAN.
"""

from __future__ import annotations

import time

import pytest

import scripts.serve as serve


@pytest.fixture
def client(monkeypatch):
    # Minimal-but-realistic dataset: enough for analyze/summarize/render.
    fake_data = {
        "meta": {"pan": "https://ise.test:443", "user": "audit-readonly", "timestamp": "2026-01-01T00:00:00+00:00"},
        "nodes": [{"hostname": "ise-pan", "personas": ["Administration"], "roles": ["PRIMARY"], "nodeStatus": "Connected"}],
        "pan_hostname": "ise-pan",
        "allowed_protocols": [{"name": "Default Network Access", "allowEapTls": True, "allowChap": True}],
        "ers_nodes": [], "system_certs": [], "trusted_certs": [], "external_radius": [],
        "repositories": [{"name": "sftp-backup", "protocol": "SFTP", "serverName": "10.0.0.5", "path": "/"}],
        "logging_targets": [], "policy_sets": [], "policy_sets_detail": [], "sponsor_groups": [],
        "security_settings": None, "admin_password_policy": None, "admin_session_settings": None,
        "fips_status": None, "profiler_feed": None, "pxgrid_settings": None,
        "endpoint_count": 10, "unknown_endpoint_count": 1, "radius_sequences": [],
        "admin_users": [], "internal_users": [], "nads": [], "ndgs": [],
        "user_identity_groups": [], "endpoint_identity_groups": [], "identity_sequences": [],
        "ad_join_points": [], "authz_profiles": [], "authz_profiles_summary": [], "dacls": [],
        "device_admin_sets": [], "device_admin_sets_detail": [], "tacacs_command_sets": [],
        "tacacs_profiles": [], "profiler_policies": [], "sgts": [], "sgacls": [],
        "egress_matrix_cells": [], "guest_types": [], "portals": [],
        "backup_schedule_config": {}, "patches": [], "license_smart": {},
        "nac_conditions": [], "posture_settings": None, "mnt_retention": None,
        "coverage": {"deployment.nodes": {"ok": True, "count": 1}},
    }

    def fake_collect(c, progress_cb=None):
        # Simulate a couple of progress callbacks like the real collector.
        if progress_cb:
            progress_cb("deployment.nodes", 1)
            progress_cb("nads.list", 2)
        return fake_data

    monkeypatch.setattr(serve, "_preflight", lambda settings: (True, ""))
    monkeypatch.setattr(serve, "collect", fake_collect)

    class _FakeClient:
        def __init__(self, settings=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(serve, "ISEClient", _FakeClient)
    serve._LAST.clear()
    with serve._JOB_LOCK:
        serve._JOB.clear()
        serve._JOB["state"] = "idle"
    serve.app.config["TESTING"] = True
    with serve.app.test_client() as c:
        yield c


def _start_run(client, **overrides):
    data = {"host": "ise.test", "port": "443", "username": "u", "password": "p"}
    data.update(overrides)
    return client.post("/run", data=data)


def _wait_done(client, timeout=10.0):
    """Poll /status until the background job finishes."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get("/status").get_json()
        if s["state"] in ("done", "error"):
            return s
        time.sleep(0.05)
    raise AssertionError("job did not finish in time")


def test_form_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    for field in ('name="host"', 'name="username"', 'name="password"', "Run Audit"):
        assert field in body


def test_run_returns_progress_page(client):
    r = _start_run(client)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Audit in progress" in body
    assert "/status" in body          # polling wired
    _wait_done(client)


def test_status_progresses_to_done(client):
    _start_run(client)
    s = _wait_done(client)
    assert s["state"] == "done"
    assert s["done"] >= 2             # fake progress callbacks counted
    assert s["log"]                   # human-readable step log populated


def test_report_after_done_is_interactive(client):
    _start_run(client)
    _wait_done(client)
    r = client.get("/report")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "app-toolbar" in body            # interactive shell injected
    assert "Executive summary" in body      # report content present
    assert "/download/json" in body         # download buttons wired


def test_report_before_any_run_redirects(client):
    r = client.get("/report")
    assert r.status_code in (301, 302)


def test_downloads_available_after_run(client):
    _start_run(client)
    _wait_done(client)
    j = client.get("/download/json")
    assert j.status_code == 200
    assert b'"findings"' in j.data
    h = client.get("/download/html")
    assert h.status_code == 200
    assert b"app-toolbar" in h.data


def test_download_before_run_redirects(client):
    r = client.get("/download/json")
    assert r.status_code in (301, 302)


def test_missing_fields_rejected(client):
    r = client.post("/run", data={"host": "", "port": "443", "username": "", "password": "p"})
    assert r.status_code == 400


def test_preflight_failure_shows_error_page(client, monkeypatch):
    monkeypatch.setattr(serve, "_preflight", lambda settings: (False, "Authentication failed (401)."))
    r = _start_run(client, password="bad")
    body = r.get_data(as_text=True)
    assert "Audit could not complete" in body
    assert "Authentication failed" in body


def test_collect_error_surfaces_on_report_page(client, monkeypatch):
    def boom(c, progress_cb=None):
        raise RuntimeError("mid-run failure")

    monkeypatch.setattr(serve, "collect", boom)
    _start_run(client)
    s = _wait_done(client)
    assert s["state"] == "error"
    r = client.get("/report")
    assert "mid-run failure" in r.get_data(as_text=True)


def test_no_credentials_in_artifacts(client):
    _start_run(client, password="Sup3rS3cret!")
    _wait_done(client)
    assert b"Sup3rS3cret!" not in serve._LAST["json"]
    assert b"Sup3rS3cret!" not in serve._LAST["html"]
