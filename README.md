# Cisco ISE 3.4 Automation Lab

Idempotent, end-to-end deployment of Cisco Identity Services Engine 3.4 + a
Catalyst 9800-CL Wireless LAN Controller, built and validated against a
Cisco dCloud sandbox.

Covers the most common ISE use cases as code:

- Network Device registration (NADs, NDGs)
- Active Directory integration (`dcloud.cisco.com` join + group import)
- Wireless 802.1X policy set with AD-backed authentication
- Authorization profiles that push **VLAN** and **dACL** to the NAD per session
- TACACS+ for device admin (AD users SSH into network gear via ISE)
- MAB for IoT endpoints (MAC-bypass with internal endpoint groups)
- ISE config snapshot / restore with secret redaction
- End-to-end RADIUS smoke tests (positive + negative for both AD and MAB)

## Stack

- **Ansible** — idempotent orchestration via direct ERS / OpenAPI calls
  (the `cisco.ise` collection has schema drift with ISE 3.4, so we use
  `ansible.builtin.uri` for reliability)
- **Python (uv)** — typed ERS client (`httpx` + `pydantic-settings`) for
  bulk ops, health checks, backup/restore
- **`cisco.ios`** for the WLC over `network_cli`

## Project layout

```
ansible/
├── ansible.cfg
├── inventory/
│   ├── hosts.yml                  # ISE PAN, vWLC, AD, Ubuntu test host
│   └── group_vars/
├── playbooks/
│   ├── ise_bootstrap.yml          # NDGs + identity groups
│   ├── ise_network_devices.yml    # Register NADs (with 3.4 leaf-NDG fix)
│   ├── ise_ad_join.yml            # AD join point + groups
│   ├── ise_policy_wireless_dot1x.yml
│   ├── ise_authz_profiles.yml     # dACL + VLAN-push profiles
│   ├── ise_tacacs_admin.yml       # Device Admin policy + TACACS profiles
│   ├── ise_mab_iot.yml            # IoT endpoint groups + MAB policy set
│   ├── wlc_discover.yml           # Read-only state dump
│   ├── wlc_aaa.yml                # RADIUS + AAA method lists on WLC
│   ├── wlc_wlan_dot1x.yml         # WPA2-Enterprise SSID
│   ├── wlc_tacacs.yml             # TACACS+ client on WLC
│   └── radius_smoke_test.yml      # 4-case end-to-end validation
└── vault/secrets.yml              # ansible-vault encrypted (template in secrets.example.yml)

python/
├── pyproject.toml
├── ise_api/                       # ERS / OpenAPI client
│   ├── client.py                  # httpx + retry + pagination
│   ├── nads.py
│   ├── policy.py
│   └── endpoints.py
└── scripts/
    ├── health_check.py            # quick reachability + NAD list
    ├── bulk_import_nads.py        # CSV -> NADs
    ├── export_config_backup.py    # snapshot with secret redaction
    └── restore_config.py          # POST/PUT replay

switch_configs/templates/          # Jinja2 IOS-XE for IBNS 2.0 wired dot1x
docs/                              # VM install + post-install runbook
backups/                           # local snapshots (gitignored)
```

## Quick start

```bash
# 1. Python env (uv)
cd python && uv sync && cd ..

# 2. Install ansible-core + cisco.ise SDK + paramiko (one tool env via uv)
uv tool install ansible-core --with ciscoisesdk --with paramiko
ansible-galaxy collection install -r ansible/requirements.yml

# 3. Configure connection details
cp .env.example .env
cp ansible/vault/secrets.example.yml ansible/vault/secrets.yml
# edit both with your real ISE / AD / RADIUS values
ansible-vault encrypt ansible/vault/secrets.yml

# 4. Sanity check
make health

# 5. Build it
make bootstrap          # NDGs + identity group
make add-nads           # register WLC / switches / test host as NADs
# then run individual playbooks in order from playbooks/

# 6. Validate
make radius-test        # 4 smoke tests (AD pos/neg, MAB pos/neg)

# 7. Snapshot config
make backup             # writes backups/<UTC>/, secrets redacted
make backup-commit      # snapshot + git commit if anything changed
```

## What we hit and fixed (so you don't)

ISE 3.4 + IOS-XE 17.09 have a handful of paper cuts in the field:

| Behavior | Workaround in this repo |
|---|---|
| ERS `joinDomainWithAllNodes` returns empty HTTP 500 | One-time AD join via GUI; everything else automated |
| ERS POST on `/networkdevice` silently drops leaf NDGs from `NetworkDeviceGroupList` | Follow-up `PUT` after POST in `ise_network_devices.yml` |
| TACACS profile name validation rejects hyphens | Use `_` and spaces only (e.g. `WLC_Admin_Priv15`) |
| Device Admin policy AuthZ rules need both `profile` and `commands` | Create `PermitAllCommands` command set, attach it |
| Device Admin service is a separate persona — port 49 closed until enabled | Enable in **Administration → System → Deployment → node → Personas** (UI only) |
| `ip name-server` removal aborts unless you confirm restart | Be explicit: `Proceed? [yes,no] yes` (script handles it) |
| dCloud DNS resolves `dcloud.cisco.com` to a public Cisco web property, not the lab AD | Re-point ISE DNS to the AD DC (`198.18.133.1`) before AD join |
| IOS-XE 17.09 silently drops `address ipv4` in `tacacs server` block when stale auto-named servers exist | Pre-delete `TACACS_SERVER_AUTH_1/_ACCT_1/_ATHR_1` (in `wlc_tacacs.yml`) |
| macOS Python 3.13+ + ansible-core hits fork() deadlock | `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` exported from Makefile |
| Ansible 2.21 dropped `community.general.yaml` callback | `stdout_callback = default, result_format = yaml` in `ansible.cfg` |

## Smoke test output

```
TASK [Summary]
ok: [ubuntu-server] => {
    "msg": [
        "AD positive (valid pw)        -> PASS Access-Accept",
        "AD negative (wrong pw)        -> PASS Access-Reject",
        "MAB positive (known IoT MAC)  -> PASS Access-Accept",
        "MAB negative (unknown MAC)    -> PASS Access-Reject"
    ]
}
```

## Security notes

- Real credentials live in `.env` (gitignored) for the Python client and
  `ansible/vault/secrets.yml` (gitignored AND ansible-vault encrypted) for
  playbooks. Template files (`*.example.yml`, `.env.example`) are committed.
- The backup script redacts known plaintext secret fields before writing —
  see `python/scripts/export_config_backup.py:SECRET_FIELD_NAMES`. If you
  extend the snapshot to new resource types, audit for new secret fields.
- `backups/*/` is gitignored by default. Treat snapshots as local artifacts
  unless your repo is private and you've confirmed redaction coverage.

## License

MIT (see `LICENSE`).
