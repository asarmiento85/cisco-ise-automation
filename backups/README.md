# ISE config snapshots

Populated by `make backup`. Each snapshot is one directory named with a UTC timestamp:

```
backups/2026-05-24T14-38-56Z/
├── ers_networkdevice.json
├── ers_authorizationprofile.json
├── ers_endpointgroup.json
├── ers_tacacsprofile.json
├── policy_network_access.json
├── policy_device_admin.json
└── … (one file per resource type)
```

`backups/latest` is a symlink to the most recent snapshot for stable diffs.

## Secret redaction

The export script redacts known plaintext secret fields before writing:

- `radiusSharedSecret`, `sharedSecret`, `secondRadiusSharedSecret`
- `keyEncryptionKey`, `messageAuthenticatorCodeKey`
- `password`, `enablePassword`
- `snmpRoCommunity`, `snmpRwCommunity`

If you add new ERS resources that return other secret values, extend
`SECRET_FIELD_NAMES` in `python/scripts/export_config_backup.py`.

## Restore

```bash
# dry-run, single resource
uv run python -m scripts.restore_config --snapshot backups/latest --resource networkdevice --dry-run

# live restore, all resources
uv run python -m scripts.restore_config --snapshot backups/latest
```

Restore is conservative: POST → PUT-on-conflict, never deletes.

## Why this directory is gitignored by default

Snapshots capture lab-specific state (NAD IDs, IPs, AD join GUIDs) and the
SECRET_FIELD_NAMES list may not cover every future field ISE adds. Treating
snapshots as local artifacts is safer for shared/public repos.

To commit snapshots anyway (e.g. private compliance archive), remove the
`backups/*/` lines from `.gitignore`.
