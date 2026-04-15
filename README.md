# Cisco ISE Automation Lab

Local automation project for deploying and managing Cisco ISE + downstream switches.

## Stack

- **Ansible** — idempotent config for ISE (via `cisco.ise` collection) and switches (`cisco.ios`)
- **Python (uv)** — ERS/OpenAPI client for bulk ops and reporting
- **Terraform** *(optional, later)* — declarative ISE state via the `CiscoDevNet/ise` provider

## Quickstart

```bash
# 1. Python env (uv)
cd python && uv sync

# 2. Ansible collections
ansible-galaxy collection install -r ansible/requirements.yml

# 3. Copy env template and fill in ISE/switch details once the VM is up
cp .env.example .env

# 4. Encrypt your real secrets
ansible-vault create ansible/vault/secrets.yml
```

## Roadmap

- [ ] Phase 0 — ISE VM deploy + first boot (see `docs/01-vm-install.md`)
- [ ] Phase 1 — Bootstrap: enable ERS/OpenAPI, create API admin, install certs
- [ ] Phase 2 — Add switches as Network Devices (NADs)
- [ ] Phase 3 — Identity sources (AD/LDAP join, internal users, groups)
- [ ] Phase 4 — Policy sets (authN/authZ) for dot1x + MAB
- [ ] Phase 5 — Switch-side AAA + dot1x/MAB templates pushed via Ansible
- [ ] Phase 6 — Profiling, posture, TrustSec

## Layout

See directory tree in project root — each subdir has its own README where useful.

## Safety

- Real credentials **never** go in plain files. Use `.env` (gitignored) for local dev and `ansible-vault` for playbook secrets.
- Test playbooks against the ISE VM and a single lab switch before touching production.
