# Phase 0 — ISE VM Install Checklist

## Download

1. Grab the ISE OVA from Cisco Software Download (CCO login required).
   - Recommended: **ISE 3.3 Patch 4+** or **3.4** for the best OpenAPI coverage.
2. SHA512 verify against Cisco's published hash.

## Hypervisor (local on Mac)

Pick one:
- **VMware Fusion** (best supported — ISE officially targets ESXi/Fusion)
- **UTM** (ARM Mac — works but unsupported by Cisco; expect quirks)
- **Parallels** (works; unsupported)

### Minimum lab sizing (Eval / Small)

| Resource | Value |
|----------|-------|
| vCPU     | 4     |
| RAM      | 16 GB (32 GB recommended) |
| Disk     | 300 GB thin |
| NIC      | 1 (bridged) |

Production sizing is much larger — see Cisco ISE Hardware Guide.

## First boot

At the console:
```
setup
```
Walks through hostname, IP, DNS, NTP, admin user. **NTP is critical** — ISE breaks subtly without it.

After reboot (~30 min), browse to `https://<ise-ip>/admin/`.

## Post-install manual steps (before automation takes over)

1. **Apply eval/Smart license** — Administration → System → Licensing
2. **Enable ERS API** — Administration → System → Settings → API Settings → ERS (Read/Write) = Enabled
3. **Enable OpenAPI** — same page, toggle OpenAPI
4. **Create an ERS admin user** — Administration → System → Admin Access → Administrators → Admin Users
   - Admin Group: `ERS Admin` + `OpenAPI Admin`
   - Save this cred to `.env` as `ISE_USERNAME` / `ISE_PASSWORD`
5. **Accept self-signed cert** from your automation host (or install a proper cert later via `ise_bootstrap.yml`)

Once the above is done, the rest is automated.
