# The TACACS+ Lockout That Taught Me Three Things About IOS-XE AAA

A short engineering story about the kind of failure that humbles you, and the diagnostic process that turns a humiliation into a useful artifact.

In the [previous post](https://blog.it-learn.io/posts/2026-05-12-cisco-ise-automation-ansible-claude-deployment/) I walked through building a Cisco ISE 3.4 deployment as code in one evening. End-to-end working: AD-integrated wireless 802.1X, MAB for IoT, TACACS+ for device admin. Smoke tests green. Repo public. Felt good.

A few sessions later I went back to tighten the screws — replace the broad "PermitAllCommands" TACACS shell with **per-command authorization**, the proper way: Helpdesk gets `show / ping / traceroute`, NetworkOps gets safe troubleshooting verbs, Admins get everything. The kind of thing audit teams ask for.

I locked myself out of the router.

Worse — I locked out **every** local user, including the break-glass `admin`. And worse-worse — I did it in the exact pattern half the lab guides on the internet recommend.

Here's the autopsy. There are three lessons; if you're deploying TACACS+ on Cisco IOS-XE you want all three.

---

## What I built (the wrong way)

The CSR-side AAA config looked exactly like every Cisco TACACS reference I've seen:

```
aaa new-model
aaa authentication login default group ISE-TACACS-GRP local
aaa authentication enable default enable
aaa authorization exec default group ISE-TACACS-GRP local if-authenticated
aaa authorization commands 1  default group ISE-TACACS-GRP local if-authenticated
aaa authorization commands 15 default group ISE-TACACS-GRP local if-authenticated
aaa accounting exec default start-stop group ISE-TACACS-GRP
aaa accounting commands 15 default start-stop group ISE-TACACS-GRP
```

Read it carefully. The chain says: **try TACACS group first; if that doesn't work, fall back to `local`; if even that fails, fall back to `if-authenticated`** (any logged-in user is permitted).

This is The Recommended Pattern™. It's in dozens of Cisco docs. It SHOULD be safe.

Then the ISE side:

- TACACS shell profiles: `WLC_Admin_Priv15` and `WLC_Helpdesk_Priv1`
- Command sets: `ReadOnlyCommands` (just show/ping/exit) and `PermitAllCommands`
- Device Admin policy set matching Device Type = Switch
- AuthN against the AD `dcloud` join point
- AuthZ rules: AD Domain Admins → Admin profile + PermitAll, AD Domain Users → Helpdesk profile + ReadOnly

I push the config. I open a fresh SSH as the local `admin` user to verify everything still works.

Login succeeds. Prompt appears. I type `show version`.

```
csr8kv#show version
Command authorization failed.

csr8kv#configure terminal
Command authorization failed.

csr8kv#write memory
Command authorization failed.

csr8kv#
```

Every command. **Every.** Even `show`. Even `write memory`. The router is a brick I can SSH into but can't do anything with.

I try the AD `administrator` user. Logs in via TACACS, gets the Helpdesk shell profile, lands at priv 1 with ReadOnly commands. They CAN run `show` (because the ReadOnly command set permits it) but obviously can't `configure terminal` to fix the broken policy.

I am locked out. Both the local break-glass user and every AD admin.

---

## Why it broke (lesson #1)

The chain `group ISE-TACACS-GRP local if-authenticated` looks like a graceful three-step fallback, but on IOS-XE it isn't.

When the TACACS server **rejects** the request (returns `STATUS_FAIL`), IOS-XE considers the authorization decision **made and final**. It does not fall through to `local`, and it does not fall through to `if-authenticated`. Those fallbacks only fire when the TACACS server **times out** (network unreachable, daemon down, packet drop).

So when local user `admin` typed `show version`:

1. CSR asks ISE: "is `admin` authorized to run `show version`?"
2. ISE looks up `admin` in the configured identity source: AD `dcloud` join point.
3. AD says "no such user".
4. ISE returns `STATUS_FAIL` to the CSR.
5. CSR considers it answered. Refuses the command. Done.

`local` never gets consulted. `if-authenticated` never fires.

The pattern is safe if ISE is unreachable. It is **unsafe if ISE is reachable but doesn't know your local user** — which is exactly when you most need your break-glass account to work.

This is documented somewhere deep in Cisco's AAA reference. It's not surfaced in any of the configuration tutorials I've ever read. The smoke test for it requires either reading the source or doing what I did.

---

## How I recovered (lesson #2)

The CSR is locked. Every command refused. I'm SSH'd in but functionally locked out.

Three options:

**A. Reload the router.** Power-cycle, reboot, lose unsaved config. If startup-config is clean, the lockout disappears with the reload. If the broken config is already in startup-config, the lockout survives the reload — and now you have a router that's locked out forever, restorable only via console password recovery (rommon).

**B. Wait for TACACS to fail.** If ISE goes down or the TACACS daemon crashes, the chain falls through to `local`. But you can't make ISE go down from outside the box.

**C. Use the console line.** Console line on IOS-XE typically isn't subject to `aaa authorization commands` unless you explicitly add `authorization commands` under `line con 0`. So console access can fix what SSH can't.

Here's the saving grace I didn't realize until the second attempt: when I pushed the breaking AAA config and tried to `write memory`, the **`write memory` itself was already locked out**. So the breaking changes lived in running-config only. Startup-config was still the original clean state. A reload was a clean recovery.

That's option A by accident. It worked. CSR came back in 60 seconds with the previous config.

**Practical takeaway:** if you ever push command-authz config and the `write memory` fails, **do not panic and find another path to save**. The failed `write memory` is the only thing saving you. A reload restores the clean state. Anything else (console password recovery, ROMmon) is hours of recovery for a 60-second alternative.

---

## The safer pattern (lesson #3)

After the recovery, I rebuilt the AAA chain with two structural changes:

```
aaa new-model
aaa authentication login default local group ISE-TACACS-GRP
aaa authentication enable default enable
aaa authorization exec default local group ISE-TACACS-GRP if-authenticated
aaa accounting exec default start-stop group ISE-TACACS-GRP
aaa accounting commands 15 default start-stop group ISE-TACACS-GRP
```

Two differences from the original:

1. **`local` is FIRST** in the login + exec chain. Now when a local user authenticates, the local database is checked first and succeeds — TACACS is never consulted. The break-glass account can never be locked out by an ISE policy decision.

2. **No `aaa authorization commands` at all.** Authorization is at the exec level only (which determines privilege level), not per-command. Helpdesk users get assigned priv 1 (via the TACACS shell profile), and priv 1 inherits the default command set for that level — most administrative commands are restricted naturally because they require priv 15.

What I lose: granular per-command policy. A Helpdesk user can type `configure terminal` and IOS-XE will tell them "Invalid input" because their priv level doesn't allow it — not because TACACS explicitly denied it.

What I keep: AD-driven device admin access, per-user privilege assignment via ISE shell profiles, full command accounting to ISE for audit, AND a break-glass account that always works.

For a lab, an SMB, or a typical enterprise, that's the right tradeoff. For a regulated environment that genuinely needs per-command authz on every device, you build it carefully:

- Always **test the fallback path** with `local` first, then explicitly verify on a non-production device what IOS-XE actually does on `STATUS_FAIL`. Don't trust documentation.
- Always **test break-glass with ISE unreachable** (firewall the TACACS port from the device) before considering the config production-ready.
- Always **save iteratively** — push exec authz, verify, save, then push command authz, verify, save. Don't do them in one batch.

---

## What this means for the automation

The whole reason I'm doing this work as code is so I don't repeat the same mistake twice. The repo now has a [playbook called `switch_aaa_safe.yml`](https://github.com/asarmiento85/cisco-ise-automation/blob/main/ansible/playbooks/switch_aaa_safe.yml) that implements the safe pattern. The first thing in the file is a 30-line header comment explaining the lockout, the symptom, the cause, and the recovery — so the next person (or future-me) who runs `git blame` on that file lands on the postmortem.

That's the actual product of this kind of failure: the failure plus the documentation of the failure is more valuable than the unbroken code by itself. The codebase carries the scar tissue.

A few other things I changed:

- The Device Admin policy set in ISE now matches **`Device Type = WLC OR Switch`** instead of just WLC. One policy serves both platforms; the cross-platform proof point.
- The CSR8000V (Cat8000V) is registered as a NAD with Device Type = Switch.
- Cross-platform validated: same automation pattern works on **C9800-CL 17.09 (vWLC)** and **CSR8000V 17.04 (router)**.

---

## What I learned about AI-assisted troubleshooting

This whole sequence — discover the lockout, work through hypotheses (was it the rule? the SID format? the AD scope?), try the SID swap, document the IOS-XE behavior, write the recovery pattern — happened as a fast back-and-forth between me and Claude.

The interesting thing wasn't that the AI knew the answer. It often didn't. The IOS-XE behavior on STATUS_FAIL vs TIMEOUT is buried in places that probably weren't well represented in training data. What worked was the **diagnostic loop**: I'd paste an error, the AI would propose a hypothesis, I'd test it, paste the result, repeat. Hypotheses got refined fast.

The first hypothesis ("maybe the SID format is wrong") was wrong. The second ("maybe the AD scope doesn't recurse into Domain Admins") was wrong. The third ("the rule's actually correct, the AAA chain itself doesn't fall through on REJECT") was right. The whole loop took maybe 20 minutes — significantly faster than scrolling `aaa-cf-debug` logs alone.

That's the pattern I keep seeing in network ops with AI assistance: it's not a replacement for understanding. It's a way to test more hypotheses per hour.

---

## Try it yourself

The complete safe AAA playbook lives in the repo: **https://github.com/asarmiento85/cisco-ise-automation**

If you're running TACACS+ on IOS-XE today, take 30 seconds and check your `show running-config | inc aaa authentication login`. If `local` isn't the first word after `default`, you're one ISE policy change away from the same lockout I hit. Fix is a one-line config change. Don't be me.

If you've hit the same lockout pattern — or worked around it in a different way — drop a comment. The more we document this in the open, the fewer people who learn it the hard way at 11pm.

---

*Built and broken with Cisco ISE 3.4, Catalyst 8000V on IOS-XE 17.04, C9800-CL on IOS-XE 17.09, and Claude. dCloud sandbox over AnyConnect. No production gear was harmed in the making of this post (one lab router briefly was).*
