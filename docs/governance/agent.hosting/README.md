# agent.hosting governance proposals

Proposal bodies (JSON action arrays for `tools/ccf_control.py propose`) that
the agentdns consortium applies for the agent-hosting shared interface
(agent-hosting ADR 0024, this repo's `docs/decisions/0001-agent-hosting-shared-interface.md`).

| File | Action | Notes |
|---|---|---|
| `create-zone.json` | `adns_create_zone agent.hosting.` | Private copy of the zone under agentdns governance. Not publicly delegated: Azure DNS remains authoritative until the owner re-delegates (agent-hosting phase 2). Signing material is generated in the enclave. |
| `grant-mail.json` | `adns_set_owner_grant agent-hosting-mail-20260916` | Subject: SHA-256 of the mail TLS key SPKI (`635e35be…`, the live TLSA 3 1 1 value). Role `mx-edge`, ports 25/465/587/993, address 20.114.5.117/32, attested TXT `_receipt.mail.agent.hosting.`, operations register/renew/deregister/anchor. |
| `grant-worker.json` | `adns_set_owner_grant agent-hosting-worker-20260916` | Subject: SHA-256 of the worker receipt key SPKI (`cad0e0b4…`, ES256). Role `worker` (no MX contribution), attested TXT `cvm1._domainkey.agent.hosting.` (DKIM) and `_receipt.worker.agent.hosting.`, operations register/renew/deregister/anchor. |

Grants alone authorize nothing: a registration still needs SNP evidence bound
to the subject key under the zone's appraisal policy. Both agent-hosting hosts
are ordinary VMs today, so these grants cannot be exercised until agent-hosting
phase 2 (confidential VMs). The `_domainkey` name is granted to the worker
because the worker holds the DKIM `cvm1` key; there is no separate `_domainkey`
principal.

Apply (member key stays with the member):

```sh
python3 tools/ccf_control.py propose --url https://agentdns.test:8000 --connect-ip NODE_IP \
  --service-cert SERVICE_CERT --member-key MEMBER_KEY --member-cert MEMBER_CERT \
  --body docs/governance/agent.hosting/create-zone.json --output out/create-zone.json
```

Each proposal's acceptance is its confirmed global-commit transaction ID; record
it in `docs/anchors.md`.

## Applied 2026-09-16

| Proposal | Transaction | Result |
|---|---|---|
| `set_constitution` (digest `cf33091a…`, 2129 lines: pinned CCF 7.0.15 defaults + `ccf/governance/actions.js` + exports) | `2.273944` | Accepted |
| `create-zone.json` | `2.273965` | Accepted; zone signed, serial 2026091601, KSK tag 59729, DS `63db4cd2…` |
| `grant-mail.json` | `2.273969` | Accepted |
| `grant-worker.json` | `2.273971` | Accepted |

Voted by the single active member `3552372e…` under a `resolve()` that accepts
every proposal — the one-member test fixture the operations guide warns about.
These commits are governance facts, not consortium approval.

## Governance v2 (open-join, reputation-weighted, agent-led)

`tools/compose_constitution.py` composes the constitution from the pinned CCF
defaults, `ccf/governance/actions.js`, `exports.js` and `resolve.js`. The
steward agent (`tools/steward.py`) reviews, records verdicts, votes, settles
reputation and sponsors joins. See `docs/decisions/0002-governance-open-join-reputation-agent-led.md`.
Live application transactions are appended below when performed.

### Applied 2026-09-16 (governance v2)

| Proposal | Transaction | Result |
|---|---|---|
| `set_constitution` v2 (`8712e257…`) then v2.1 (`5f28aa7c…`, governor notes accept text) | `2.303357`, `2.303431` | Accepted under the previous rule (one unregistered agent, bootstrap) |
| `adns_set_governor` operator key `3552372e…` → **trapdoor** | `2.303439` | Accepted |
| `set_member` + `adns_set_governor` steward agent `11c6ae7f…` (key on VM-worker, `agenthost`, `/var/lib/agentdns-steward`) | `2.303474` create, `2.303498` trapdoor override, `2.303603` ack | Active |
| `adns_set_governance_parameters {min_agent_yes:1, open_join:true}` proposed by the trapdoor **with abstention** | `2.303625` create | **Accepted by the steward's vote alone** (proposal `c2837a53…`, final votes `{11c6ae7f: true}`); verdict `approve` recorded; settled by the steward |

The steward runs every 10 minutes on VM-worker (`agentdns-steward.timer`) with a
24-hour trap-door window on high-impact proposals. The operator key is now a
trapdoor: its `true` ballot overrides, its `false` ballot vetoes, both visible.
