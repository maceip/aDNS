# Durable authority candidate

`tools/prepare_aci_durable_candidate.py` prepares a distinct, explicit **new
genesis** from reviewed public member inputs and a hash-pinned baseline. It
does not generate keys, read runtime credentials, contact Azure or start CCF.
An existing authority is not recovered by this operation.

The output includes public CCF, storage and logging-workspace ARM templates,
public bootstrap files, a summary and `ccf.parameters.TEMPLATE.json`. Supply
runtime values in a separate mode-0600 parameter file; never commit that file.

| Parameter | ARM type | Value supplied at deployment |
| --- | --- | --- |
| `transferKeyB64` | `secureString` | Canonical base64 TSIG key |
| `transferKeyJson` | `secureString` | Matching primary TSIG JSON |
| `durableStorageAccountKey` | `secureString` | Dedicated Azure Files account key |
| `logAnalyticsWorkspaceId` | `string` | Workspace `customerId` UUID, not resource ID |
| `logAnalyticsWorkspaceKey` | `secureString` | Workspace shared ingestion key |

The logging workspace template declares `adns-authority-logs` in the candidate
region, `PerGB2018`, 30-day retention, public ingestion/query and local
authentication. The container group includes Log Analytics configuration from
creation, with no workspace key in the public template, container environment
or CCE policy. [Azure's creation-time integration](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-log-analytics)
requires those workspace access settings. After deployment, verify both actual
native startup output in `ContainerInstanceLog_CL` and events in
`ContainerEvent_CL`; configuration alone is not proof of ingestion. The
workspace's effective retention must also be checked. OTLP tracing remains a
separate optional application channel.

The ledger and snapshots use `/durable/ledger` and `/durable/snapshots` on a
dedicated Azure Files share. PID, supervisor lock and frozen bootstrap files
remain local under `/state`. `restartPolicy: Never` is intentional: this is a
one-shot `Start`, not automatic restart availability. A later startup needs
live-peer `Join` or member-authorized `Recover` with the complete retained
ledger/snapshots and previous service certificate. Only one group may write
each share; this configuration has no distributed writer fence. A share alone
is not an independent backup or a tested recovery procedure.

Replay preparation using the retained public operator inputs:

```sh
python3 tools/prepare_aci_durable_candidate.py \
  --baseline-template docs/evidence/startup-repair-20260919/deployment/template.json \
  --baseline-sha256 d1a54c28b6d72c2890b697d89a0acd0c457fea4005b6a35c47e4a9c73df992c6 \
  --member-certificate docs/evidence/azure-native-v5-ready-20260913/bootstrap/member0_cert.pem \
  --member-encryption-public-key docs/evidence/azure-native-v5-ready-20260913/bootstrap/member0_enc_pubk.pem \
  --date 20260921 --output /absolute/new-candidate-directory
```

Generate CCE with `az confcom acipolicygen --template-file ... --tar ...
--platform linux/amd64 --enable-stdio --approve-wildcards`, retaining default infrastructure
fragments for Azure Files. Confcom archive input uses matching tags; retain
the verified immutable digests in the deployment template. Call
`finalize_policy(candidate_template, confcom_template)` to narrow the generated
TSIG wildcard and apply the reviewed
platform environment constraints and canonical TSIG rule, then run:

```sh
python3 tools/check_aci_template.py /absolute/candidate/ccf.template.json \
  --primary-archive /absolute/primary.tar \
  --secondary-archive /absolute/secondary.tar \
  --tar-map /absolute/candidate/ccf-tars.json \
  --output /absolute/candidate/preflight.json
PYTHONPATH=tools/tests python3 -m unittest \
  test_aci_preflight.ArchivePreflightTests test_aci_durable_candidate -v
```

Preflight verifies distinct archives and their manifest/config/layer hashes,
policy commands and mount restrictions, manifest-bound public bootstrap,
secure parameter references, creation-time logging and the Start contract.
It does not independently recompute dm-verity roots or exercise the SMB mount.

The retained repaired image carries the previously deployed native application
and packaged constitution plus the supervisor PID guard. It does not imply
that current-source CVM/SVCB features are deployed. Frontend/consumer wiring,
governance, DNSSEC receipts, native log readback and backup/recovery acceptance
are deployment work; passing these offline checks does not claim restoration.
