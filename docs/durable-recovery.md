# Durable candidate backup and member recovery

This is an explicit recovery exercise for the new Azure Files candidate. It does
not restore the failed original authority. Keep that original group untouched.
The new candidate has `restartPolicy=Never`: do not run its one-shot `Start`
configuration again against an existing ledger. Recovery creates a new CCF
service certificate; the DNS KSK must remain unchanged.

Use the same pinned Python CCF 7.0.15 environment used by `ccf_control.py`, including
`cryptography`. All local work directories must be private (`umask 077`, mode 0700).
Keep storage credentials in the existing authorized environment; never put keys,
SAS tokens, member private keys or decrypted recovery shares in commands, reports,
Git, or shell tracing. The helpers print only public evidence or step status.

## Capture the running candidate's identity

First authenticate the candidate by the existing native appraisal and TLS process.
Save its actual service certificate and independently verified DER SHA256. The
helper refuses a different certificate; it does not bootstrap trust itself.

```sh
umask 077
python3 tools/durable_recovery.py capture \
  --url "$ADNS_ORIGIN" --connect-ip "$ADNS_IP" \
  --service-cert "$ADNS_SERVICE_CERT" --service-sha256 "$ADNS_SERVICE_SHA256" \
  --zone "$ADNS_ZONE" --output "$ADNS_WORK/before-ksk-receipt.json"
```

Save the validated Start template, its digest, public node configuration and
native appraisal alongside this evidence. The receipt is independently verified
against the selected certificate, including the exact zone and DNSKEY bytes.

## Stop one writer and snapshot the complete share

The deployment owner stops only the new candidate using `az container stop`, then
waits for the group to be `Stopped` and its containers `Terminated`. Azure Files
persists independently of the container group. This procedure is unsafe for the
failed group's `emptyDir`, which must not be stopped or changed.

Obtain a current subscription-wide ACI inventory. Retain only group ID,
restartPolicy, instanceView, each volume's name/storageAccountName/shareName, and
each container's mounts/current state. Do not save account keys, secret volumes,
environment values or deployment parameters. Pass that sanitized inventory to:

```sh
python3 tools/durable_recovery.py check-stopped \
  --inventory "$ADNS_WORK/aci-mount-inventory.json" \
  --group-id "$ADNS_SOURCE_GROUP_ID" --account "$ADNS_ACCOUNT" \
  --share "$ADNS_SOURCE_SHARE" --output "$ADNS_WORK/stopped-writer.json"

az storage share snapshot --account-name "$ADNS_ACCOUNT" \
  --name "$ADNS_SOURCE_SHARE" --query snapshot --output tsv \
  > "$ADNS_WORK/share-snapshot.txt"

mkdir -m 700 "$ADNS_WORK/snapshot-download"
az storage file download-batch --account-name "$ADNS_ACCOUNT" \
  --source "$ADNS_SOURCE_SHARE" \
  --snapshot "$(cat "$ADNS_WORK/share-snapshot.txt")" \
  --destination "$ADNS_WORK/snapshot-download" --no-progress
```

The inventory check refuses another ACI mount of the source share, a live writer,
or automatic restarts. It is **not a distributed storage fence**: the deployment
owner must keep this dedicated share unavailable to other writers throughout the
exercise. No VM/process outside the ACI inventory may write it. There is no
automatic restart or rollback to `Start`.

Verify the snapshot's recursive file inventory with `az storage file list
--num-results '*' --snapshot <timestamp>` for every directory. This avoids the
default 5000-entry limit. Use listings to enumerate names, then obtain **per-file
properties from that same snapshot** (`az storage file show --share-name <share>
--path <file> --snapshot <timestamp>`, or SDK `get_file_properties`) to verify each
downloaded size. Do not trust directory-listing lengths or omit a file because a
listing reports zero bytes. In the 2026-09-21 Azure exercise the immutable snapshot
listing reported `ledger_19` as zero bytes, while its per-file properties and
download both contained 323264 bytes. Preserve such discrepancies as evidence;
require the full download to agree with per-file properties before sealing it.
Compare every filename and hash the downloaded content. Download-batch may
omit empty directories: confirm an empty snapshot directory remotely before
creating its corresponding empty local directory. Do not infer that an omitted
directory was empty. Keep the full snapshot download private.

Create a small `provenance.json` recording the source account/share/group,
snapshot timestamp, stop-observation time, inventory digest and successful full
download/inventory verification. The archive stores this record as operator
provenance; it does not claim to independently authenticate Azure state.

```sh
python3 tools/durable_recovery.py archive \
  --source "$ADNS_WORK/snapshot-download" --previous-service "$ADNS_SERVICE_CERT" \
  --before-receipt "$ADNS_WORK/before-ksk-receipt.json" --zone "$ADNS_ZONE" \
  --provenance "$ADNS_WORK/provenance.json" --output "$ADNS_WORK/backup"
python3 tools/durable_recovery.py verify-archive --backup "$ADNS_WORK/backup"
```

This copies **all** files under ledger and snapshots, including the current
unsuffixed `ledger_N` chunk. Copying only `*.committed` or using read-only ledger
directories can omit committed transactions in that current chunk. The backup
does not include local PID files or member private keys. File hashes and the
verified certificate/receipt are sealed into a manifest. CCF itself must still
validate the ledger and snapshot's cryptographic continuity during Recover.

## Recover from a separate verified copy

Create a fresh, empty share under the dedicated recovery account. Verify no group
mounts it. Never overwrite the source share or launch two groups against the same
writable ledger. The immutable backup remains outside the writable copy.

```sh
python3 tools/durable_recovery.py restore-copy --backup "$ADNS_WORK/backup" \
  --output "$ADNS_WORK/restore-upload"
az storage file upload-batch --account-name "$ADNS_ACCOUNT" \
  --destination "$ADNS_RECOVERY_SHARE" --source "$ADNS_WORK/restore-upload" \
  --validate-content --no-progress
mkdir -m 700 "$ADNS_WORK/restore-readback"
az storage file download-batch --account-name "$ADNS_ACCOUNT" \
  --source "$ADNS_RECOVERY_SHARE" --destination "$ADNS_WORK/restore-readback" --no-progress
python3 tools/durable_recovery.py verify-state --backup "$ADNS_WORK/backup" \
  --state "$ADNS_WORK/restore-readback"

python3 tools/prepare_aci_recovery.py render \
  --start-template "$ADNS_START_TEMPLATE" --start-template-sha256 "$ADNS_START_SHA256" \
  --backup "$ADNS_WORK/backup" --resource-name "$ADNS_RECOVERY_GROUP" \
  --share-name "$ADNS_RECOVERY_SHARE" --output "$ADNS_WORK/recover.input.json"
```

The renderer requires names prefixed `agentdns-ccf-recovery-` and
`ccf-recovery-`, different from the Start group/share. It sets `Recover`, the
previous service identity, complete writable ledger, no read-only ledger
directories, distinct FQDN and `Never`. It retains logging and secure parameter
references, binds all public files in a new manifest and clears the old CCE policy.

Use the same verified, separate image archives and tar mappings as the Start
deployment to generate a new policy with `az confcom acipolicygen`. The existing
workflow's tag-only confcom input copy remains necessary for archive mappings.
Keep the generated output, then finalize and preflight the explicit Recover mode:

```sh
python3 tools/prepare_aci_recovery.py finalize \
  --start-template "$ADNS_START_TEMPLATE" --start-template-sha256 "$ADNS_START_SHA256" \
  --backup "$ADNS_WORK/backup" --recover-template "$ADNS_WORK/recover.input.json" \
  --confcom-template "$ADNS_WORK/recover.confcom.json" --output "$ADNS_WORK/recover.final.json"
python3 tools/prepare_aci_recovery.py check \
  --start-template "$ADNS_START_TEMPLATE" --start-template-sha256 "$ADNS_START_SHA256" \
  --backup "$ADNS_WORK/backup" --recover-template "$ADNS_WORK/recover.final.json" \
  --output "$ADNS_WORK/recover-preflight.json"
```

The checker requires the exact previously validated Start template and rejects
any delta outside the reviewed Recover transformation. Policy authority must
remain unchanged except the primary command's new configuration-manifest digest.
The ordinary Start preflight intentionally continues rejecting Recover mode.
Deployment remains an explicit action by the deployment owner, using its private
secure parameters. Capture retained logs from the first boot.

## Existing member authorizes recovery

Wait for `PartOfPublicNetwork`. Independently authenticate the new node and save
its new service certificate; do not trust a response-supplied certificate alone.
Member actions are explicit and separate. If interrupted, inspect governance and
node state before retrying a proposal; share submission can be retried separately.

```sh
python3 tools/durable_recovery.py accept \
  --url "$ADNS_RECOVERY_ORIGIN" --connect-ip "$ADNS_RECOVERY_IP" \
  --service-cert "$ADNS_RECOVERED_CERT" --service-sha256 "$ADNS_RECOVERED_SHA256" \
  --backup "$ADNS_WORK/backup" --member-key "$ADNS_MEMBER_KEY" \
  --member-cert "$ADNS_MEMBER_CERT" --output "$ADNS_WORK/recovery-accepted.json"
python3 tools/durable_recovery.py submit-share \
  --url "$ADNS_RECOVERY_ORIGIN" --connect-ip "$ADNS_RECOVERY_IP" \
  --service-cert "$ADNS_RECOVERED_CERT" --service-sha256 "$ADNS_RECOVERED_SHA256" \
  --member-key "$ADNS_MEMBER_KEY" --member-cert "$ADNS_MEMBER_CERT" \
  --member-encryption-key "$ADNS_MEMBER_ENCRYPTION_KEY" \
  --output "$ADNS_WORK/share-acknowledgment.json"
```

The helper acknowledges recovered public state and submits a signed transition
binding both service identities. The existing RSA member key decrypts its share
locally; the share is signed and submitted without being written or printed.
Repeat share submission for other existing members if the actual threshold
requires them. A share acknowledgment does not prove private recovery completed.

After the service is Open and the zone endpoint is available:

```sh
python3 tools/durable_recovery.py verify \
  --url "$ADNS_RECOVERY_ORIGIN" --connect-ip "$ADNS_RECOVERY_IP" \
  --service-cert "$ADNS_RECOVERED_CERT" --service-sha256 "$ADNS_RECOVERED_SHA256" \
  --backup "$ADNS_WORK/backup" --zone "$ADNS_ZONE" --output "$ADNS_WORK/recovery-proof.json"
```

Require a verified new-identity receipt with identical DNSKEY RDATA, actual DNSSEC
validation, secondary synchronization and native appraisal before cutover. Keep
the immutable snapshot, manifest, identities and proof. Subsequent backups need a
new snapshot and evidence directory; helpers refuse overwriting existing outputs.

The CI `ccf-consensus` recovery exercise uses these same archive, copied-Recover,
member acceptance/share and continuity functions with real CCF 7.0.15. It also
checks TSIG, committed request history and pending nonce continuity. Virtual CCF
testing does not replace the Azure Files/SNP/runtime exercise.

## Recurring copies while the authority is online

`tools/committed_backup.py` is a separate byte-copy helper for a live source or a
downloaded immutable source snapshot. It selects only canonical `.committed`
ledger chunks and snapshots, rejects declared history gaps/overlaps, excludes
mutable files and snapshots whose evidence sequence is beyond the closed chunks,
then hashes the selected source files twice and independently reads back the
destination. The completion manifest is written last. A partial output without
that manifest is not a backup. Outputs are private and never overwritten.

```sh
python3 tools/committed_backup.py copy \
  --source "$ADNS_COMMITTED_SOURCE" --output "$ADNS_NEW_BACKUP" \
  --service-cert "$ADNS_AUTHENTICATED_SERVICE_CERT" \
  --receipt "$ADNS_VERIFIED_KSK_RECEIPT" --zone "$ADNS_ZONE" \
  --provenance "$ADNS_COPY_PROVENANCE" --previous "$ADNS_PREVIOUS_BACKUP"
python3 tools/committed_backup.py verify --backup "$ADNS_NEW_BACKUP"
python3 tools/committed_backup.py report --backup "$ADNS_NEW_BACKUP" \
  --max-age-seconds 900
```

Use `--initial` instead of `--previous` only for the first copy. Retain the previous
verified manifest and all its committed ledger chunks on recurring runs: missing
or changed prior history is rejected. Copying unchanged chunks again preserves
the original content-progress timestamp, so a healthy timer cannot hide stalled
ledger rotation. The example 900-second limit is an operator-selected freshness
threshold, not a demonstrated recovery-point guarantee.

The trusted certificate and KSK receipt are verified and retained, but a receipt
does **not** prove that its transaction occurs in the copied ledger bytes. Chunk
names establish only declared ranges. The manifest therefore always records
`transaction_inclusion_verified: false` and `recovery_exercised: false`. This
format is deliberately distinct from the complete stopped-state archive. It must
not be passed to the stopped-state recovery helper as though it were equivalent.

The `report` command verifies bytes before producing JSON. Exit 1 means invalid
or missing evidence; exit 2 means stale copying or no observed ledger progress;
exit 3 means fresh copied bytes with recovery coverage still unverified. It never
returns a green recoverability verdict. A monitor should retain the last report,
check its timestamp independently even if the timer stops, and alert on exits 1
or 2. Display fresh byte copies separately from an isolated, member-authorized
Recover proof. Missing signed ledger-coverage verification remains visible until
that additional proof exists.

The deployment runner must use read-only source access and independently retained
backup storage, preserve the previous-manifest chain, and schedule authorized
`trigger_ledger_chunk` governance actions to bound delay before transactions reach
closed chunks. Periodic `trigger_snapshot` can shorten recovery, but does not by
itself close that ledger gap. Wait for the resulting committed files before
declaring the copy cycle complete. Read Azure file sizes from per-file snapshot
properties, not directory listings. Keep the service certificate, source identity
and protected recovery-member custody references alongside the copies; never put
keys or shares in public manifests. The helper does not install a timer, invoke
governance, modify cloud resources or establish unattended recovery on its own.

The normal live-copy contract follows [CCF 7.0.15 data persistence](https://github.com/microsoft/CCF/blob/ccf-7.0.15/doc/operations/data_persistence.rst)
and [ledger/snapshot management](https://github.com/microsoft/CCF/blob/ccf-7.0.15/doc/operations/ledger_snapshot.rst).

References: [Azure Files snapshots](https://learn.microsoft.com/en-us/rest/api/storageservices/snapshot-share),
[ACI Azure Files persistence](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-volume-azure-files),
[CCF 7.0.15 recovery](https://github.com/microsoft/CCF/blob/ccf-7.0.15/doc/operations/recovery.rst).
