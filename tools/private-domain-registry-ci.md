# Private registry access in consumer CI

The registry source repository is private. A consumer repository's ordinary
`GITHUB_TOKEN` cannot read that separate repository. This wiring uses one
dedicated SSH deploy key per consumer repository, granted **read-only access to
the entire source repository**. GitHub deploy keys cannot restrict access to a
single file. It creates no credential or grant automatically.

After the source owner approves that read scope, an administrator can register
each consumer's public key as a distinct source-repository deploy key with
write access disabled, and store its private half in that consumer's Actions
secret `DOMAIN_REGISTRY_SSH_KEY`. Do not share one key across consumers or use a
personal SSH identity. Rotate by provisioning a replacement read-only key,
updating that consumer's secret, verifying a pinned fetch, and deleting its old
source deploy key and stale secret. Revoke both grant and secret when removing
the consumer.

The workflow exposes the secret only to the registry fetch step. The helper
removes it from its process environment before invoking Git, writes a temporary
identity file with mode 0600 inside a mode 0700 directory, and deletes the
directory after success or failure. Child processes receive the file path,
not the secret environment value. Subsequent steps receive only the public
registry snapshot and source/commit/path/hash provenance.

Only the declared HTTPS GitHub repository is converted to SSH; the full pinned
commit and registry path are preserved. Ambient registry repository/ref
overrides are not honored in this CI path. Ordinary local
`tools/domain_registry.py fetch` behavior is unchanged.

`tools/github-known-hosts` contains GitHub's public host keys verified from
the official HTTPS API at `https://api.github.com/meta`. The helper enables
strict checking against that file, disables agent identities and user SSH
configuration, and disables inherited Git configuration. It never learns host
keys from an unauthenticated `ssh-keyscan` response. Host-key rotation requires
reviewing updated official keys and their published fingerprints.

Missing credentials fail with setup instructions. Fork pull requests normally
do not receive repository secrets and therefore cannot perform this private
fetch; they must not be given the key through a privileged untrusted-code
workflow. Only run credential-bearing steps on code trusted by the consumer
repository's maintainers. Do not place keys in workflow job-wide environment,
container build contexts, artifacts, logs, or provenance.

Local verification without any real credentials or GitHub requests:

```sh
python3 -B -m unittest discover -s tools -p 'test_fetch_domain_registry_ci.py' -v
```
