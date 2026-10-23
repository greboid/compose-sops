# compose-sops

A [Compose provider](https://github.com/docker/compose/blob/main/docs/extension.md)
that materializes a SOPS-encrypted YAML file as individual `0400` secret files
on host tmpfs, consumed through Compose file secrets (`/run/secrets/<name>`).
Statically linked Go binary — no `sops` or `age` executable required at runtime.

## Usage

```yaml
services:
  secrets:
    provider:
      type: compose-sops
      options:
        file: ./secrets.yaml
        age-key-file: /run/compose-sops/age-key.txt
        runtime-dir: /dev/shm/demo
        owner-uid: "65532"                          # optional
        owner-gid: "65532"                          # optional
  app:
    depends_on: [secrets]                           # required on every consumer
    secrets: [db_password]                          # per-service grants only
secrets:
  db_password:
    file: /dev/shm/demo/demo/secrets/db_password
```

Secrets publish to `<runtime-dir>/<project>/<provider-service>/<secret-name>`
(files `0400`, directories `0711`). The provider also runs standalone:

```console
$ compose-sops compose --project-name NAME up   --runtime-dir DIR SERVICE
$ compose-sops compose --project-name NAME down --runtime-dir DIR SERVICE
```

## Behavior

- Decryption is in-process (SOPS + age Go libraries). Only the configured
  `age-key-file` is used; ambient SOPS discovery (`SOPS_AGE_*`, SSH paths,
  plugin identities) is structurally skipped, and plugin/SSH identity lines
  are rejected. The document MAC is verified before anything is published.
- The document must be a flat mapping of secret name → string. Duplicate
  keys, nesting, non-string scalars, NUL bytes, invalid names, and oversized
  values are rejected. Values are preserved exactly, with no added newlines.
- Repeated `up` with unchanged secrets is a no-op (inodes preserved). Changed
  secrets fail and require `down` + `up`, since bind mounts keep the old
  inode. Provisioning is atomic (private staging + rename), serialized per
  project/service with `flock`.
- `down` removes only `<runtime-dir>/<project>/<service>` and needs neither
  the encrypted file nor the identity. The `stop` block in `metadata` opts
  the provider into `docker compose stop`, which retains files so existing
  containers can restart. If normal cleanup was prevented (crash, orphans),
  remove consumer containers first — they hold bind mounts — then delete the
  directory.
- Compose file secrets are bind mounts, so ownership is not remapped: set
  `owner-uid`/`owner-gid` to the consumer's UID/GID when it does not run as
  root. Changing ownership requires CAP_CHOWN (e.g. running Compose as root).
- Keep secret values out of Compose `environment`, `setenv`, and `rawsetenv`:
  provider env becomes container `Config.Env`, visible in `docker inspect`
  and persisted on disk. The file-based design records only the mount path.

## Host key management (systemd-creds)

On a systemd host (≥ 258, with `systemd-creds.socket` active) the age
identity never sits in plaintext at rest. `compose-sops setup` walks through
the whole flow: install the binary to `/usr/local/bin`, generate an age key
(default `/etc/compose-sops/key.txt`), seal it into an encrypted credential
(`host`, `tpm2`, `host+tpm2`, or `auto` binding), install a oneshot unit that
decrypts it into a `0700` tmpfs `RuntimeDirectory` at boot
(`/run/compose-sops/age-key.txt`), optionally enable the unit, and optionally
encrypt a first secrets file. Documents are sealed to the generated key
alone — no backup key is offered.

Standalone equivalents:

```sh
compose-sops install                                  # binary to /usr/local/bin
compose-sops keygen [--output /etc/compose-sops/key.txt]
compose-sops cred /etc/compose-sops/key.cred --with-key host|tpm2|host+tpm2
compose-sops unit --output /etc/systemd/system/compose-sops-key.service /etc/compose-sops/key.cred
compose-sops encrypt --output secrets.sops.yaml secrets.yaml
```

Notes:

- Generated files are created exclusively; existing files are never
  overwritten.
- The credential name (default `compose-sops-key`) is embedded at seal time;
  `cred` and `unit` `--name` values must match.
- The materialized key is root-owned `0400` on tmpfs and gone at shutdown;
  run Compose as root or adjust ownership yourself.
- `encrypt` requires `--output`; `--key-file` defaults to
  `/run/compose-sops/age-key.txt`. The key file may contain native
  identities, explicit `age1...` recipient lines, or both; every document is
  sealed to all of them.
- Rotation: generate a new key, re-encrypt the document, re-run `cred`,
  restart the unit.

## Security limits

- tmpfs can swap: require disabled or encrypted swap.
- Process memory and crash dumps can expose plaintext independently of the
  filesystem; Go offers no guaranteed memory erasure, and deleting files is
  lifecycle cleanup, not erasure.
- Host root and Docker administrators remain trusted.
