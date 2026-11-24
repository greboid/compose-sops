# compose-sops

A Docker volume plugin (managed, plugin API v2) that publishes secrets from a
SOPS-encrypted YAML document as read-only `0400` files on a private tmpfs.
Docker calls the plugin every time a consuming container starts, including
restarts after a reboot, so secrets are regenerated without Compose running.
Statically linked Go binary; no `sops` or `age` executable required.

## Install

```sh
install -d -m 0700 /var/lib/compose-sops
docker plugin install --alias compose-sops git.mouse-lake.ts.net/greboid/compose-sops:latest \
  documents.source=/srv/stacks key.source=/run/compose-sops state.source=/var/lib/compose-sops
```

Plugin settings (change with `docker plugin disable`, `docker plugin set`, `docker plugin enable`):

| Setting            | Default                 | Purpose                                                  |
|--------------------|-------------------------|----------------------------------------------------------|
| `documents.source` | `/srv`                  | host directory that volume `file` options are relative to (read-only) |
| `key.source`       | `/run/compose-sops`     | host directory containing `age-key.txt` (read-only)      |
| `state.source`     | `/var/lib/compose-sops` | host directory persisting volume options (no secrets)    |

All three directories must exist when Docker enables the plugin. The
generated key unit (below) orders itself before `docker.service`.

To build locally: `plugin/build.sh dist && docker plugin create compose-sops dist/plugin`.

`plugin/install.sh PLUGIN_DIR` creates the plugin from a local directory,
replaces an installed plugin from a different build, and applies the
settings from `COMPOSE_SOPS_DOCUMENTS`, `COMPOSE_SOPS_KEY_DIR` and
`COMPOSE_SOPS_STATE_DIR` (defaults as above); it is idempotent. Replacing the
plugin leaves running consumers on their existing secrets; they pick up the
new plugin when restarted.

The `compose-sops` apk ships the plugin in `/usr/lib/compose-sops/plugin`
and `compose-sops-plugin.service`, which docker.service wants, to run that
installer after Docker starts (settings from `/etc/compose-sops/plugin.env`).
A `docker.service` drop-in orders Docker after `compose-sops-key.service`.
The package puts no binary on the PATH; the host commands below are
available as `/usr/lib/compose-sops/plugin/rootfs/usr/bin/compose-sops`.

## Usage

```yaml
services:
  app:
    image: example/app
    volumes:
      - type: volume
        source: app-secrets
        target: /run/secrets
        read_only: true
        volume:
          nocopy: true
volumes:
  app-secrets:
    driver: compose-sops
    driver_opts:
      file: myproject/secrets.sops.yaml   # relative to documents.source
      keys: db_password,api_key           # optional; default is every secret
      uid: "65532"                        # optional, with gid
      gid: "65532"
```

Use one volume per distinct set of secrets; several volumes may reference the
same document with different `keys`. `nocopy` stops Docker trying to copy
image content into the read-only volume.

## Behavior

- `file` must be relative, without `..` components, and resolve beneath the
  documents root; symlinks that escape it are refused.
- Volume creation verifies that the document decrypts and contains every
  selected key. Only the options are persisted, never the document contents.
- The first active mount reads the current document, decrypts it, mounts a
  size-limited tmpfs (`noswap` where the kernel supports it, Linux 6.4+),
  writes the selected secrets as `0400` files (directory `0500`, both owned
  by `uid`/`gid`) and
  remounts it read-only. The last unmount removes the tmpfs.
- Mounting fails, and the container does not start, if the document or key
  is unavailable or does not verify.
- Rotation: update the document, then stop every container using the volume
  and start them again. The document is not reread while any consumer is
  running, so all consumers always see the same contents.
- After a reboot or plugin restart, mount records for mount points that no
  longer exist are discarded; the next container start republishes.
- The document must be a flat mapping of secret name → string. Duplicate
  keys, nesting, non-string scalars, NUL bytes, invalid names and oversized
  values are rejected. Only the configured key file is used; plugin/SSH
  identity lines are rejected. Values are preserved exactly.
- File ownership is the `uid`/`gid` options (default root), so a non-root
  application needs them set to its own UID/GID.

## Host key management (systemd-creds)

On a systemd host (≥ 258, with `systemd-creds.socket` active) the age
identity never sits in plaintext at rest. `compose-sops setup` walks through
the whole flow: install the binary to `/usr/local/bin`, generate an age key
(default `/etc/compose-sops/key.txt`), seal it into an encrypted credential
(`host`, `tpm2`, `host+tpm2`, or `auto` binding), install a oneshot unit that
decrypts it into a `0700` tmpfs `RuntimeDirectory` at boot
(`/run/compose-sops/age-key.txt`) before Docker starts, optionally enable the
unit, and optionally encrypt a first secrets file. Documents are sealed to the
generated key alone — no backup key is offered.

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
- The materialized key is root-owned `0400` on tmpfs and gone at shutdown.
  The directory is kept across unit restarts (`RuntimeDirectoryPreserve=restart`)
  because the plugin binds it; stopping the unit removes it, after which the
  plugin must be disabled and enabled again. Units generated before the
  volume plugin lack this and the `docker.service` ordering: regenerate them.
- `encrypt` requires `--output`. `-` as INPUT reads stdin and `--output -`
  writes stdout, so the plaintext never needs a file. `--key-file` defaults to
  `/run/compose-sops/age-key.txt`. The key file may contain native
  identities, explicit `age1...` recipient lines, or both; every document is
  sealed to all of them.
- Rotation: generate a new key, re-encrypt the document, re-run `cred`,
  restart the unit.

## Orchestration commands

These read nothing from the runtime environment beyond `--key-file`
(default `/run/compose-sops/age-key.txt`). `INPUT` may be `-` for stdin.

```sh
compose-sops recipient [--key-file PATH]
compose-sops check [--key-file PATH] INPUT
compose-sops rekey [--key-file PATH] [--add R,...] [--remove R,...] INPUT
compose-sops decrypt [--key-file PATH] INPUT
```

- `recipient` prints the `age1...` recipient of each identity in the key file.
- `check` decrypts and verifies the document and prints `valid`. It never writes.
- `rekey` writes the document to stdout with recipients added or removed. Adding
  wraps the existing data key for each new recipient. Removing rotates the data key
  and re-encrypts every value. If the recipients already match, the input is
  copied unchanged and the key file is not read. Only documents with a single key
  group are supported.
- `decrypt` decrypts and verifies the document and prints its secrets to stdout
  as a single JSON object of name → value, for orchestrators that use the values
  themselves. Nothing is written to disk, and nothing is printed if verification fails.

### Go library

Package `github.com/greboid/compose-sops/secrets` runs `recipient`, `check`,
`rekey`, `encrypt` and `decrypt` in process, with the same validation as the
commands: `Recipients`, `Check`, `Rekey`, `Encrypt` and `Decrypt`. Publishing
stays with the volume plugin.

## Security limits

- Before Linux 6.4 tmpfs cannot opt out of swap: require disabled or
  encrypted swap.
- Process memory and crash dumps can expose plaintext independently of the
  filesystem; Go offers no guaranteed memory erasure, and deleting files is
  lifecycle cleanup, not erasure.
- Host root and Docker administrators remain trusted. The plugin runs with
  `CAP_SYS_ADMIN` to mount tmpfs.
