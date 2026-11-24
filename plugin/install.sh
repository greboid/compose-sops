#!/bin/sh
# Installs the compose-sops volume plugin into Docker from a plugin directory
# (config.json + rootfs), replacing an installed plugin from a different
# build, and applies the host mount settings. Safe to run repeatedly.
#
# Usage: install.sh [PLUGIN_DIR]   (default /usr/lib/compose-sops/plugin)
# Environment:
#   COMPOSE_SOPS_PLUGIN     plugin name (default compose-sops)
#   COMPOSE_SOPS_DOCUMENTS  documents root (default /srv)
#   COMPOSE_SOPS_KEY_DIR    directory holding age-key.txt (default /run/compose-sops)
#   COMPOSE_SOPS_STATE_DIR  volume state directory (default /var/lib/compose-sops)
set -eu

dir=${1:-/usr/lib/compose-sops/plugin}
name=${COMPOSE_SOPS_PLUGIN:-compose-sops}
documents=${COMPOSE_SOPS_DOCUMENTS:-/srv}
key=${COMPOSE_SOPS_KEY_DIR:-/run/compose-sops}
state=${COMPOSE_SOPS_STATE_DIR:-/var/lib/compose-sops}

want=$(cat "$dir/config.json" "$dir/rootfs/usr/bin/compose-sops" | sha256sum | cut -c1-16)
install -d -m 0700 "$state"

installed() { docker plugin inspect "$name" >/dev/null 2>&1; }
field() { docker plugin inspect -f "$1" "$name"; }
build() { field '{{range .Settings.Env}}{{println .}}{{end}}' | sed -n 's/^COMPOSE_SOPS_BUILD=//p'; }

if installed && [ "$(build)" != "$want" ]; then
	echo "replacing $name with build $want"
	if [ "$(field '{{.Enabled}}')" = true ]; then
		docker plugin disable -f "$name"
	fi
	docker plugin rm -f "$name"
fi
if ! installed; then
	echo "creating $name from $dir"
	docker plugin create "$name" "$dir"
fi

mounts=$(field '{{range .Settings.Mounts}}{{.Name}}={{.Source}} {{end}}')
if [ "$mounts" != "documents=$documents key=$key state=$state " ] || [ "$(build)" != "$want" ]; then
	if [ "$(field '{{.Enabled}}')" = true ]; then
		docker plugin disable -f "$name"
	fi
	docker plugin set "$name" documents.source="$documents" key.source="$key" state.source="$state" COMPOSE_SOPS_BUILD="$want"
fi
if [ "$(field '{{.Enabled}}')" != true ]; then
	docker plugin enable "$name"
fi
echo "$name enabled (build $want)"
