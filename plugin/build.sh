#!/bin/sh
# Builds the managed Docker plugin into OUT (default: dist):
#   OUT/plugin  config.json + rootfs, for 'docker plugin create NAME OUT/plugin'
#   OUT/oci     OCI layout tagged "latest", for 'skopeo copy oci:OUT/oci:latest docker://REF'
# Requires go, GNU tar, gzip, jq and sha256sum.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-dist}
rm -rf "$out"
mkdir -p "$out"
out=$(cd "$out" && pwd)
rootfs="$out/plugin/rootfs"
mkdir -p "$rootfs/usr/bin" "$rootfs/documents" "$rootfs/state" "$rootfs/mnt/volumes" \
	"$rootfs/run/compose-sops" "$rootfs/run/docker/plugins" "$rootfs/tmp"
chmod 1777 "$rootfs/tmp"

(cd "$here/.." && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$rootfs/usr/bin/compose-sops" .)
cp "$here/config.json" "$out/plugin/config.json"

blobs="$out/oci/blobs/sha256"
mkdir -p "$blobs"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$rootfs" -cf "$out/rootfs.tar" .
diff_id=$(sha256sum "$out/rootfs.tar" | cut -d' ' -f1)
gzip -n -9 "$out/rootfs.tar"
layer=$(sha256sum "$out/rootfs.tar.gz" | cut -d' ' -f1)
mv "$out/rootfs.tar.gz" "$blobs/$layer"

jq -c --arg d "sha256:$diff_id" '. + {rootfs: {type: "layers", diff_ids: [$d]}}' "$here/config.json" > "$out/config.blob"
config=$(sha256sum "$out/config.blob" | cut -d' ' -f1)
mv "$out/config.blob" "$blobs/$config"

size() { wc -c < "$1" | tr -d ' '; }
jq -nc \
	--arg c "sha256:$config" --argjson cs "$(size "$blobs/$config")" \
	--arg l "sha256:$layer" --argjson ls "$(size "$blobs/$layer")" \
	'{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
	  config: {mediaType: "application/vnd.docker.plugin.v1+json", digest: $c, size: $cs},
	  layers: [{mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: $l, size: $ls}]}' > "$out/manifest.json"
manifest=$(sha256sum "$out/manifest.json" | cut -d' ' -f1)
msize=$(size "$out/manifest.json")
mv "$out/manifest.json" "$blobs/$manifest"

printf '{"imageLayoutVersion":"1.0.0"}' > "$out/oci/oci-layout"
jq -nc --arg m "sha256:$manifest" --argjson s "$msize" \
	'{schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $m, size: $s,
	  annotations: {"org.opencontainers.image.ref.name": "latest"}}]}' > "$out/oci/index.json"

echo "plugin: $out/plugin"
echo "oci:    $out/oci (manifest sha256:$manifest)"
