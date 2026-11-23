#!/bin/sh
# Prints the compressed size of a local Docker image, in bytes, and fails if it is not below a
# budget (default 5,000,000 bytes, the v0.2 image budget; the v1 image measures well under it).
#
#   deploy/image-size.sh <image> [budget-bytes]
#
# The size is what a registry stores and a host pulls: every layer gzip-compressed (the default
# compression of a `docker push`, level 6) plus the image configuration. It is measured from
# `docker save` before the image is pushed, so that an image over budget is never published.
# Needs docker and python3 (both preinstalled on GitHub-hosted runners); downloads nothing.
set -eu
image=$1
budget=${2:-5000000}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
docker save "$image" -o "$work/image.tar"
mkdir "$work/x"
tar -xf "$work/image.tar" -C "$work/x"
size=$(python3 -I - "$work/x" <<'EOF'
import json, os, sys, zlib
root = sys.argv[1]
with open(os.path.join(root, "manifest.json")) as f:
    manifest = json.load(f)
if len(manifest) != 1:
    sys.exit("expected one image in the archive")
entry = manifest[0]
total = os.path.getsize(os.path.join(root, entry["Config"]))
for layer in entry["Layers"]:
    c = zlib.compressobj(6, zlib.DEFLATED, 31)  # gzip framing, level 6
    n = 0
    with open(os.path.join(root, layer), "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            n += len(c.compress(chunk))
    n += len(c.flush())
    print(f"layer {layer}: {n} bytes compressed", file=sys.stderr)
    total += n
print(total)
EOF
)
echo "image $image: $size bytes compressed (budget: below $budget)"
if [ "$size" -ge "$budget" ]; then
  echo "::error::image $image is $size bytes compressed, budget is below $budget"
  exit 1
fi
