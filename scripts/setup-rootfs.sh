#!/usr/bin/env bash
# Builds a minimal, self-contained rootfs for testing nanorock, using
# BusyBox as a multi-call binary for /bin/sh, ls, ps, mount, etc.
set -euo pipefail

ROOTFS_DIR="${1:-./rootfs}"

echo "[setup-rootfs] target directory: $ROOTFS_DIR"

if ! command -v busybox >/dev/null 2>&1; then
    echo "[setup-rootfs] busybox not found, installing busybox-static..."
    sudo apt-get update -qq
    sudo apt-get install -y busybox-static
fi

BUSYBOX_BIN="$(command -v busybox)"
echo "[setup-rootfs] using busybox at: $BUSYBOX_BIN"

mkdir -p "$ROOTFS_DIR"/{bin,proc,sys,dev,etc,tmp,root}
cp "$BUSYBOX_BIN" "$ROOTFS_DIR/bin/busybox"

# Creates the sh/ls/ps/mount/... applet symlinks that make this look
# like a normal (if tiny) userland.
#
# NOTE: `busybox --install -s` looks tempting here, but it always
# resolves symlink targets to *this host's* absolute path to the
# busybox binary. That path stops existing the moment nanorock
# pivot_roots into the container, silently breaking every applet.
# Pointing each symlink at the literal, unresolved string
# "/bin/busybox" instead means it resolves correctly once /bin/busybox
# *is* the container's own root.
for applet in $("$ROOTFS_DIR/bin/busybox" --list); do
    # "busybox" is listed as an applet of itself - symlinking it would
    # overwrite the real binary with a symlink pointing at itself.
    [ "$applet" = "busybox" ] && continue
    ln -sf /bin/busybox "$ROOTFS_DIR/bin/$applet"
done

cat > "$ROOTFS_DIR/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
EOF

cat > "$ROOTFS_DIR/etc/group" <<'EOF'
root:x:0:
EOF

echo "nanorock" > "$ROOTFS_DIR/etc/hostname"

echo "[setup-rootfs] done."
echo "[setup-rootfs] try:  sudo bin/nanorock run --rootfs $ROOTFS_DIR --hostname box -- /bin/sh"
