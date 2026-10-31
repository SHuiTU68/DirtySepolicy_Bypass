#!/usr/bin/env bash
# Build the DirtySepolicy Bypass kernel module against the OnePlus MT6991
# kernel tree and package a flashable Magisk module zip into dist/.
#
# Requirements: clang + lld (LLVM=1), make, bc, flex, bison, libelf,
# pahole, python3, curl and tar.  On Debian/Ubuntu:
#
#   sudo apt-get install -y clang lld llvm make bc flex bison libelf-dev \
#                            libssl-dev dwarves python3 curl
#
# Set KERNEL_SRC to reuse an already extracted kernel tree (a local clone of
# https://github.com/OnePlusOSS/android_kernel_oneplus_mt6991 works too).
# Set KERNEL_OUT to reuse a prepared object tree.
#
# The kernel commit is pinned: the module has to match the KMI of the device
# kernel, and vermagic/MODVERSIONS are handled by tools/fixup-versions.py.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KERNEL_REPO="${KERNEL_REPO:-OnePlusOSS/android_kernel_oneplus_mt6991}"
KERNEL_SHA="${KERNEL_SHA:-1d453aabd9c290bc7d185626b9542eae1cf0b1f6}"

KERNEL_SRC="${KERNEL_SRC:-$ROOT/.kernel}"
KERNEL_OUT="${KERNEL_OUT:-$ROOT/.kout}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

if [[ ! -d "$KERNEL_SRC" || ! -f "$KERNEL_SRC/Makefile" ]]; then
    echo "==> Fetching kernel $KERNEL_SHA"
    rm -rf "$KERNEL_SRC" "$KERNEL_SRC.tmp"
    mkdir -p "$KERNEL_SRC.tmp"
    curl -fL --retry 3 --retry-delay 2 \
        "https://codeload.github.com/$KERNEL_REPO/tar.gz/$KERNEL_SHA" \
        -o "$KERNEL_SRC.tmp/kernel.tar.gz"
    tar -xzf "$KERNEL_SRC.tmp/kernel.tar.gz" -C "$KERNEL_SRC.tmp" \
        --strip-components=1
    mv "$KERNEL_SRC.tmp" "$KERNEL_SRC"
fi

mkdir -p "$KERNEL_OUT"

MAKE=(make -C "$KERNEL_SRC" O="$KERNEL_OUT" ARCH=arm64 LLVM=1 -j"$JOBS")

echo "==> Configuring kernel"
"${MAKE[@]}" gki_defconfig

echo "==> Preparing kernel headers"
"${MAKE[@]}" modules_prepare

echo "==> Building dsb_kmod.ko"
# No Module.symvers exists in a modules_prepare tree, so the module is built
# without CRCs (__versions stays empty) and unresolved symbols are warnings
# rather than fatal; the device resolves them at load time.
"${MAKE[@]}" KBUILD_MODPOST_WARN=1 M="$ROOT/kmod" modules

KO="$ROOT/kmod/dsb_kmod.ko"
[[ -f "$KO" ]] || { echo "error: $KO was not produced" >&2; exit 1; }

echo "==> Patching module metadata"
python3 "$ROOT/tools/fixup-versions.py" "$KO"

mkdir -p "$ROOT/module/kmod"
cp "$KO" "$ROOT/module/kmod/dsb_kmod.ko"

# Leave no build products in the source tree.
make -C "$KERNEL_SRC" O="$KERNEL_OUT" ARCH=arm64 LLVM=1 \
    M="$ROOT/kmod" clean >/dev/null 2>&1 || true

VERSION="$(sed -n 's/^version=//p' "$ROOT/module/module.prop" | tr -d '\r')"
VERSION="${VERSION:-dev}"
mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/dirtysepbypass-${VERSION}.zip"
rm -f "$OUT"

python3 - "$ROOT" "$OUT" <<'PY'
import os
import sys
import zipfile

root, out = sys.argv[1], sys.argv[2]
module_dir = os.path.join(root, "module")
exec_bits = {"update-binary", "customize.sh", "post-fs-data.sh", "service.sh",
             "uninstall.sh", "action.sh"}

with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for dirpath, _dirnames, filenames in os.walk(module_dir):
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, module_dir)
            info = zipfile.ZipInfo.from_file(path, rel)
            if name in exec_bits or name.endswith(".sh"):
                info.external_attr = (0o100755 << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(path, "rb") as fh:
                zf.writestr(info, fh.read())
print("packaged", out)
PY

echo "==> Output: $OUT"
