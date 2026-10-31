#!/usr/bin/env bash
# Build the Zygisk library for every supported ABI and package a flashable
# Magisk module zip into dist/.
#
# Requirements: Android NDK (r26+), python3.  Set ANDROID_NDK_HOME (or
# ANDROID_NDK_ROOT) before running, or let the script find a side-by-side
# NDK under $ANDROID_SDK_ROOT/ndk.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ABIS=(arm64-v8a armeabi-v7a x86 x86_64)

find_ndk() {
    if [[ -n "${ANDROID_NDK_HOME:-}" && -d "$ANDROID_NDK_HOME" ]]; then
        echo "$ANDROID_NDK_HOME"; return
    fi
    if [[ -n "${ANDROID_NDK_ROOT:-}" && -d "$ANDROID_NDK_ROOT" ]]; then
        echo "$ANDROID_NDK_ROOT"; return
    fi
    local sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
    if [[ -n "$sdk" && -d "$sdk/ndk" ]]; then
        local newest
        newest="$(ls -1 "$sdk/ndk" 2>/dev/null | sort -V | tail -n 1)"
        if [[ -n "$newest" ]]; then echo "$sdk/ndk/$newest"; return; fi
    fi
    echo ""
}

NDK="$(find_ndk)"
if [[ -z "$NDK" ]]; then
    echo "error: Android NDK not found (set ANDROID_NDK_HOME)" >&2
    exit 1
fi

NDK_BUILD="$NDK/ndk-build"
[[ -x "$NDK_BUILD" ]] || NDK_BUILD="$NDK/ndk-build.cmd"
if [[ ! -x "$NDK_BUILD" ]]; then
    echo "error: ndk-build not executable at $NDK_BUILD" >&2
    exit 1
fi

echo "==> NDK: $NDK"
echo "==> Building libdirtysepbypass.so (${ABIS[*]})"

rm -rf "$ROOT/build" "$ROOT/libs" "$ROOT/module/zygisk"
mkdir -p "$ROOT/module/zygisk"

"$NDK_BUILD" \
    NDK_PROJECT_PATH="$ROOT" \
    APP_BUILD_SCRIPT="$ROOT/jni/Android.mk" \
    NDK_APPLICATION_MK="$ROOT/jni/Application.mk" \
    NDK_OUT="$ROOT/build/obj" \
    NDK_LIBS_OUT="$ROOT/build/libs" \
    -j"$(nproc 2>/dev/null || echo 4)"

for abi in "${ABIS[@]}"; do
    src="$ROOT/build/libs/$abi/libdirtysepbypass.so"
    if [[ ! -f "$src" ]]; then
        echo "error: missing $src" >&2
        exit 1
    fi
    cp "$src" "$ROOT/module/zygisk/$abi.so"
done

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
