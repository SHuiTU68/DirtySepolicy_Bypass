#!/system/bin/sh
# Load the kernel module early enough that every app started afterwards is
# covered.  Magisk runs this as root in the magisk SELinux domain; the module
# only needs to be loaded, it does the rest from inside the kernel.

MODDIR=${0%/*}
KO="$MODDIR/kmod/dsb_kmod.ko"
LOG="$MODDIR/load.log"
BUSYBOX=/data/adb/magisk/busybox

{
  echo "=== dsb_kmod $(date) ==="

  if [ -x "$BUSYBOX" ]; then
    "$BUSYBOX" rmmod dsb_kmod 2>/dev/null || true
    if "$BUSYBOX" insmod "$KO"; then
      echo "loaded"
    else
      echo "insmod failed ($?)"
      "$BUSYBOX" dmesg 2>/dev/null | tail -n 20
    fi
  else
    rmmod dsb_kmod 2>/dev/null || true
    if insmod "$KO"; then
      echo "loaded"
    else
      echo "insmod failed ($?)"
      dmesg 2>/dev/null | tail -n 20
    fi
  fi
} >> "$LOG" 2>&1

chmod 600 "$LOG" 2>/dev/null || true
