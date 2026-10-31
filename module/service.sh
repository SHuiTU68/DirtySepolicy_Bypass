#!/system/bin/sh
# The kernel module is loaded in the *service* stage, i.e. after the device
# has booted.  A defective module can therefore never keep it from booting.
#
# boot_state guards against a panic loop: before loading we drop the marker,
# and a background watchdog removes it once the device has stayed up for five
# minutes.  If the kernel dies earlier the marker survives, so the next boot
# skips loading and the phone comes up normally.  Delete the marker (or use
# Magisk safe mode) to try again.

MODDIR=${0%/*}
KO="$MODDIR/kmod/dsb_kmod.ko"
LOG="$MODDIR/load.log"
STATE="$MODDIR/boot_state"
BUSYBOX=/data/adb/magisk/busybox

insmod_ko() {
  if [ -x "$BUSYBOX" ]; then
    "$BUSYBOX" rmmod dsb_kmod 2>/dev/null || true
    "$BUSYBOX" insmod "$KO" "$@"
  else
    rmmod dsb_kmod 2>/dev/null || true
    insmod "$KO" "$@"
  fi
}

{
  echo "=== dsb_kmod $(date) ==="

  if [ ! -f "$KO" ]; then
    echo "missing $KO"
    exit 0
  fi

  if [ -f "$STATE" ]; then
    echo "skip: the previous boot did not stabilise after loading."
    echo "      remove $STATE to retry, or disable the module in Magisk."
    exit 0
  fi

  echo "attempt $(date)" > "$STATE"

  if [ -f "$MODDIR/hide_mounts" ]; then
    echo "hide_mounts=1 (opt-in mount hiding)"
    insmod_ko hide_mounts=1
  else
    insmod_ko
  fi

  if [ $? -ne 0 ]; then
    echo "insmod failed ($?)"
    rm -f "$STATE"
    dmesg 2>/dev/null | tail -n 20
    exit 0
  fi

  echo "loaded"

  ( sleep 300; rm -f "$STATE" ) </dev/null >/dev/null 2>&1 &
} >> "$LOG" 2>&1

chmod 600 "$LOG" 2>/dev/null || true
