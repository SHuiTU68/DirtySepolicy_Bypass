#!/system/bin/sh
# Best effort unload; the module also disappears on reboot.

if [ -x /data/adb/magisk/busybox ]; then
  /data/adb/magisk/busybox rmmod dsb_kmod 2>/dev/null || true
fi
rmmod dsb_kmod 2>/dev/null || true
