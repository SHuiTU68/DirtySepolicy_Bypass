#!/sbin/sh
# DirtySepolicy Bypass — Magisk module installer (kernel module flavor)

SKIPUNZIP=0

if [ "$MAGISK_VER_CODE" -lt 24000 ]; then
  ui_print "! Magisk 24.0+ required (you have $MAGISK_VER)"
  abort  "! Aborting"
fi

case "$ARCH" in
  arm64) ;;
  *) ui_print "! arm64 device required (found $ARCH)"
     abort  "! Aborting" ;;
esac

ui_print "- Installing DirtySepolicy Bypass v5.0.0 (kernel side)"

if [ ! -f "$MODPATH/kmod/dsb_kmod.ko" ]; then
  ui_print "! Missing kmod/dsb_kmod.ko in module zip"
  abort  "! Aborting"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/customize.sh"   0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/kmod/dsb_kmod.ko" 0 0 0644

ui_print "- Reboot to load dsb_kmod.ko (post-fs-data)."
ui_print "- Check /data/adb/modules/dirtysepbypass/load.log for the result."
