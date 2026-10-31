// Shared hiding rules used by the SELinux, stealth and AVC components.
//
// Keep this header in sync with tools/audit.py (HOOK_BLOCKLIST /
// HOOK_EXACT_PROBES) when adding new detection surfaces.

#pragma once

#include <stddef.h>
#include <string.h>

namespace dsb {

inline bool mem_contains(const void *hay, size_t haylen, const char *needle) {
    if (!hay || !needle) return false;
    const size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > haylen) return false;
    const char *h = static_cast<const char *>(hay);
    const char *last = h + haylen - nlen;
    for (const char *p = h; p <= last; ++p) {
        if (*p == needle[0] && memcmp(p, needle, nlen) == 0) return true;
    }
    return false;
}

// Context substrings. ":su:" matches u:r:su:s0 / u:object_r:su:s0 and
// deliberately avoids bare "su" inside unrelated type names.
inline const char *const kHiddenTokens[] = {
    ":magisk",       ":kitsune",     ":apatch",
    ":ksu",          ":kernelsu",
    ":lsposed",      ":xposed",      ":riru",
    ":adbroot",
    ":supersu",      ":supolicy",    ":su:",
    ":zygisk",       ":shamiko",     ":zygisknext", ":zygisksu",
    ":neozygisk",    ":rezygisk",
    ":droidspacesd", ":msd_app",     ":msd_daemon",
    ":auditpatch",
    nullptr,
};

inline bool hidden_context(const char *s) {
    if (!s) return false;
    for (int i = 0; kHiddenTokens[i]; ++i) {
        if (strstr(s, kHiddenTokens[i])) return true;
    }
    return false;
}

inline bool hidden_buffer(const void *buf, size_t len) {
    if (!buf || len == 0) return false;
    for (int i = 0; kHiddenTokens[i]; ++i) {
        if (mem_contains(buf, len, kHiddenTokens[i])) return true;
    }
    return false;
}

// Binary policy string table scrub list. No leading ':' and no bare "su"
// (AOSP itself defines the su type on some releases).
inline const char *const kBinaryTokens[] = {
    "magisk", "kitsune", "kernelsu", "ksu", "lsposed", "xposed", "riru",
    "supersu", "supolicy", "zygisk", "apatch", "shamiko", "adbroot",
    "droidspacesd", "msd_daemon", "msd_app", "auditpatch",
    nullptr,
};

inline const char *const kSuspiciousActors[] = {
    "su", "magisk", "magiskd", "magisk32", "ksud", "kernelsu", "apatch",
    "apd", "supersu", "supolicy", "shamiko", "zygisk", "zygiskd",
    "zygisk64", "zygisk32", "dirtysepbypass", "auditpatch",
    nullptr,
};

// Paths and loader keywords that give a root framework away when they show
// up in maps, smaps, fd targets or linker namespaces.  Only applied while
// serving the scrubbed view of an ordinary, non-root app process; root-granted
// apps and system_server keep the real /data/adb mappings.
//
// Directory prefixes are matched anywhere in the string, but framework names
// are matched only against the final path component or a [bracket] mapping
// annotation.  Otherwise an app whose own data path merely contains e.g.
// "magisk" (com.topjohnwu.magisk) or "lsposed" would have its own APK
// mappings scrubbed away, which is a stronger anomaly than the injection.
inline bool restricted_path(const char *p) {
    if (!p || !*p) return false;
    static const char *const kDirs[] = {
        "/data/adb", "/debug_ramdisk", "/sbin/.magisk", "/sbin/magisk",
        nullptr,
    };
    for (int i = 0; kDirs[i]; ++i) {
        if (strstr(p, kDirs[i])) return true;
    }

    static const char *const kTokens[] = {
        "zygisk", "magisk", "riru", "lsposed", "xposed", "kernelsu",
        "ksud", "apatch", "shamiko", "auditpatch", "neozygisk",
        "rezygisk", "dirtysepbypass", "supersu", "supolicy", "kitsune",
        nullptr,
    };
    const char *base = strrchr(p, '/');
    base = base ? base + 1 : p;
    const char *ann = strrchr(p, '[');
    for (int i = 0; kTokens[i]; ++i) {
        if (strstr(base, kTokens[i])) return true;
        if (ann && strstr(ann, kTokens[i])) return true;
    }
    return false;
}

// A mapping path that is already a strong signal by itself.
inline bool deleted_shared_object(const char *p) {
    return p && strstr(p, "(deleted)") && strstr(p, ".so");
}

// Lower-case ASCII helper used for comm/exe comparisons.
inline void lower_copy(char *dst, const char *src, size_t max) {
    if (max == 0) return;
    size_t i = 0;
    for (; src[i] && i + 1 < max; ++i) {
        char c = src[i];
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        dst[i] = c;
    }
    dst[i] = '\0';
}

inline bool suspicious_actor(const char *name) {
    if (!name || !*name) return false;
    char lower[64];
    lower_copy(lower, name, sizeof(lower));
    for (int i = 0; kSuspiciousActors[i]; ++i) {
        if (strcmp(lower, kSuspiciousActors[i]) == 0) return true;
    }
    return false;
}

}  // namespace dsb
