// AVC audit-log camouflage (ZygiskNext-free port of ZN-AuditPatch).

#include "avc.h"
#include "rules.h"

#include <android/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace avc {

int (*orig_log_write)(int, const char *, const char *) = nullptr;
int (*orig_log_buf_write)(int, int, const char *, const char *) = nullptr;
int (*orig_log_print)(int, const char *, const char *, ...) = nullptr;
int (*orig_log_vprint)(int, const char *, const char *, va_list) = nullptr;

// ---- record classification ----------------------------------------------

bool is_avc_record(const char *s, size_t len) {
    if (!s || len == 0) return false;
    bool tagged = dsb::mem_contains(s, len, "avc:") ||
                  dsb::mem_contains(s, len, "type=1400") ||
                  dsb::mem_contains(s, len, "type=1401");
    if (!tagged) return false;
    return dsb::mem_contains(s, len, "denied") ||
           dsb::mem_contains(s, len, "granted") ||
           dsb::mem_contains(s, len, "audit(");
}

static const char *find_literal(const char *hay, size_t haylen,
                                const char *needle, size_t nlen) {
    if (nlen == 0 || nlen > haylen) return nullptr;
    const char *last = hay + haylen - nlen;
    for (const char *p = hay; p <= last; ++p) {
        if (*p == needle[0] && memcmp(p, needle, nlen) == 0) return p;
    }
    return nullptr;
}

static bool has_suspicious_comm(const char *s, size_t len) {
    const char *p = s;
    const char *end = s + len;
    while (p < end) {
        const char *hit = find_literal(p, static_cast<size_t>(end - p),
                                       "comm=", 5);
        if (!hit) break;
        const char *v = hit + 5;
        size_t vl = 0;
        while (v + vl < end && vl < 63) {
            char c = v[vl];
            if (c == '"' || c == ',' || c == ' ' || c == '\n' || c == '\t') break;
            ++vl;
        }
        char name[64];
        memcpy(name, v, vl);
        name[vl] = '\0';
        if (dsb::suspicious_actor(name)) return true;
        p = v;
    }
    return false;
}

bool line_leaks(const char *s, size_t len) {
    if (!s || len == 0) return false;
    if (dsb::hidden_buffer(s, len)) return true;
    if (has_suspicious_comm(s, len)) return true;
    // AVC records carry the offending path inside path=/name= fields, where
    // the framework name has no ':' prefix (hidden_buffer would miss it).
    if (dsb::mem_contains(s, len, "/data/adb")) return true;
    static const char *const kPaths[] = {
        "zygisk", "magisk", "kernelsu", "ksud", "shamiko", "lsposed",
        "xposed", "riru", "apatch", "auditpatch", "dirtysepbypass",
        nullptr,
    };
    for (int i = 0; kPaths[i]; ++i) {
        if (dsb::mem_contains(s, len, kPaths[i])) return true;
    }
    // ZN-AuditPatch forgery markers Duck-Detector matches directly.
    if (dsb::mem_contains(s, len, "zn-auditpatch")) return true;
    if (dsb::mem_contains(s, len, "libauditpatch")) return true;
    if (dsb::mem_contains(s, len, "logd PLT hook")) return true;
    if (dsb::mem_contains(s, len, "priv_app:s0:c512,c768")) return true;
    return false;
}

// ---- read-side filtering -------------------------------------------------

size_t filter_buffer(void *buf, size_t len) {
    if (!buf || len == 0) return len;
    if (!dsb::mem_contains(buf, len, "avc:") &&
        !dsb::mem_contains(buf, len, "type=1400") &&
        !dsb::mem_contains(buf, len, "type=1401"))
        return len;

    auto *p = static_cast<char *>(buf);
    size_t out = 0, i = 0;
    while (i < len) {
        size_t end = i;
        while (end < len && p[end] != '\n') ++end;
        size_t line_end = (end < len) ? end + 1 : end;
        size_t line_len = end - i;

        bool drop = is_avc_record(p + i, line_len) && line_leaks(p + i, line_len);
        if (!drop) {
            if (out != i) memmove(p + out, p + i, line_end - i);
            out += line_end - i;
        }
        i = line_end;
    }

    // Never turn a full drop into a fake EOF for the reader.
    if (out == 0 && len > 0) {
        p[0] = '\n';
        out = 1;
    }
    return out;
}

// ---- log source filtering ------------------------------------------------

static bool text_self_exposes(const char *tag, const char *text, size_t len) {
    if (is_avc_record(text, len) && line_leaks(text, len)) return true;
    // Only our own bookkeeping strings; do not swallow app logs that merely
    // mention a framework name.
    if (dsb::mem_contains(text, len, "dirtysepbypass")) return true;
    if (dsb::mem_contains(text, len, "auditpatch")) return true;
    if (tag && (strstr(tag, "auditpatch") || strstr(tag, "DirtySep") ||
                strstr(tag, "dirtysep")))
        return true;
    return false;
}

int my_log_write(int prio, const char *tag, const char *text) {
    if (text) {
        size_t n = strlen(text);
        if (text_self_exposes(tag, text, n)) return 0;
    }
    if (!orig_log_write) return 0;
    return orig_log_write(prio, tag, text);
}

int my_log_buf_write(int buf_id, int prio, const char *tag, const char *text) {
    if (text) {
        size_t n = strlen(text);
        if (text_self_exposes(tag, text, n)) return 0;
    }
    if (!orig_log_buf_write) return 0;
    return orig_log_buf_write(buf_id, prio, tag, text);
}

static bool fmt_needs_inspection(const char *fmt) {
    if (!fmt) return false;
    size_t n = strlen(fmt);
    return dsb::mem_contains(fmt, n, "avc:") ||
           dsb::mem_contains(fmt, n, "type=1400") ||
           dsb::mem_contains(fmt, n, "type=1401") ||
           dsb::mem_contains(fmt, n, "auditpatch") ||
           dsb::mem_contains(fmt, n, "dirtysepbypass");
}

int my_log_print(int prio, const char *tag, const char *fmt, ...) {
    if (!fmt) return 0;
    va_list ap;
    va_start(ap, fmt);
    int r = my_log_vprint(prio, tag, fmt, ap);
    va_end(ap);
    return r;
}

int my_log_vprint(int prio, const char *tag, const char *fmt, va_list ap) {
    if (!fmt) return 0;

    char buf[1024];
    int n = -1;
    if (fmt_needs_inspection(fmt)) {
        va_list ap2;
        va_copy(ap2, ap);
        n = vsnprintf(buf, sizeof(buf), fmt, ap2);
        va_end(ap2);
        if (n > 0 && text_self_exposes(tag, buf,
                                       static_cast<size_t>(n) < sizeof(buf)
                                           ? static_cast<size_t>(n)
                                           : sizeof(buf) - 1))
            return 0;
    }

    // The va_list must never be forwarded as a variadic argument (UB: the
    // callee then reads the va_list struct itself as its first argument).
    if (orig_log_vprint) return orig_log_vprint(prio, tag, fmt, ap);

    // No vprint entry point resolved: format once and use the plain writer.
    // vsnprintf() consumes the list, so hand it a copy.
    va_list ap3;
    va_copy(ap3, ap);
    n = vsnprintf(buf, sizeof(buf), fmt, ap3);
    va_end(ap3);
    if (n < 0) return 0;
    if (orig_log_write) return orig_log_write(prio, tag, buf);
    return 0;
}

}  // namespace avc
