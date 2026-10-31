// DirtySepolicy Bypass — Zygisk module
//
// Defeats DirtySepolicy v2.0–v2.2 detection and the Duck-Detector probe set by:
// 1. Intercepting reads/writes to /sys/fs/selinux/access to hide framework
//    allow rules and fix the avdSeqNo counter.
// 2. Intercepting writes to /sys/fs/selinux/context and /proc/self/attr/current
//    to hide framework SELinux types from contextExists() checks.
// 3. Intercepting reads from /sys/fs/selinux/status to hide evidence of
//    policy reloads (sequence/policyload counters) and blocking mmap of it.
// 4. PLT-hooking libselinux APIs as defense-in-depth against detectors that
//    still use the userspace library.
// 5. Re-clearing PR_SET_DUMPABLE in postAppSpecialize so same-uid
//    cross-process readers (forked cat, process_vm_readv, ptrace) cannot see
//    maps/mem.  Zygote already leaves normal apps non-dumpable; only
//    profileable ones (PROFILE_FROM_SHELL) need the extra clear.  The spoof
//    hooks (prctl/syscall/stat/statx) are always registered in the same batch
//    as the rest (a second pltHookCommit() call is not portable across Zygisk
//    providers), but they only rewrite results when guard_process() really
//    changed the flag; otherwise they forward untouched.
// 6. Handing out scrubbed copies of /proc/{self,thread-self,<pid>}/{
//    maps,smaps,smaps_rollup,status,comm,stat,sched,mountinfo,mounts,environ},
//    fd link targets, linker solists and environment variables so a normal app
//    cannot see the injected Zygisk library (see stealth.cpp).
// 7. Dropping leaking AVC audit records at the log source and while reading
//    logcat-style streams (see avc.cpp, ported from ZN-AuditPatch without the
//    ZygiskNext dependency).

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <android/log.h>
#include "zygisk.hpp"
#include "rules.h"
#include "stealth.h"
#include "avc.h"

#define LOG_TAG "selinuxfs"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#ifdef DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...) ((void)0)
#endif

// No C++ runtime is linked (APP_STL := none): the module uses no exceptions,
// RTTI, STL containers or heap allocation of its own, and linking libc++ into
// a library that gets dlopen()ed inside zygote/system_server would export
// _Znwm/__cxa_throw/__gxx_personality_v0 and risk interposing on the host
// process's runtime.

// ---- hidden context substrings ------------------------------------------

static inline bool is_hidden(const char *con) {
    return dsb::hidden_context(con);
}

// ---- exact-match probes (stock contexts, framework-injected rules) ------

struct ExactProbe {
    const char *scon;
    const char *tcon;
    const char *tclass;
    const char *perm;
};

static const ExactProbe kHiddenExact[] = {
    {"u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"},
    {"u:r:kernel:s0",        "u:object_r:tmpfs:s0", "fifo_file",  "open"},
    {"u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"},
    {"u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"},
    {"u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0",  "file", "execute_no_trans"},
    {"u:r:zygote:s0",        "u:object_r:adb_data_file:s0", "dir",  "search"},
    // Duck-Detector "fsck_untrusted sys_admin" oracle.
    {"u:r:fsck_untrusted:s0", "u:r:fsck_untrusted:s0", "capability", "sys_admin"},
    {nullptr, nullptr, nullptr, nullptr},
};

static inline bool is_hidden_exact(const char *scon, const char *tcon,
                                   const char *tclass, const char *perm) {
    if (!scon || !tcon || !tclass || !perm) return false;
    for (int i = 0; kHiddenExact[i].scon; ++i) {
        if (strcmp(scon, kHiddenExact[i].scon) == 0 &&
            strcmp(tcon, kHiddenExact[i].tcon) == 0 &&
            strcmp(tclass, kHiddenExact[i].tclass) == 0 &&
            strcmp(perm, kHiddenExact[i].perm) == 0) {
            return true;
        }
    }
    return false;
}

// ---- hidden class:perm pairs (broad perm hiding) -------------------------

struct ClassPerm { const char *cls; const char *perm; };
static const ClassPerm kHiddenClassPerms[] = {
    { "process", "execmem" },
    { nullptr, nullptr },
};

static inline bool is_hidden_perm(const char *perm) {
    if (!perm) return false;
    for (int i = 0; kHiddenClassPerms[i].perm; ++i) {
        if (strcmp(perm, kHiddenClassPerms[i].perm) == 0) return true;
    }
    return false;
}

// ---- numeric resolution via sysfs ----------------------------------------

typedef unsigned int   access_vector_t;
typedef unsigned short security_class_t;

struct ResolvedBit {
    security_class_t cls_id;
    access_vector_t  perm_bit;
};
static ResolvedBit g_hidden_bits[8] = {};
static int         g_hidden_bit_count = 0;

struct ExactBit {
    const char      *scon;
    const char      *tcon;
    security_class_t cls_id;
    access_vector_t  perm_bit;
};
static ExactBit g_exact_bits[16] = {};
static int      g_exact_bit_count = 0;

static bool g_bits_resolved = false;

static bool read_int_file(const char *path, int *out) {
    FILE *f = fopen(path, "re");
    if (!f) { LOGW("read_int_file: fopen(%s) failed: %s", path, strerror(errno)); return false; }
    char buf[32];
    bool ok = fgets(buf, sizeof(buf), f) != nullptr;
    fclose(f);
    if (!ok) { LOGW("read_int_file: fgets(%s) returned null", path); return false; }
    *out = atoi(buf);
    return true;
}

static bool resolve_class_perm(const char *cls, const char *perm,
                                security_class_t *out_cls, access_vector_t *out_bit) {
    char path[256];
    int cid, pid;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", cls);
    if (!read_int_file(path, &cid)) { LOGW("resolve_class_perm: failed for %s:%s (class index)", cls, perm); return false; }
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/perms/%s", cls, perm);
    if (!read_int_file(path, &pid)) { LOGW("resolve_class_perm: failed for %s:%s (perm bit)", cls, perm); return false; }
    *out_cls = (security_class_t)cid;
    *out_bit = 1u << (pid - 1);
    LOGD("resolved %s:%s -> class=%u bit=0x%x", cls, perm, cid, *out_bit);
    return true;
}

static void resolve_hidden_bits() {
    if (g_bits_resolved) return;

    for (int i = 0; kHiddenClassPerms[i].cls && g_hidden_bit_count < 8; ++i) {
        security_class_t cid;
        access_vector_t pbit;
        if (resolve_class_perm(kHiddenClassPerms[i].cls, kHiddenClassPerms[i].perm,
                               &cid, &pbit)) {
            g_hidden_bits[g_hidden_bit_count++] = { cid, pbit };
        }
    }
    for (int i = 0; kHiddenExact[i].scon && g_exact_bit_count < 16; ++i) {
        security_class_t cid;
        access_vector_t pbit;
        if (resolve_class_perm(kHiddenExact[i].tclass, kHiddenExact[i].perm,
                               &cid, &pbit)) {
            g_exact_bits[g_exact_bit_count++] = {
                kHiddenExact[i].scon, kHiddenExact[i].tcon, cid, pbit
            };
        }
    }

    g_bits_resolved = true;
    LOGD("resolve_hidden_bits: %d broad, %d exact", g_hidden_bit_count, g_exact_bit_count);
}

// ---- kernel version detection -------------------------------------------

static bool g_new_kernel = false;

static void detect_kernel_version() {
    struct utsname uts;
    if (uname(&uts) != 0) { LOGW("detect_kernel_version: uname() failed: %s", strerror(errno)); return; }
    int major = 0, minor = 0;
    sscanf(uts.release, "%d.%d", &major, &minor);
    g_new_kernel = (major > 6 || (major == 6 && minor >= 10));
    LOGD("kernel %s -> %d.%d, new_kernel=%d", uts.release, major, minor, g_new_kernel);
}

// ---- fd tracking --------------------------------------------------------

enum FdType : unsigned char {
    FD_NONE = 0,
    FD_CONTEXT,
    FD_ACCESS,
    FD_STATUS,
    FD_POLICY,
    FD_AVC_STATS,
};

struct TrackedFd {
    int fd;
    FdType type;
    char scon[256];
    char tcon[256];
    unsigned int tclass;
    bool has_query;
};

#define MAX_TRACKED 16
static TrackedFd g_tracked[MAX_TRACKED];
static int g_tracked_count = 0;

static TrackedFd *find_tracked(int fd) {
    for (int i = 0; i < g_tracked_count; ++i)
        if (g_tracked[i].fd == fd) return &g_tracked[i];
    return nullptr;
}

static void track_fd(int fd, FdType type) {
    for (int i = 0; i < g_tracked_count; ++i) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i].type = type;
            g_tracked[i].scon[0] = '\0';
            g_tracked[i].tcon[0] = '\0';
            g_tracked[i].tclass = 0;
            g_tracked[i].has_query = false;
            return;
        }
    }
    if (g_tracked_count >= MAX_TRACKED) { LOGW("track_fd: MAX_TRACKED (%d) exceeded, dropping fd %d", MAX_TRACKED, fd); return; }
    auto *t = &g_tracked[g_tracked_count++];
    t->fd = fd;
    t->type = type;
    t->scon[0] = '\0';
    t->tcon[0] = '\0';
    t->tclass = 0;
    t->has_query = false;
}

static void untrack_fd(int fd) {
    for (int i = 0; i < g_tracked_count; ++i) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i] = g_tracked[--g_tracked_count];
            return;
        }
    }
}

static const char *selinuxfs_name(const char *path) {
    if (strncmp(path, "/sys/fs/selinux/", 16) == 0) return path + 16;
    if (strncmp(path, "/selinux/", 9) == 0)         return path + 9;
    return nullptr;
}

static FdType classify_path(const char *path) {
    if (!path) return FD_NONE;

    const char *name = selinuxfs_name(path);
    if (name) {
        if (strcmp(name, "access") == 0)  return FD_ACCESS;
        if (strcmp(name, "status") == 0)  return FD_STATUS;
        if (strcmp(name, "policy") == 0)  return FD_POLICY;
        if (strcmp(name, "avc/cache_stats") == 0) return FD_AVC_STATS;
        if (strcmp(name, "context") == 0 ||
            strcmp(name, "create") == 0 ||
            strcmp(name, "member") == 0 ||
            strcmp(name, "relabel") == 0 ||
            strcmp(name, "user") == 0 ||
            strcmp(name, "validatetrans") == 0) return FD_CONTEXT;
    }

    if (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/attr/"))
        return FD_CONTEXT;

    return FD_NONE;
}

// ---- access query parsing and response patching -------------------------

static void parse_access_query(TrackedFd *tfd, const char *query) {
    const char *sp1 = strchr(query, ' ');
    if (!sp1) { LOGW("parse_access_query: no first space in '%s'", query); return; }
    size_t len = sp1 - query;
    if (len >= sizeof(tfd->scon)) len = sizeof(tfd->scon) - 1;
    memcpy(tfd->scon, query, len);
    tfd->scon[len] = '\0';

    const char *p = sp1 + 1;
    const char *sp2 = strchr(p, ' ');
    if (!sp2) { LOGW("parse_access_query: no second space in '%s'", query); return; }
    len = sp2 - p;
    if (len >= sizeof(tfd->tcon)) len = sizeof(tfd->tcon) - 1;
    memcpy(tfd->tcon, p, len);
    tfd->tcon[len] = '\0';

    tfd->tclass = (unsigned int)strtoul(sp2 + 1, nullptr, 10);
    tfd->has_query = true;
    LOGD("access query: scon=%s tcon=%s class=%u", tfd->scon, tfd->tcon, tfd->tclass);
}

static ssize_t patch_access_response(TrackedFd *tfd, char *buf,
                                     ssize_t ret, size_t bufsize) {
    if (ret <= 0 || (size_t)ret >= bufsize) return ret;

    char tmp[128];
    if ((size_t)ret >= sizeof(tmp)) return ret;
    memcpy(tmp, buf, ret);
    tmp[ret] = '\0';

    unsigned int allowed, decided, auditallow, auditdeny, flags, seqno;
    if (sscanf(tmp, "%x %x %x %x %u %x",
               &allowed, &decided, &auditallow, &auditdeny, &seqno, &flags) != 6) {
        LOGW("patch_access_response: sscanf failed on '%s'", tmp);
        return ret;
    }

    unsigned int orig_allowed = allowed, orig_auditallow = auditallow;

    for (int i = 0; i < g_hidden_bit_count; ++i) {
        if (g_hidden_bits[i].cls_id == (security_class_t)tfd->tclass) {
            allowed    &= ~g_hidden_bits[i].perm_bit;
            auditallow &= ~g_hidden_bits[i].perm_bit;
        }
    }

    for (int i = 0; i < g_exact_bit_count; ++i) {
        if (g_exact_bits[i].cls_id == (security_class_t)tfd->tclass &&
            strcmp(tfd->scon, g_exact_bits[i].scon) == 0 &&
            strcmp(tfd->tcon, g_exact_bits[i].tcon) == 0) {
            allowed    &= ~g_exact_bits[i].perm_bit;
            auditallow &= ~g_exact_bits[i].perm_bit;
        }
    }

    // Match the kernel's userspace ABI exactly: selinuxfs always reports
    // 0xffffffff in the "decided" slot and seqno 1 on a clean boot.  KernelSU
    // does the same when it re-computes /access against the pre-injection
    // policy (see kernel/feature/selinux_hide.c, my_write_access).
    unsigned int orig_seqno = seqno, orig_decided = decided;
    decided = 0xffffffffu;
    seqno = 1;

    if (allowed != orig_allowed || auditallow != orig_auditallow ||
        orig_seqno != 1 || orig_decided != decided)
        LOGD("patch_access: scon=%s tcon=%s class=%u allowed=0x%x->0x%x auditallow=0x%x->0x%x "
             "decided=0x%x->0x%x seqno=%u->1",
             tfd->scon, tfd->tcon, tfd->tclass, orig_allowed, allowed,
             orig_auditallow, auditallow, orig_decided, decided, orig_seqno);

    int newlen = snprintf(buf, bufsize, "%x %x %x %x %u %x",
                          allowed, decided, auditallow, auditdeny, seqno, flags);
    if (newlen < 0 || (size_t)newlen >= bufsize) { LOGW("patch_access_response: snprintf overflow (%d vs %zu)", newlen, bufsize); return ret; }
    return newlen;
}

// ---- status patching ----------------------------------------------------

static void patch_status(void *buf, ssize_t len) {
    if (len < 20) { LOGW("patch_status: buffer too short (%zd < 20)", len); return; }
    auto *p = (unsigned char *)buf;
    unsigned int seq, pload;
    if (g_new_kernel) {
        seq = 4;  pload = 1;
    } else {
        seq = 0;  pload = 0;
    }
    unsigned int raw_seq, raw_pload;
    memcpy(&raw_seq, p + 4, sizeof(raw_seq));
    memcpy(&raw_pload, p + 12, sizeof(raw_pload));
    memcpy(p + 4,  &seq,   sizeof(seq));
    memcpy(p + 12, &pload, sizeof(pload));
    LOGD("patch_status: seq=%u->%u policyload=%u->%u", raw_seq, seq, raw_pload, pload);
}

// ---- read-side scrubbing ------------------------------------------------

static ssize_t scrub_read_content(int fd, void *buf, ssize_t ret) {
    if (ret <= 0 || !buf) return ret;

    auto *tfd = find_tracked(fd);
    if (tfd && tfd->type == FD_POLICY) {
        stealth::scrub_policy(static_cast<char *>(buf), (size_t)ret);
        return ret;
    }

    // avc/cache_stats is tiny; match on content so fopen-based reads are
    // covered even when the fd was not opened through the PLT hook.
    if ((size_t)ret <= 512 &&
        dsb::mem_contains(buf, (size_t)ret, "lookups hits")) {
        stealth::scrub_avc_stats(static_cast<char *>(buf), (size_t)ret);
    }

    // logcat / removed-event buffers are small; filter leaking AVC records.
    if ((size_t)ret <= 8192) {
        ret = static_cast<ssize_t>(
            avc::filter_buffer(buf, static_cast<size_t>(ret)));
    }
    return ret;
}

// ---- libselinux ABI (defense-in-depth hooks) ----------------------------

struct av_decision {
    access_vector_t allowed;
    access_vector_t decided;
    access_vector_t auditallow;
    access_vector_t auditdeny;
    unsigned int    seqno;
    unsigned int    flags;
};

static inline void mask_hidden_bits(security_class_t tclass, av_decision *avd) {
    if (!avd) return;
    for (int i = 0; i < g_hidden_bit_count; ++i) {
        if (g_hidden_bits[i].cls_id == tclass) {
            avd->allowed    &= ~g_hidden_bits[i].perm_bit;
            avd->auditallow &= ~g_hidden_bits[i].perm_bit;
        }
    }
}

static inline void mask_exact_bits(const char *scon, const char *tcon,
                                   security_class_t tclass, av_decision *avd) {
    if (!avd || !scon || !tcon) return;
    for (int i = 0; i < g_exact_bit_count; ++i) {
        if (g_exact_bits[i].cls_id == tclass &&
            strcmp(scon, g_exact_bits[i].scon) == 0 &&
            strcmp(tcon, g_exact_bits[i].tcon) == 0) {
            avd->allowed    &= ~g_exact_bits[i].perm_bit;
            avd->auditallow &= ~g_exact_bits[i].perm_bit;
        }
    }
}

static void fake_deny(av_decision *avd) {
    if (!avd) return;
    avd->allowed    = 0;
    avd->decided    = ~0u;
    avd->auditallow = 0;
    avd->auditdeny  = ~0u;
    avd->seqno      = 1;
    avd->flags      = 0;
}

static int (*orig_security_compute_av)(const char *, const char *,
                                       security_class_t, access_vector_t,
                                       av_decision *) = nullptr;
static int (*orig_security_compute_av_flags)(const char *, const char *,
                                             security_class_t, access_vector_t,
                                             av_decision *) = nullptr;
static int (*orig_selinux_check_access)(const char *, const char *,
                                        const char *, const char *,
                                        void *) = nullptr;

static int my_security_compute_av(const char *scon, const char *tcon,
                                  security_class_t tclass,
                                  access_vector_t requested,
                                  av_decision *avd) {
    if (is_hidden(scon) || is_hidden(tcon)) {
        LOGD("compute_av: fake deny for hidden scon=%s tcon=%s", scon ? scon : "(null)", tcon ? tcon : "(null)");
        fake_deny(avd);
        return 0;
    }
    if (!orig_security_compute_av) { LOGW("compute_av: orig is null"); errno = ENOSYS; return -1; }
    int r = orig_security_compute_av(scon, tcon, tclass, requested, avd);
    if (r == 0) {
        unsigned int pre = avd ? avd->allowed : 0;
        mask_hidden_bits(tclass, avd);
        mask_exact_bits(scon, tcon, tclass, avd);
        if (avd) {
            if (avd->allowed != pre)
                LOGD("compute_av: masked scon=%s tcon=%s class=%u allowed=0x%x->0x%x", scon, tcon, tclass, pre, avd->allowed);
            avd->seqno = 1;
        }
    }
    return r;
}

static int my_security_compute_av_flags(const char *scon, const char *tcon,
                                        security_class_t tclass,
                                        access_vector_t requested,
                                        av_decision *avd) {
    if (is_hidden(scon) || is_hidden(tcon)) {
        LOGD("compute_av_flags: fake deny for hidden scon=%s tcon=%s", scon ? scon : "(null)", tcon ? tcon : "(null)");
        fake_deny(avd);
        return 0;
    }
    if (!orig_security_compute_av_flags) { LOGW("compute_av_flags: orig is null"); errno = ENOSYS; return -1; }
    int r = orig_security_compute_av_flags(scon, tcon, tclass, requested, avd);
    if (r == 0) {
        unsigned int pre = avd ? avd->allowed : 0;
        mask_hidden_bits(tclass, avd);
        mask_exact_bits(scon, tcon, tclass, avd);
        if (avd) {
            if (avd->allowed != pre)
                LOGD("compute_av_flags: masked scon=%s tcon=%s class=%u allowed=0x%x->0x%x", scon, tcon, tclass, pre, avd->allowed);
            avd->seqno = 1;
        }
    }
    return r;
}

static int my_selinux_check_access(const char *scon, const char *tcon,
                                   const char *tclass, const char *perm,
                                   void *auditdata) {
    if (is_hidden(scon) || is_hidden(tcon) || is_hidden_perm(perm) ||
        is_hidden_exact(scon, tcon, tclass, perm)) {
        LOGD("check_access: denied %s -> %s [%s:%s]", scon ? scon : "(null)", tcon ? tcon : "(null)", tclass ? tclass : "(null)", perm ? perm : "(null)");
        errno = EACCES;
        return -1;
    }
    if (orig_selinux_check_access)
        return orig_selinux_check_access(scon, tcon, tclass, perm, auditdata);
    LOGW("check_access: orig is null");
    errno = ENOSYS;
    return -1;
}

// ---- file I/O hooks -----------------------------------------------------

static int     (*orig_open)(const char *, int, ...) = nullptr;
static int     (*orig_open64)(const char *, int, ...) = nullptr;
static int     (*orig_openat)(int, const char *, int, ...) = nullptr;
static int     (*orig_openat64)(int, const char *, int, ...) = nullptr;
static ssize_t (*orig_write)(int, const void *, size_t) = nullptr;
static ssize_t (*orig_read)(int, void *, size_t) = nullptr;
static ssize_t (*orig_pread64)(int, void *, size_t, off64_t) = nullptr;
static int     (*orig_close)(int) = nullptr;
static void   *(*orig_mmap)(void *, size_t, int, int, int, off_t) = nullptr;
static void   *(*orig_mmap64)(void *, size_t, int, int, int, off64_t) = nullptr;

#ifdef DEBUG
static const char *fdtype_str(FdType t) {
    switch (t) {
        case FD_CONTEXT:   return "context";
        case FD_ACCESS:    return "access";
        case FD_STATUS:    return "status";
        case FD_POLICY:    return "policy";
        case FD_AVC_STATS: return "avc";
        default:           return "none";
    }
}
#endif

static void track_if_needed(int fd, const char *pathname) {
    if (fd < 0) return;
    FdType type = classify_path(pathname);
    if (type != FD_NONE) {
        track_fd(fd, type);
        LOGD("open: tracking fd=%d type=%s path=%s", fd, fdtype_str(type), pathname);
    }
}

// Only a plain read-only open can be replaced by a memfd: handing one back for
// O_PATH / O_DIRECTORY / O_WRONLY / O_RDWR would break callers that fstat,
// openat(AT_EMPTY_PATH) or write through the descriptor.
static bool virtualizable(int flags) {
    return (flags & (O_WRONLY | O_RDWR | O_PATH | O_DIRECTORY | O_CREAT |
                     O_TRUNC | O_APPEND)) == 0;
}

static int my_open(const char *pathname, int flags, mode_t mode) {
    if (virtualizable(flags)) {
        int virtual_fd = stealth::open_virtual(pathname);
        if (virtual_fd >= 0) return virtual_fd;
    }

    int fd = orig_open ? orig_open(pathname, flags, mode) : -1;
    track_if_needed(fd, pathname);
    return fd;
}

static int my_open64(const char *pathname, int flags, mode_t mode) {
    if (virtualizable(flags)) {
        int virtual_fd = stealth::open_virtual(pathname);
        if (virtual_fd >= 0) return virtual_fd;
    }

    int fd;
    if (orig_open64)             fd = orig_open64(pathname, flags, mode);
    else if (orig_open)          fd = orig_open(pathname, flags, mode);
    else                         fd = -1;
    track_if_needed(fd, pathname);
    return fd;
}

static int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (virtualizable(flags)) {
        int virtual_fd = stealth::open_virtual(pathname);
        if (virtual_fd >= 0) return virtual_fd;
    }

    int fd = orig_openat ? orig_openat(dirfd, pathname, flags, mode) : -1;
    track_if_needed(fd, pathname);
    return fd;
}

static int my_openat64(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (virtualizable(flags)) {
        int virtual_fd = stealth::open_virtual(pathname);
        if (virtual_fd >= 0) return virtual_fd;
    }

    int fd;
    if (orig_openat64)           fd = orig_openat64(dirfd, pathname, flags, mode);
    else if (orig_openat)        fd = orig_openat(dirfd, pathname, flags, mode);
    else                         fd = -1;
    track_if_needed(fd, pathname);
    return fd;
}

static ssize_t my_write(int fd, const void *buf, size_t count) {
    if (g_tracked_count > 0 && buf && count > 0 && count < 512) {
        auto *tfd = find_tracked(fd);
        if (tfd) {
            char tmp[512];
            memcpy(tmp, buf, count);
            tmp[count] = '\0';

            if (tfd->type == FD_CONTEXT || tfd->type == FD_ACCESS) {
                if (is_hidden(tmp)) {
                    LOGD("write: blocked hidden context on fd=%d type=%s content='%s'", fd, fdtype_str(tfd->type), tmp);
                    errno = EINVAL;
                    return -1;
                }
            }

            if (tfd->type == FD_ACCESS)
                parse_access_query(tfd, tmp);
        }
    }
    if (!orig_write) { errno = ENOSYS; return -1; }
    return orig_write(fd, buf, count);
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    if (!orig_read) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_read(fd, buf, count);
    if (ret <= 0) return ret;

    auto *tfd = find_tracked(fd);
    if (tfd) {
        if (tfd->type == FD_ACCESS && tfd->has_query) {
            ret = patch_access_response(tfd, (char *)buf, ret, count);
            tfd->has_query = false;
        } else if (tfd->type == FD_STATUS) {
            patch_status(buf, ret);
        }
    }

    return scrub_read_content(fd, buf, ret);
}

static ssize_t my_pread64(int fd, void *buf, size_t count, off64_t offset) {
    if (!orig_pread64) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_pread64(fd, buf, count, offset);
    if (ret <= 0) return ret;

    auto *tfd = find_tracked(fd);
    if (tfd) {
        if (tfd->type == FD_ACCESS && tfd->has_query) {
            ret = patch_access_response(tfd, (char *)buf, ret, count);
            tfd->has_query = false;
        } else if (tfd->type == FD_STATUS) {
            patch_status(buf, ret);
        }
    }

    return scrub_read_content(fd, buf, ret);
}

static int my_close(int fd) {
    if (g_tracked_count > 0)
        untrack_fd(fd);
    return orig_close ? orig_close(fd) : -1;
}

// Duck-Detector mmaps /sys/fs/selinux/status looking for a second page with
// writable permissions. Refuse mmap for status fds instead of handing out a
// doctored mapping. Fds opened through libc's internal helpers are not tracked,
// so verify the fd target with a raw readlinkat as a fallback.
static bool fd_is_selinux_status(int fd) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    char target[256];
#ifdef __NR_readlinkat
    long n = syscall(__NR_readlinkat, AT_FDCWD, link, target, sizeof(target) - 1);
#else
    long n = syscall(__NR_readlink, link, target, sizeof(target) - 1);
#endif
    if (n <= 0) return false;
    target[n] = '\0';
    return strstr(target, "selinux/status") != nullptr;
}

static void *my_mmap(void *addr, size_t len, int prot, int flags, int fd,
                     off_t offset) {
    if (g_tracked_count > 0) {
        auto *tfd = find_tracked(fd);
        if (tfd && tfd->type == FD_STATUS) {
            errno = EACCES;
            return MAP_FAILED;
        }
    }
    if (fd >= 0 && len <= 8192 && fd_is_selinux_status(fd)) {
        errno = EACCES;
        return MAP_FAILED;
    }
    if (!orig_mmap) { errno = ENOSYS; return MAP_FAILED; }
    return orig_mmap(addr, len, prot, flags, fd, offset);
}

static void *my_mmap64(void *addr, size_t len, int prot, int flags, int fd,
                        off64_t offset) {
    if (g_tracked_count > 0) {
        auto *tfd = find_tracked(fd);
        if (tfd && tfd->type == FD_STATUS) {
            errno = EACCES;
            return MAP_FAILED;
        }
    }
    if (fd >= 0 && len <= 8192 && fd_is_selinux_status(fd)) {
        errno = EACCES;
        return MAP_FAILED;
    }
    if (orig_mmap64) return orig_mmap64(addr, len, prot, flags, fd, offset);
    if (!orig_mmap) { errno = ENOSYS; return MAP_FAILED; }
    return orig_mmap(addr, len, prot, flags, fd, static_cast<off_t>(offset));
}

// ---- map walking --------------------------------------------------------
//
// Zygisk providers keep their pending-PLT-hook list in a fixed-size table.  A
// stock app maps well over a hundred `.so` files and *each file shows up as
// three or four maps segments*, so registering a hook for every maps line
// explodes into thousands of records -- enough to overflow that table and take
// the whole Zygisk runtime (zygote injection) down with it.  Only the
// libraries that actually host the probes are registered, and each (dev, ino)
// is visited once:
//   * libjavacore / libandroid_runtime: every Java-side file, stat, readlink,
//     getenv and log call (FileInputStream, Os.stat, Runtime.exec plumbing),
//   * libselinux / libnativehelper: direct SELinux API calls,
//   * anything loaded from the app's own lib dir (native detectors).
#define MAX_HOOK_LIBS  24
#define MAX_HOOK_CALLS 320

static bool lib_wanted(const char *path) {
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    static const char *const kLibs[] = {
        "libjavacore.so", "libandroid_runtime.so", "libselinux.so",
        "libnativehelper.so", nullptr,
    };
    for (int i = 0; kLibs[i]; ++i)
        if (strcmp(base, kLibs[i]) == 0) return true;
    return strstr(path, "/data/app/") != nullptr;
}

struct HookLib { dev_t dev; ino_t ino; };

static int register_against_all_libs(zygisk::Api *api, bool guard) {
    FILE *fp = fopen("/proc/self/maps", "re");
    if (!fp) {
        LOGW("fopen(/proc/self/maps) failed: %s", strerror(errno));
        return 0;
    }
    HookLib seen[MAX_HOOK_LIBS];
    int seen_n = 0, calls = 0, n = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        size_t len = strlen(path);
        if (path[len - 1] == '\n') { path[len - 1] = '\0'; len--; }
        if (len < 4) continue;
        if (strcmp(path + len - 3, ".so") != 0) continue;
        if (strstr(path, "(deleted)") != nullptr) continue;
        if (!lib_wanted(path)) continue;

        struct stat st;
        if (stat(path, &st) != 0) { LOGD("register: stat(%s) failed: %s", path, strerror(errno)); continue; }

        bool dup = false;
        for (int i = 0; i < seen_n; ++i) {
            if (seen[i].dev == st.st_dev && seen[i].ino == st.st_ino) { dup = true; break; }
        }
        if (dup) continue;
        if (seen_n >= MAX_HOOK_LIBS) { LOGW("register: lib budget reached (%d)", seen_n); break; }
        seen[seen_n].dev = st.st_dev;
        seen[seen_n].ino = st.st_ino;
        ++seen_n;

        auto hook = [&](const char *sym, void *fn, void **old) {
            if (calls >= MAX_HOOK_CALLS) return;
            api->pltHookRegister(st.st_dev, st.st_ino, sym, fn, old);
            ++calls;
        };

        if (guard) {
            // Dumpable spoof.  These sit on hot paths, so they are only
            // registered for processes that can actually need them (ordinary,
            // non-debuggable apps) and the wrappers forward untouched unless
            // guard_process() really cleared PR_SET_DUMPABLE.
            hook("prctl",     (void *)stealth::my_prctl,     (void **)&stealth::orig_prctl);
            hook("syscall",   (void *)stealth::my_syscall,   (void **)&stealth::orig_syscall);
            hook("stat",      (void *)stealth::my_stat,      (void **)&stealth::orig_stat);
            hook("lstat",     (void *)stealth::my_lstat,     (void **)&stealth::orig_lstat);
            hook("fstat",     (void *)stealth::my_fstat,     (void **)&stealth::orig_fstat);
            hook("fstatat",   (void *)stealth::my_fstatat,   (void **)&stealth::orig_fstatat);
            hook("statx",     (void *)stealth::my_statx,     (void **)&stealth::orig_statx);
#ifdef DSB_HAVE_STAT64
            hook("stat64",    (void *)stealth::my_stat64,    (void **)&stealth::orig_stat64);
            hook("lstat64",   (void *)stealth::my_lstat64,   (void **)&stealth::orig_lstat64);
            hook("fstat64",   (void *)stealth::my_fstat64,   (void **)&stealth::orig_fstat64);
            hook("fstatat64", (void *)stealth::my_fstatat64, (void **)&stealth::orig_fstatat64);
#endif
        }

        hook("open",      (void *)my_open,           (void **)&orig_open);
        hook("open64",    (void *)my_open64,         (void **)&orig_open64);
        hook("openat",    (void *)my_openat,         (void **)&orig_openat);
        hook("openat64",  (void *)my_openat64,       (void **)&orig_openat64);
        hook("write",     (void *)my_write,          (void **)&orig_write);
        hook("read",      (void *)my_read,           (void **)&orig_read);
        hook("pread64",   (void *)my_pread64,        (void **)&orig_pread64);
        hook("close",     (void *)my_close,          (void **)&orig_close);
        hook("mmap",      (void *)my_mmap,           (void **)&orig_mmap);
        hook("mmap64",    (void *)my_mmap64,         (void **)&orig_mmap64);

        hook("fopen",     (void *)stealth::my_fopen,     (void **)&stealth::orig_fopen);
        hook("fopen64",   (void *)stealth::my_fopen64,   (void **)&stealth::orig_fopen64);
        hook("readlink",  (void *)stealth::my_readlink,  (void **)&stealth::orig_readlink);
        hook("readlinkat", (void *)stealth::my_readlinkat, (void **)&stealth::orig_readlinkat);
        hook("getenv",    (void *)stealth::my_getenv,    (void **)&stealth::orig_getenv);
        hook("secure_getenv", (void *)stealth::my_secure_getenv, (void **)&stealth::orig_secure_getenv);
        hook("dl_iterate_phdr", (void *)stealth::my_dl_iterate_phdr,
             (void **)&stealth::orig_dl_iterate_phdr);

        hook("__android_log_write",     (void *)avc::my_log_write,     (void **)&avc::orig_log_write);
        hook("__android_log_buf_write", (void *)avc::my_log_buf_write, (void **)&avc::orig_log_buf_write);
        hook("__android_log_print",     (void *)avc::my_log_print,     (void **)&avc::orig_log_print);
        hook("__android_log_vprint",    (void *)avc::my_log_vprint,    (void **)&avc::orig_log_vprint);

        hook("security_compute_av",
             (void *)my_security_compute_av,
             (void **)&orig_security_compute_av);
        hook("security_compute_av_flags",
             (void *)my_security_compute_av_flags,
             (void **)&orig_security_compute_av_flags);
        hook("selinux_check_access",
             (void *)my_selinux_check_access,
             (void **)&orig_selinux_check_access);
        ++n;
    }
    fclose(fp);
    if (calls >= MAX_HOOK_CALLS) LOGW("register: hook budget reached (%d calls)", calls);
    return n;
}

// A pltHookRegister() that did not find the symbol leaves the "old" pointer
// untouched.  Some providers also commit asynchronously, so re-resolve any
// still-null slot from the global scope: a wrapper that hands back ENOSYS for
// read()/openat() would break every app instead of staying transparent.
struct SymSlot { const char *name; void **slot; };

static void fill_missing_orig() {
    static SymSlot slots[] = {
        {"open",                       (void **)&orig_open},
        {"open64",                     (void **)&orig_open64},
        {"openat",                     (void **)&orig_openat},
        {"openat64",                   (void **)&orig_openat64},
        {"write",                      (void **)&orig_write},
        {"read",                       (void **)&orig_read},
        {"pread64",                    (void **)&orig_pread64},
        {"close",                      (void **)&orig_close},
        {"mmap",                       (void **)&orig_mmap},
        {"mmap64",                     (void **)&orig_mmap64},
        {"fopen",                      (void **)&stealth::orig_fopen},
        {"fopen64",                    (void **)&stealth::orig_fopen64},
        {"readlink",                   (void **)&stealth::orig_readlink},
        {"readlinkat",                 (void **)&stealth::orig_readlinkat},
        {"getenv",                     (void **)&stealth::orig_getenv},
        {"secure_getenv",              (void **)&stealth::orig_secure_getenv},
        {"dl_iterate_phdr",            (void **)&stealth::orig_dl_iterate_phdr},
        {"prctl",                      (void **)&stealth::orig_prctl},
        {"syscall",                    (void **)&stealth::orig_syscall},
        {"stat",                       (void **)&stealth::orig_stat},
        {"lstat",                      (void **)&stealth::orig_lstat},
        {"fstat",                      (void **)&stealth::orig_fstat},
        {"fstatat",                    (void **)&stealth::orig_fstatat},
        {"statx",                      (void **)&stealth::orig_statx},
#ifdef DSB_HAVE_STAT64
        {"stat64",                     (void **)&stealth::orig_stat64},
        {"lstat64",                    (void **)&stealth::orig_lstat64},
        {"fstat64",                    (void **)&stealth::orig_fstat64},
        {"fstatat64",                  (void **)&stealth::orig_fstatat64},
#endif
        {"__android_log_write",        (void **)&avc::orig_log_write},
        {"__android_log_buf_write",    (void **)&avc::orig_log_buf_write},
        {"__android_log_print",        (void **)&avc::orig_log_print},
        {"__android_log_vprint",       (void **)&avc::orig_log_vprint},
        {"security_compute_av",        (void **)&orig_security_compute_av},
        {"security_compute_av_flags",  (void **)&orig_security_compute_av_flags},
        {"selinux_check_access",       (void **)&orig_selinux_check_access},
        {nullptr, nullptr},
    };
    for (int i = 0; slots[i].name; ++i) {
        if (*slots[i].slot) continue;
        *slots[i].slot = dlsym(RTLD_DEFAULT, slots[i].name);
    }
}

// ---- Zygisk module ------------------------------------------------------

class DirtySepBypass : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        // One line per boot.  If zygote dies without it, the failure is in the
        // Zygisk provider's loader rather than in our callbacks.
        LOGI("module loaded into pid %d", getpid());
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args) return;
        // Only ordinary, non-root apps get the scrubbed view.  Root-granted
        // apps keep the real /data/adb mappings and linker solist, so root
        // tooling keeps working.
        bool ordinary = args->uid >= 10000 &&
                        !(api->getFlags() & zygisk::PROCESS_GRANTED_ROOT);
        // Leave debuggable apps alone: native/JDWP debuggers need ptrace.
        bool debuggable = (args->runtime_flags & 0x1) != 0;
        proc_guard = ordinary && !debuggable;
        install("app", ordinary);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        // Must run after SpecializeCommon: its setresuid / PR_SET_DUMPABLE
        // calls would overwrite a flag cleared in preAppSpecialize.  The spoof
        // hooks are already in place; they start rewriting only once
        // guard_process() reports that it really changed the flag.
        if (proc_guard && stealth::guard_process())
            LOGI("cleared PR_SET_DUMPABLE for pid %d", getpid());
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        // App zygotes (uid >= 10000) host DirtySepolicy's probes, so they get
        // the hooks.  system_server (uid 1000) is deliberately left untouched:
        // it maps the largest library set and a single bad hook there takes
        // down system_server, which in turn kills zygote and the whole boot.
        if (!args || args->uid < 10000) return;
        install("app-zygote", true);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv      *env = nullptr;
    bool         proc_guard = false;

    void install(const char *who, bool app_process) {
        stealth::set_app_mode(app_process);
        detect_kernel_version();
        resolve_hidden_bits();
        // Base hooks and (when needed) the dumpable spoof go into one batch: a
        // second pltHookCommit() is not portable across Zygisk providers.
        int n = register_against_all_libs(api, proc_guard);
        bool committed = api->pltHookCommit();
        // pltHookRegister() leaves "old" untouched when it cannot resolve a
        // symbol; a wrapper that hands back ENOSYS for read()/openat() would
        // break every app, so fill the gaps from the global scope.
        fill_missing_orig();
        if (n == 0) {
            LOGW("[%s] no .so libs found to hook", who);
            return;
        }
        if (!committed) {
            LOGW("[%s] pltHookCommit failed after registering %d libs", who, n);
        } else {
            LOGI("[%s] hooks committed across %d libs", who, n);
        }
    }
};

REGISTER_ZYGISK_MODULE(DirtySepBypass)
