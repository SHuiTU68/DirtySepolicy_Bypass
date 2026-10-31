// Userspace stealth for the DirtySepolicy Bypass module.
//
// Everything here runs inside a forked app/system_server process that already
// has the Zygisk module library mapped.  The goal is that a normal (non-root)
// app cannot tell the difference between a clean process and one carrying the
// module: the module library must not appear in linker solists, maps/smaps,
// fd targets, thread names or environment variables.

#include "stealth.h"
#include "rules.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif

#ifndef __NR_memfd_create
#if defined(__aarch64__)
#define __NR_memfd_create 319
#elif defined(__arm__)
#define __NR_memfd_create 356
#elif defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__i386__)
#define __NR_memfd_create 356
#endif
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace stealth {

FILE    *(*orig_fopen)(const char *, const char *) = nullptr;
FILE    *(*orig_fopen64)(const char *, const char *) = nullptr;
ssize_t  (*orig_readlink)(const char *, char *, size_t) = nullptr;
ssize_t  (*orig_readlinkat)(int, const char *, char *, size_t) = nullptr;
char    *(*orig_getenv)(const char *) = nullptr;
char    *(*orig_secure_getenv)(const char *) = nullptr;
int      (*orig_dl_iterate_phdr)(int (*)(struct dl_phdr_info *, size_t, void *), void *) = nullptr;
int      (*orig_prctl)(int, ...) = nullptr;
long     (*orig_syscall)(long, ...) = nullptr;
int      (*orig_stat)(const char *, struct stat *) = nullptr;
int      (*orig_lstat)(const char *, struct stat *) = nullptr;
int      (*orig_fstat)(int, struct stat *) = nullptr;
int      (*orig_fstatat)(int, const char *, struct stat *, int) = nullptr;
int      (*orig_statx)(int, const char *, int, unsigned int, void *) = nullptr;
#ifdef DSB_HAVE_STAT64
int      (*orig_stat64)(const char *, struct stat64 *) = nullptr;
int      (*orig_lstat64)(const char *, struct stat64 *) = nullptr;
int      (*orig_fstat64)(int, struct stat64 *) = nullptr;
int      (*orig_fstatat64)(int, const char *, struct stat64 *, int) = nullptr;
#endif

// External linkage on purpose: read by open_virtual(), written by the Zygisk
// specialization callbacks.
bool g_app_mode = false;

void set_app_mode(bool app) { g_app_mode = app; }

// ---- raw syscalls (never routed through the PLT hooks) -------------------

static int raw_open_ro(const char *path) {
#ifdef __NR_openat
    return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path,
                                    O_RDONLY | O_CLOEXEC, 0));
#else
    return static_cast<int>(syscall(__NR_open, path, O_RDONLY | O_CLOEXEC));
#endif
}

static ssize_t raw_read(int fd, void *buf, size_t n) {
    return static_cast<ssize_t>(syscall(__NR_read, fd, buf, n));
}

static ssize_t raw_write(int fd, const void *buf, size_t n) {
    return static_cast<ssize_t>(syscall(__NR_write, fd, buf, n));
}

static int raw_close(int fd) {
    return static_cast<int>(syscall(__NR_close, fd));
}

static off_t raw_lseek(int fd, off_t off, int whence) {
    return static_cast<off_t>(syscall(__NR_lseek, fd, off, whence));
}

// ---- file helpers --------------------------------------------------------

static char *read_whole(const char *path, size_t *out_len, size_t max_size) {
    int fd = raw_open_ro(path);
    if (fd < 0) return nullptr;

    size_t cap = 4096, len = 0;
    char *buf = static_cast<char *>(malloc(cap));
    if (!buf) { raw_close(fd); return nullptr; }

    while (len < max_size) {
        if (len == cap) {
            if (cap >= max_size) break;
            size_t ncap = cap * 2;
            if (ncap > max_size) ncap = max_size;
            char *nb = static_cast<char *>(realloc(buf, ncap));
            if (!nb) break;
            buf = nb;
            cap = ncap;
        }
        ssize_t n = raw_read(fd, buf + len, cap - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        len += static_cast<size_t>(n);
    }
    raw_close(fd);

    // Keep a little head room so a scrubber may grow a few bytes (thread
    // name replacement in stat/sched).
    if (len && cap < len + 64) {
        char *nb = static_cast<char *>(realloc(buf, len + 64));
        if (nb) buf = nb;
    }
    *out_len = len;
    return buf;
}

static int memfd_from(const char *name, const char *data, size_t len) {
#ifdef __NR_memfd_create
    int fd = static_cast<int>(syscall(__NR_memfd_create, name, MFD_CLOEXEC));
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = raw_write(fd, data + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            raw_close(fd);
            return -1;
        }
        off += static_cast<size_t>(n);
    }
    raw_lseek(fd, 0, SEEK_SET);
    return fd;
#else
    (void)name; (void)data; (void)len;
    return -1;
#endif
}

// ---- guarded paths -------------------------------------------------------

static bool is_cache_stats(const char *p) {
    return p && strstr(p, "/avc/cache_stats") != nullptr;
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

// Accepts /proc/self/..., /proc/thread-self/... and /proc/<own-pid>/...
// (including /proc/<pid>/task/<tid>/...).  Detectors routinely substitute the
// literal pid for "self" to dodge naive string matching, and /proc/thread-self
// is another alias.  Returns the leaf name, or nullptr when the path is not
// this process.
static const char *proc_self_suffix(const char *p) {
    if (!p) return nullptr;
    const char *rest = nullptr;

    if (strncmp(p, "/proc/self/", 11) == 0) {
        rest = p + 11;
    } else if (strncmp(p, "/proc/thread-self/", 18) == 0) {
        rest = p + 18;
    } else if (strncmp(p, "/proc/", 6) == 0) {
        const char *q = p + 6;
        const char *digits = q;
        long pid = 0;
        while (is_digit(*q)) { pid = pid * 10 + (*q - '0'); ++q; }
        if (q == digits || *q != '/') return nullptr;
        if (pid != static_cast<long>(getpid())) return nullptr;
        rest = q + 1;
    } else {
        return nullptr;
    }

    if (strncmp(rest, "task/", 5) == 0) {
        const char *slash = strchr(rest + 5, '/');
        if (!slash) return nullptr;
        rest = slash + 1;
    }
    return rest;
}

enum VirtualKind {
    VK_NONE = 0,
    VK_TEXT,   // line-oriented: maps, status, mountinfo, ...
    VK_ENV,    // NUL-separated environ
    VK_STAT,   // one-line pid (comm) ... / sched
    VK_AVC,    // avc/cache_stats counters
};

static VirtualKind classify_virtual(const char *p) {
    if (!p) return VK_NONE;
    if (is_cache_stats(p)) return VK_AVC;

    const char *leaf = proc_self_suffix(p);
    if (!leaf || !*leaf) return VK_NONE;

    if (strcmp(leaf, "environ") == 0) return VK_ENV;
    if (strcmp(leaf, "stat") == 0 || strcmp(leaf, "sched") == 0)
        return VK_STAT;
    if (strcmp(leaf, "maps") == 0 || strcmp(leaf, "smaps") == 0 ||
        strcmp(leaf, "smaps_rollup") == 0 || strcmp(leaf, "status") == 0 ||
        strcmp(leaf, "comm") == 0 || strcmp(leaf, "mountinfo") == 0 ||
        strcmp(leaf, "mounts") == 0 || strcmp(leaf, "mountstats") == 0)
        return VK_TEXT;
    return VK_NONE;
}

// ---- text scrubbing ------------------------------------------------------

static bool hidden_env_name(const char *name) {
    if (!name) return false;
    static const char *const kNames[] = {
        "tmp_path", "magisk", "zygisk", "ksu", "kernelsu", "apatch",
        "lsposed", "xposed", "riru", "shamiko", "supolicy", "adbroot",
        nullptr,
    };
    static const char *const kPrefixes[] = {
        "magisk_", "zygisk_", "ksu_", "kernelsu_", "apatch_", "lsposed_",
        "xposed_", "riru_", "shamiko_", "supolicy_", "adbroot_",
        nullptr,
    };
    char lower[64];
    dsb::lower_copy(lower, name, sizeof(lower));
    for (int i = 0; kNames[i]; ++i)
        if (strcmp(lower, kNames[i]) == 0) return true;
    for (int i = 0; kPrefixes[i]; ++i)
        if (strncmp(lower, kPrefixes[i], strlen(kPrefixes[i])) == 0)
            return true;
    return false;
}

static bool line_is_restricted(const char *line, size_t len) {
    if (len == 0) return false;
    char tmp[512];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, line, n);
    tmp[n] = '\0';
    if (dsb::restricted_path(tmp)) return true;
    if (dsb::deleted_shared_object(tmp)) return true;
    return false;
}

static bool line_is_hidden_comm(const char *line, size_t len) {
    // Plain comm payload (no "Name:" prefix) or "Name:\t<comm>".
    char tmp[128];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, line, n);
    tmp[n] = '\0';
    size_t off = 0;
    while (off < n && (tmp[off] == ' ' || tmp[off] == '\t')) ++off;
    return dsb::hidden_buffer(tmp, n) || dsb::suspicious_actor(tmp + off);
}

static size_t emit_line(char *dst, size_t out, const char *text, size_t len) {
    memmove(dst + out, text, len);
    return out + len;
}

size_t scrub_text(char *buf, size_t len) {
    if (!buf || len == 0) return 0;

    size_t out = 0, i = 0;
    while (i < len) {
        size_t end = i;
        while (end < len && buf[end] != '\n') ++end;
        size_t line_len = end - i;
        size_t line_end = (end < len) ? end + 1 : end;

        // Rewrite the tracer pid instead of dropping the whole line.
        const char *line = buf + i;
        if (line_len >= 9 && memcmp(line, "TracerPid", 9) == 0) {
            static const char kZero[] = "TracerPid:\t0\n";
            out = emit_line(buf, out, kZero, sizeof(kZero) - 1);
            i = line_end;
            continue;
        }

        // Rename a thread/process that would expose the framework.
        if (line_len >= 5 && memcmp(line, "Name:", 5) == 0 &&
            line_is_hidden_comm(line + 5, line_len - 5)) {
            static const char kName[] = "Name:\tzygote64\n";
            out = emit_line(buf, out, kName, sizeof(kName) - 1);
            i = line_end;
            continue;
        }

        if (line_is_restricted(line, line_len)) {  // drop entirely
            i = line_end;
            continue;
        }

        // Bare comm file: replace the whole payload when it leaks.
        if (!memchr(line, ':', line_len) && line_is_hidden_comm(line, line_len)) {
            static const char kComm[] = "zygote64";
            out = emit_line(buf, out, kComm, sizeof(kComm) - 1);
            i = line_end;
            continue;
        }

        if (out != i) memmove(buf + out, line, line_end - i);
        out += line_end - i;
        i = line_end;
    }

    if (out < len) buf[out] = '\0';
    return out;
}

// /proc/self/environ is NUL-separated, not newline-separated.
size_t scrub_environ(char *buf, size_t len) {
    if (!buf || len == 0) return 0;

    size_t out = 0, i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && buf[j] != '\0') ++j;
        size_t entry_len = j - i;

        if (entry_len == 0) {  // separator / trailing NUL
            i = j + 1;
            continue;
        }

        bool drop = false;
        size_t eq = 0;
        while (eq < entry_len && buf[i + eq] != '=') ++eq;
        if (eq < entry_len) {
            char name[64];
            size_t n = eq < sizeof(name) - 1 ? eq : sizeof(name) - 1;
            memcpy(name, buf + i, n);
            name[n] = '\0';
            drop = hidden_env_name(name) ||
                   line_is_restricted(buf + i + eq + 1, entry_len - eq - 1);
        }

        if (!drop) {
            if (out != i) memmove(buf + out, buf + i, entry_len);
            out += entry_len;
            buf[out++] = '\0';
        }
        i = j + 1;
    }

    if (out == 0 && len > 0) { buf[0] = '\0'; out = 1; }
    return out;
}

// /proc/[pid]/stat: "pid (comm) state ..."  /proc/[pid]/sched: "comm (tid, ...)"
size_t scrub_stat(char *buf, size_t len) {
    if (!buf || len == 0) return len;

    const char *open_p = static_cast<const char *>(memchr(buf, '(', len));
    if (!open_p) return len;
    size_t start = static_cast<size_t>(open_p - buf) + 1;

    // stat is "pid (comm) ...", sched is "comm (tid, ...)".  If the text
    // before '(' is not a pid, the comm lives there instead.
    size_t pre = start - 1;
    while (pre > 0 && (buf[pre - 1] == ' ' || buf[pre - 1] == '\t')) --pre;
    bool pid_prefix = true;
    for (size_t k = 0; k < pre; ++k) {
        if (!is_digit(buf[k])) { pid_prefix = false; break; }
    }
    if (!pid_prefix) {
        char scomm[64];
        size_t cn = pre < sizeof(scomm) - 1 ? pre : sizeof(scomm) - 1;
        memcpy(scomm, buf, cn);
        scomm[cn] = '\0';
        if (!line_is_hidden_comm(scomm, cn)) return len;

        static const char kNew0[] = "zygote64";
        const size_t nlen0 = sizeof(kNew0) - 1;
        const size_t tail0 = len - pre;
        const size_t outlen0 = nlen0 + tail0;
        if (outlen0 > len + 64) return len;
        memmove(buf + nlen0, buf + pre, tail0);
        memcpy(buf, kNew0, nlen0);
        return outlen0;
    }

    size_t limit = len;
    const char *nl = static_cast<const char *>(memchr(buf, '\n', len));
    if (nl) limit = static_cast<size_t>(nl - buf);

    size_t end = start;
    for (size_t k = limit; k > start; --k) {
        if (buf[k - 1] == ')') { end = k - 1; break; }
    }
    if (end <= start) return len;

    char comm[64];
    size_t n = end - start;
    if (n >= sizeof(comm)) n = sizeof(comm) - 1;
    memcpy(comm, buf + start, n);
    comm[n] = '\0';
    if (!line_is_hidden_comm(comm, n)) return len;

    static const char kNew[] = "zygote64";
    const size_t newlen = sizeof(kNew) - 1;
    const size_t tail = len - end;
    const size_t outlen = start + newlen + tail;
    if (outlen > len + 64) return len;  // no head room: leave untouched

    if (newlen != n) memmove(buf + start + newlen, buf + end, tail);
    memcpy(buf + start, kNew, newlen);
    return outlen;
}

void scrub_avc_stats(char *buf, size_t len) {
    if (!buf || len == 0) return;
    size_t i = 0;
    while (i < len && buf[i] != '\n') ++i;  // keep the header line
    for (; i < len; ++i)
        if (buf[i] >= '0' && buf[i] <= '9') buf[i] = '0';
}

void scrub_policy(char *buf, size_t len) {
    if (!buf || len == 0) return;
    for (int t = 0; dsb::kBinaryTokens[t]; ++t) {
        const char *needle = dsb::kBinaryTokens[t];
        size_t nlen = strlen(needle);
        if (nlen == 0 || nlen > len) continue;
        for (size_t i = 0; i + nlen <= len; ++i) {
            if (buf[i] == needle[0] && memcmp(buf + i, needle, nlen) == 0) {
                memset(buf + i, 0, nlen);
                i += nlen - 1;
            }
        }
    }
}

// ---- virtual file construction ------------------------------------------

int open_virtual(const char *path) {
    if (!g_app_mode || !path) return -1;
    VirtualKind kind = classify_virtual(path);
    if (kind == VK_NONE) return -1;

    size_t len = 0;
    char *buf = read_whole(path, &len, 16u * 1024u * 1024u);
    if (!buf) return -1;
    if (len == 0) { free(buf); return -1; }

    switch (kind) {
        case VK_AVC:
            scrub_avc_stats(buf, len);
            break;
        case VK_ENV:
            len = scrub_environ(buf, len);
            if (len == 0) { free(buf); return -1; }
            break;
        case VK_STAT:
            len = scrub_stat(buf, len);
            break;
        default:
            len = scrub_text(buf, len);
            if (len == 0) { free(buf); return -1; }
            break;
    }

    int fd = memfd_from("jit-cache", buf, len);
    free(buf);
    return fd;
}

static bool link_target_hidden(const char *target) {
    return dsb::restricted_path(target) || dsb::deleted_shared_object(target);
}

// ---- hooks ---------------------------------------------------------------

static FILE *fopen_virtual(const char *path, const char *mode) {
    if (!mode || mode[0] != 'r') return nullptr;
    int fd = open_virtual(path);
    if (fd < 0) return nullptr;

    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    FILE *fp = orig_fopen ? orig_fopen(link, mode) : nullptr;
    raw_close(fd);
    return fp;
}

FILE *my_fopen(const char *path, const char *mode) {
    FILE *fp = fopen_virtual(path, mode);
    if (fp) return fp;
    if (!orig_fopen) { errno = ENOSYS; return nullptr; }
    return orig_fopen(path, mode);
}

FILE *my_fopen64(const char *path, const char *mode) {
    FILE *fp = fopen_virtual(path, mode);
    if (fp) return fp;
    if (orig_fopen64) return orig_fopen64(path, mode);
    if (orig_fopen) return orig_fopen(path, mode);
    errno = ENOSYS;
    return nullptr;
}

static ssize_t filter_link(ssize_t ret, char *buf, size_t bufsiz) {
    if (ret <= 0) return ret;
    size_t n = static_cast<size_t>(ret);
    if (n >= bufsiz) n = bufsiz - 1;
    char tmp[512];
    size_t c = n < sizeof(tmp) - 1 ? n : sizeof(tmp) - 1;
    memcpy(tmp, buf, c);
    tmp[c] = '\0';
    if (link_target_hidden(tmp)) {
        errno = ENOENT;
        return -1;
    }
    return ret;
}

ssize_t my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (!orig_readlink) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_readlink(path, buf, bufsiz);
    if (!g_app_mode) return ret;
    return filter_link(ret, buf, bufsiz);
}

ssize_t my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    if (!orig_readlinkat) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_readlinkat(dirfd, path, buf, bufsiz);
    if (!g_app_mode) return ret;
    return filter_link(ret, buf, bufsiz);
}

char *my_getenv(const char *name) {
    if (g_app_mode && hidden_env_name(name)) return nullptr;
    if (!orig_getenv) return nullptr;
    return orig_getenv(name);
}

char *my_secure_getenv(const char *name) {
    if (g_app_mode && hidden_env_name(name)) return nullptr;
    if (orig_secure_getenv) return orig_secure_getenv(name);
    if (orig_getenv) return orig_getenv(name);
    return nullptr;
}

struct PhdrCtx {
    int (*cb)(struct dl_phdr_info *, size_t, void *);
    void *data;
};

static int phdr_filter(struct dl_phdr_info *info, size_t size, void *data) {
    auto *ctx = static_cast<PhdrCtx *>(data);
    if (g_app_mode && info && info->dlpi_name) {
        // Anonymous memfd modules are how ZygiskNext/Riru-style injectors
        // avoid a /data/adb path; stock app processes have no such entries
        // in their linker solist.
        if (dsb::restricted_path(info->dlpi_name) ||
            strstr(info->dlpi_name, "memfd:") != nullptr)
            return 0;
    }
    return ctx->cb(info, size, ctx->data);
}

int my_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!orig_dl_iterate_phdr) return -1;
    if (!g_app_mode) return orig_dl_iterate_phdr(cb, data);
    PhdrCtx ctx = {cb, data};
    return orig_dl_iterate_phdr(phdr_filter, &ctx);
}

// ---- same-uid cross-process /proc reads ----------------------------------
//
// Hooks only cover code inside this process.  A detector can fork a helper
// ("cat /proc/<our-pid>/maps", process_vm_readv, PTRACE_ATTACH) that runs
// outside our reach, and the kernel will happily serve the untouched file
// because both processes share the app uid.  Linux gates those accesses with
// ptrace_may_access(), which requires the target to be dumpable
// (SUID_DUMP_USER == 1).
//
// AOSP's zygote normally leaves app processes non-dumpable already:
// setresuid from uid 0 resets the flag to /proc/sys/fs/suid_dumpable (0), and
// SpecializeCommon forces 0 when suid_dumpable is 2.  Blocking is therefore
// stock behaviour for ordinary apps and guard_process() does nothing for them.
// The flag is only raised again for PROFILE_FROM_SHELL (profileable) apps;
// clearing it for those is what closes the cross-process hole.
//
// This must run in postAppSpecialize: a preAppSpecialize hook would be
// overwritten by SpecializeCommon's own setresuid / PR_SET_DUMPABLE calls.
//
// The side effects are masked only when we actually changed the flag
// (prev == SUID_DUMP_USER), because otherwise they would deviate from stock:
//   * /proc/<pid> and everything below it become root-owned -> rewrite
//     st_uid/st_gid in the stat family;
//   * prctl(PR_GET_DUMPABLE) would answer 0            -> answer 1;
//   * the same check through syscall(__NR_prctl, ...)  -> filtered too.
// When prev was 0 the process already matched stock (root-owned proc inodes,
// PR_GET_DUMPABLE == 0), so every hook stays transparent and only forwards.

static bool g_dumpable_spoof = false;

static long raw_prctl(long option, long a2, long a3, long a4, long a5) {
#ifdef __NR_prctl
    if (orig_syscall) return orig_syscall(__NR_prctl, option, a2, a3, a4, a5);
    return ::syscall(__NR_prctl, option, a2, a3, a4, a5);
#else
    (void)a2; (void)a3; (void)a4; (void)a5;
    return prctl(option, 0);
#endif
}

void guard_process() {
    long prev = raw_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    // SUID_DUMP_DISABLE (0) and SUID_DUMP_ROOT (2) already make
    // task_still_dumpable() fail, so only the user-dumpable state needs action.
    if (prev != 1) return;
    raw_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    g_dumpable_spoof = true;
}

static bool raw_readlink_target(int fd, char *out, size_t cap) {
    if (fd < 0 || !out || cap == 0) return false;
    char link[64];
    int n = snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof link) return false;
#ifdef __NR_readlinkat
    long r = syscall(__NR_readlinkat, AT_FDCWD, link, out, cap - 1);
#else
    long r = syscall(__NR_readlink, link, out, cap - 1);
#endif
    if (r <= 0) return false;
    out[r] = '\0';
    return true;
}

// Any path under this process's own /proc/<pid>, including /proc/self and
// /proc/thread-self aliases.  Only directory ownership changes when the
// process is non-dumpable, but every procfs inode for that pid is affected,
// so the whole subtree is rewritten.
static bool proc_path_self(const char *path) {
    if (!path || strncmp(path, "/proc/", 6) != 0) return false;
    const char *rest = path + 6;
    if (strncmp(rest, "self", 4) == 0 && (rest[4] == '\0' || rest[4] == '/'))
        return true;
    if (strncmp(rest, "thread-self", 11) == 0 &&
        (rest[11] == '\0' || rest[11] == '/'))
        return true;

    const char *q = rest;
    const char *digits = q;
    long pid = 0;
    while (is_digit(*q)) { pid = pid * 10 + (*q - '0'); ++q; }
    if (q == digits || pid != static_cast<long>(getpid())) return false;
    return *q == '\0' || *q == '/';
}

static bool fd_is_self_proc(int fd) {
    char target[256];
    return raw_readlink_target(fd, target, sizeof target) &&
           proc_path_self(target);
}

static bool at_is_self_proc(int dirfd, const char *path) {
    if (!path) return false;
    // AT_EMPTY_PATH: the directory fd itself refers to the file.
    if (path[0] == '\0') return dirfd >= 0 && fd_is_self_proc(dirfd);
    if (path[0] == '/') return proc_path_self(path);
    if (dirfd < 0) return false;
    char target[256];
    if (!raw_readlink_target(dirfd, target, sizeof target)) return false;
    return proc_path_self(target);
}

template <typename StatT>
static void fix_owner(StatT *st) {
    if (!st) return;
    st->st_uid = getuid();
    st->st_gid = getgid();
}

// Kernel uapi struct statx layout (include/uapi/linux/stat.h), mirrored so the
// wrapper does not depend on NDK headers gated behind __ANDROID_API__ >= 30.
// Only the uid/gid prefix is touched; the caller owns the full 256-byte buffer.
struct DsbStatx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t _spare0;
    uint8_t  _tail[256 - 30];
};
static_assert(offsetof(DsbStatx, stx_uid) == 20, "statx prefix layout");
static_assert(offsetof(DsbStatx, stx_gid) == 24, "statx prefix layout");

int my_statx(int dirfd, const char *path, int flags, unsigned int mask, void *buf) {
    if (!orig_statx) { errno = ENOSYS; return -1; }
    int r = orig_statx(dirfd, path, flags, mask, buf);
    if (r == 0 && g_app_mode && g_dumpable_spoof && buf &&
        at_is_self_proc(dirfd, path)) {
        auto *sx = static_cast<DsbStatx *>(buf);
        sx->stx_uid = static_cast<uint32_t>(getuid());
        sx->stx_gid = static_cast<uint32_t>(getgid());
    }
    return r;
}

int my_prctl(int option, ...) {
    if (g_app_mode && g_dumpable_spoof && option == PR_GET_DUMPABLE) return 1;

    va_list ap;
    va_start(ap, option);
    unsigned long a1 = va_arg(ap, unsigned long);
    unsigned long a2 = va_arg(ap, unsigned long);
    unsigned long a3 = va_arg(ap, unsigned long);
    unsigned long a4 = va_arg(ap, unsigned long);
    va_end(ap);
    if (!orig_prctl) { errno = ENOSYS; return -1; }
    return orig_prctl(option, a1, a2, a3, a4);
}

long my_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    unsigned long a1 = va_arg(ap, unsigned long);
    unsigned long a2 = va_arg(ap, unsigned long);
    unsigned long a3 = va_arg(ap, unsigned long);
    unsigned long a4 = va_arg(ap, unsigned long);
    unsigned long a5 = va_arg(ap, unsigned long);
    unsigned long a6 = va_arg(ap, unsigned long);
    va_end(ap);

    if (g_app_mode && g_dumpable_spoof && number == __NR_prctl &&
        static_cast<int>(a1) == PR_GET_DUMPABLE)
        return 1;
    if (!orig_syscall) { errno = ENOSYS; return -1; }
    return orig_syscall(number, a1, a2, a3, a4, a5, a6);
}

int my_stat(const char *path, struct stat *st) {
    if (!orig_stat) { errno = ENOSYS; return -1; }
    int r = orig_stat(path, st);
    if (r == 0 && g_app_mode && g_dumpable_spoof && proc_path_self(path)) fix_owner(st);
    return r;
}

int my_lstat(const char *path, struct stat *st) {
    if (!orig_lstat) { errno = ENOSYS; return -1; }
    int r = orig_lstat(path, st);
    if (r == 0 && g_app_mode && g_dumpable_spoof && proc_path_self(path)) fix_owner(st);
    return r;
}

int my_fstat(int fd, struct stat *st) {
    if (!orig_fstat) { errno = ENOSYS; return -1; }
    int r = orig_fstat(fd, st);
    if (r == 0 && g_app_mode && g_dumpable_spoof && fd_is_self_proc(fd)) fix_owner(st);
    return r;
}

int my_fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    if (!orig_fstatat) { errno = ENOSYS; return -1; }
    int r = orig_fstatat(dirfd, path, st, flags);
    if (r == 0 && g_app_mode && g_dumpable_spoof && at_is_self_proc(dirfd, path)) fix_owner(st);
    return r;
}

#ifdef DSB_HAVE_STAT64
int my_stat64(const char *path, struct stat64 *st) {
    if (!orig_stat64) { errno = ENOSYS; return -1; }
    int r = orig_stat64(path, st);
    if (r == 0 && g_app_mode && g_dumpable_spoof && proc_path_self(path)) fix_owner(st);
    return r;
}

int my_lstat64(const char *path, struct stat64 *st) {
    if (!orig_lstat64) { errno = ENOSYS; return -1; }
    int r = orig_lstat64(path, st);
    if (r == 0 && g_app_mode && g_dumpable_spoof && proc_path_self(path)) fix_owner(st);
    return r;
}

int my_fstat64(int fd, struct stat64 *st) {
    if (!orig_fstat64) { errno = ENOSYS; return -1; }
    int r = orig_fstat64(fd, st);
    if (r == 0 && g_app_mode && g_dumpable_spoof && fd_is_self_proc(fd)) fix_owner(st);
    return r;
}

int my_fstatat64(int dirfd, const char *path, struct stat64 *st, int flags) {
    if (!orig_fstatat64) { errno = ENOSYS; return -1; }
    int r = orig_fstatat64(dirfd, path, st, flags);
    if (r == 0 && g_app_mode && g_dumpable_spoof && at_is_self_proc(dirfd, path)) fix_owner(st);
    return r;
}
#endif

}  // namespace stealth
