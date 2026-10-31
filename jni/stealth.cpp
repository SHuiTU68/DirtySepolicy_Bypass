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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

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

static bool is_self_proc_file(const char *p) {
    if (!p) return false;
    if (strncmp(p, "/proc/self/", 11) != 0) return false;
    const char *rest = p + 11;
    if (strcmp(rest, "maps") == 0 || strcmp(rest, "smaps") == 0 ||
        strcmp(rest, "status") == 0 || strcmp(rest, "comm") == 0)
        return true;
    if (strncmp(rest, "task/", 5) == 0) {
        const char *tail = strstr(rest, "/comm");
        if (tail && strcmp(tail, "/comm") == 0) return true;
    }
    return false;
}

// ---- text scrubbing ------------------------------------------------------

static bool hidden_env_name(const char *name) {
    if (!name) return false;
    static const char *const kNames[] = {
        "tmp_path", "magisk", "zygisk", "ksu", "kernelsu", "apatch",
        "lsposed", "xposed", "riru", "shamiko", "supolicy", "adbroot",
        nullptr,
    };
    char lower[64];
    dsb::lower_copy(lower, name, sizeof(lower));
    for (int i = 0; kNames[i]; ++i)
        if (strcmp(lower, kNames[i]) == 0) return true;
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
    bool stats = is_cache_stats(path);
    if (!stats && !is_self_proc_file(path)) return -1;

    size_t len = 0;
    char *buf = read_whole(path, &len, 8u * 1024u * 1024u);
    if (!buf) return -1;
    if (len == 0) { free(buf); return -1; }

    if (stats) {
        scrub_avc_stats(buf, len);
    } else {
        len = scrub_text(buf, len);
        if (len == 0) { free(buf); return -1; }
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
    if (g_app_mode && info && info->dlpi_name &&
        dsb::restricted_path(info->dlpi_name))
        return 0;
    return ctx->cb(info, size, ctx->data);
}

int my_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!orig_dl_iterate_phdr) return -1;
    if (!g_app_mode) return orig_dl_iterate_phdr(cb, data);
    PhdrCtx ctx = {cb, data};
    return orig_dl_iterate_phdr(phdr_filter, &ctx);
}

}  // namespace stealth
