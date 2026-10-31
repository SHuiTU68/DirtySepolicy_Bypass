// Userspace zygisk-injection hiding.
//
// Detectors such as Duck-Detector enumerate linker solists, /proc/self/maps,
// /proc/self/smaps, /proc/self/smaps_rollup, /proc/self/status, stat/sched,
// mountinfo, environ, fd targets and thread comm values to find a framework
// loaded into an otherwise clean app process.  This component serves scrubbed,
// private copies of those files (anonymous memfd), filters dl_iterate_phdr and
// readlink results, and hides framework environment variables.  Paths are also
// recognised when written as /proc/<own-pid>/... or /proc/thread-self/...

#pragma once

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <link.h>

namespace stealth {

// Original function pointers filled in by the Zygisk PLT hook.
extern FILE    *(*orig_fopen)(const char *, const char *);
extern FILE    *(*orig_fopen64)(const char *, const char *);
extern ssize_t  (*orig_readlink)(const char *, char *, size_t);
extern ssize_t  (*orig_readlinkat)(int, const char *, char *, size_t);
extern char    *(*orig_getenv)(const char *);
extern char    *(*orig_secure_getenv)(const char *);
extern int      (*orig_dl_iterate_phdr)(int (*)(struct dl_phdr_info *, size_t, void *), void *);

// Enables the scrubbed view.  Set only for ordinary, non-root app processes
// (uid >= 10000 and without PROCESS_GRANTED_ROOT); root-granted apps and
// system_server keep the real /data/adb mappings and linker solist.
void set_app_mode(bool app);

// Returns an anonymous memfd holding a scrubbed copy of `path`, or -1 when
// the path is not one of the guarded files / cannot be opened.
int open_virtual(const char *path);

// Content scrubbers used by module.cpp after read()/pread64().
size_t scrub_text(char *buf, size_t len);        // maps / smaps / status / comm
void   scrub_avc_stats(char *buf, size_t len);   // avc/cache_stats
void   scrub_policy(char *buf, size_t len);      // binary policy string table

// PLT hook implementations.
FILE   *my_fopen(const char *path, const char *mode);
FILE   *my_fopen64(const char *path, const char *mode);
ssize_t my_readlink(const char *path, char *buf, size_t bufsiz);
ssize_t my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz);
char   *my_getenv(const char *name);
char   *my_secure_getenv(const char *name);
int     my_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data);

}  // namespace stealth
