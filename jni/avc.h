// AVC audit-log camouflage.
//
// Ported (without the ZygiskNext dependency) from aviraxp/ZN-AuditPatch.  The
// original injects libauditpatch.so into logd with ZygiskNext and rewrites
// `tcontext=u:r:su:s0` into a fake priv_app label.  A plain Magisk Zygisk
// module cannot inject logd, so instead we:
//   * drop leaking AVC lines at the source (__android_log_* calls made from
//     the hooked process), and
//   * filter AVC lines that come back through read()/pread64() (e.g. a
//     `logcat` child process whose stdout the detector parses).
//
// Unlike ZN-AuditPatch we never synthesize a fake tcontext.  Duck-Detector
// flags `u:r:priv_app:s0:c512,c768` as a forgery marker, so suspicious records
// are removed entirely.

#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

namespace avc {

bool is_avc_record(const char *s, size_t len);
bool line_leaks(const char *s, size_t len);

// Drops leaking lines in place, returns the (possibly shortened) length.
size_t filter_buffer(void *buf, size_t len);

// ---- log source hooks ---------------------------------------------------

extern int (*orig_log_write)(int, const char *, const char *);
extern int (*orig_log_buf_write)(int, int, const char *, const char *);
extern int (*orig_log_print)(int, const char *, const char *, ...);
extern int (*orig_log_vprint)(int, const char *, const char *, va_list);

int my_log_write(int prio, const char *tag, const char *text);
int my_log_buf_write(int buf_id, int prio, const char *tag, const char *text);
int my_log_print(int prio, const char *tag, const char *fmt, ...);
int my_log_vprint(int prio, const char *tag, const char *fmt, va_list ap);

}  // namespace avc
