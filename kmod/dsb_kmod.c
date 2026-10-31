// SPDX-License-Identifier: GPL-2.0
/*
 * DirtySepolicy Bypass - kernel side
 *
 * The userspace (Zygisk) generation of this module could only hide what the
 * probe itself went through: a detector that reads selinuxfs/procfs with raw
 * syscalls, or that runs in a process the injector never touched, saw the
 * real answers.  This module moves the hiding into the one place every probe
 * has to go through: the kernel.
 *
 * Six kretprobes are installed:
 *
 *  1. security_context_to_sid() - makes Magisk/KernelSU/LSPosed/... contexts
 *     indistinguishable from contexts that simply do not exist in the loaded
 *     policy.  A context that exists makes a write to /proc/<pid>/attr/current
 *     or /sys/fs/selinux/context fail with EACCES (refused by policy), an
 *     unknown one fails with EINVAL.  That difference is what the detectors
 *     use to recognise privileged contexts.
 *
 *  2. selinux_setprocattr() - the same answer for /proc/<pid>/attr/current,
 *     forced at the LSM hook itself so it keeps working even if the context
 *     lookup above gets inlined by the compiler.
 *
 *  3. sel_write_context() - the same answer for a write to
 *     /sys/fs/selinux/context.
 *
 *  4. sel_write_access() - rewrites the six field answer of
 *     /sys/fs/selinux/access so the rules a live policy patcher injected
 *     (rootfs -> tmpfs associate, kernel -> tmpfs fifo open,
 *     system_server -> apk_data_file execute, zygote -> adb_data_file search,
 *     system_server execmem, ...) read back as denied.  The decision is made
 *     on the query text, so no SID lookup, no policy walk and no reference to
 *     SELinux internals is required.
 *
 *  5./6. show_mountinfo() and show_vfsmnt() - drop whole lines from
 *     /proc/<pid>/mountinfo and /proc/<pid>/mounts whose text mentions a
 *     root managed mount (source=magisk, /debug_ramdisk, /adb/modules/...).
 *     A line is discarded by rewinding seq_file->count to the value it had
 *     before the show callback appended anything.
 *
 * Every hook is gated on the *caller* being an ordinary application
 * (uid >= 10000).  That covers normal apps, isolated processes and the
 * app_zygote children Duck-Detector uses as probe carriers, and leaves root,
 * shell (2000), system (1000) and every system service untouched, so the
 * framework keeps behaving exactly as before.
 *
 * The module is deliberately self contained: no sscanf/snprintf, no libc
 * string helpers.  The fewer external symbols the better, both for GKI
 * module protection and for how much of the kernel interface has to be
 * trusted.
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uidgid.h>

#define PFX "dsb_kmod: "

#define CTX_MAX 200

/* ------------------------------------------------------------------------- */
/* small helpers (no lib/string.c calls)                                     */
/* ------------------------------------------------------------------------- */

static inline bool is_blank(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/*
 * Copy at most @n bytes from a buffer that may not be NUL terminated (the
 * context paths pass a length, not a string).  @cap includes the NUL.
 */
static void copy_nstr(char *dst, const void *src, size_t n, size_t cap)
{
	const char *s = src;
	size_t i;

	if (!cap)
		return;
	if (n > cap - 1)
		n = cap - 1;
	for (i = 0; i < n; i++) {
		if (!s[i]) {
			dst[i] = '\0';
			return;
		}
		dst[i] = s[i];
	}
	dst[i] = '\0';
}

/* Substring search inside a NUL terminated string. */
static bool has_substr(const char *hay, const char *needle)
{
	size_t i, j;

	if (!needle[0])
		return false;
	for (i = 0; hay[i]; i++) {
		for (j = 0; needle[j]; j++) {
			if (hay[i + j] != needle[j])
				break;
		}
		if (!needle[j])
			return true;
	}
	return false;
}

/* Substring search inside a bounded region (for seq_file buffers). */
static bool has_substr_n(const char *hay, size_t len, const char *needle)
{
	size_t i, j;

	if (!needle[0])
		return false;
	for (i = 0; i < len; i++) {
		for (j = 0; needle[j] && i + j < len; j++) {
			if (hay[i + j] != needle[j])
				break;
		}
		if (!needle[j])
			return true;
	}
	return false;
}

static bool is_same(const char *a, const char *b)
{
	size_t i = 0;

	while (a[i] && b[i]) {
		if (a[i] != b[i])
			return false;
		i++;
	}
	return a[i] == '\0' && b[i] == '\0';
}

static const char *skip_blanks(const char *p)
{
	while (*p && is_blank(*p))
		p++;
	return p;
}

/* ------------------------------------------------------------------------- */
/* gating                                                                    */
/* ------------------------------------------------------------------------- */

/*
 * Ordinary applications only.  Android app UIDs start at 10000; isolated
 * processes (90000+) and app_zygote children (10xxx) are included on
 * purpose, that is exactly where the detectors run.
 */
static inline bool app_caller(void)
{
	return current_uid().val >= 10000;
}

/* ------------------------------------------------------------------------- */
/* hidden SELinux contexts                                                   */
/* ------------------------------------------------------------------------- */

/*
 * Matched against the whole context string, e.g. "u:r:magisk:s0" or
 * "u:object_r:magisk_file:s0".  Substrings, because the same family shows up
 * as domain, file type, property type and so on.
 */
static const char *const hidden_ctx_parts[] = {
	"magisk",
	"lsposed",
	"zygisk",
	"kernelsu",
	"ksu",
	"apatch",
	"adbroot",
	"xposed",
	"droidspaces",
	"msd_app",
	"msd_daemon",
	"auditpatch",
	"dirtysep",
	"dsb_",
	NULL,
};

static bool hidden_context(const char *ctx)
{
	int i;

	if (!ctx || !ctx[0])
		return false;
	for (i = 0; hidden_ctx_parts[i]; i++) {
		if (has_substr(ctx, hidden_ctx_parts[i]))
			return true;
	}
	return false;
}

struct ctx_rec {
	char con[CTX_MAX];
};

static struct kretprobe kr_ctx;

static int ctx_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ctx_rec *r = (struct ctx_rec *)ri->data;
	const char *scon;
	u32 len;

	if (!app_caller())
		return 0;

	scon = (const char *)regs_get_kernel_argument(regs, 0);
	len = (u32)regs_get_kernel_argument(regs, 1);
	if (!scon || !len)
		return 0;

	if (len > CTX_MAX - 1)
		len = CTX_MAX - 1;
	copy_nstr(r->con, scon, len, CTX_MAX);

	/* Only privileged contexts are worth a return trip. */
	if (!hidden_context(r->con))
		return 0;

	return 1;
}

static int ctx_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ctx_rec *r = (struct ctx_rec *)ri->data;

	/* Successful lookup => "no such context". */
	if ((long)regs_return_value(regs) != 0)
		return 0;
	if (!hidden_context(r->con))
		return 0;

	regs_set_return_value(regs, (unsigned long)(u32)(-EINVAL));
	return 0;
}

/* ------------------------------------------------------------------------- */
/* /proc/<pid>/attr/current (selinux_setprocattr)                            */
/* ------------------------------------------------------------------------- */

static struct kretprobe kr_procattr;

static int procattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ctx_rec *r = (struct ctx_rec *)ri->data;
	const void *value;
	size_t size;

	if (!app_caller())
		return 0;

	/* const char *name, void *value, size_t size */
	value = (const void *)regs_get_kernel_argument(regs, 1);
	size = (size_t)regs_get_kernel_argument(regs, 2);
	if (!value || !size)
		return 0;

	if (size > CTX_MAX - 1)
		size = CTX_MAX - 1;
	copy_nstr(r->con, value, size, CTX_MAX);

	if (!hidden_context(r->con))
		return 0;

	return 1;
}

static int procattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ctx_rec *r = (struct ctx_rec *)ri->data;

	if (!hidden_context(r->con))
		return 0;

	/*
	 * The write never reaches the policy check: an unknown context is
	 * rejected as malformed, not as "recognised but not permitted".
	 */
	regs_set_return_value(regs, (unsigned long)(u32)(-EINVAL));
	return 0;
}

/* ------------------------------------------------------------------------- */
/* /sys/fs/selinux/context (sel_write_context)                               */
/* ------------------------------------------------------------------------- */

static struct kretprobe kr_wrctx;

static int wrctx_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ctx_rec *r = (struct ctx_rec *)ri->data;
	const char *buf;
	size_t size;

	if (!app_caller())
		return 0;

	/* struct file *file, char *buf, size_t size */
	buf = (const char *)regs_get_kernel_argument(regs, 1);
	size = (size_t)regs_get_kernel_argument(regs, 2);
	if (!buf || !size)
		return 0;

	if (size > CTX_MAX - 1)
		size = CTX_MAX - 1;
	copy_nstr(r->con, buf, size, CTX_MAX);

	if (!hidden_context(r->con))
		return 0;

	return 1;
}

static int wrctx_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ctx_rec *r = (struct ctx_rec *)ri->data;

	if (!hidden_context(r->con))
		return 0;

	regs_set_return_value(regs, (unsigned long)(u32)(-EINVAL));
	return 0;
}

/* ------------------------------------------------------------------------- */
/* /sys/fs/selinux/access (sel_write_access)                                 */
/* ------------------------------------------------------------------------- */

struct acc_rec {
	char *buf;
	char q[CTX_MAX * 2];
};

/* Both contexts are stock, so only the answer itself can be masked. */
struct pair {
	const char *s;
	const char *t;
};

static const struct pair dirty_pairs[] = {
	{ "u:r:system_server:s0",  "u:r:system_server:s0" },
	{ "u:r:system_server:s0",  "u:object_r:apk_data_file:s0" },
	{ "u:r:zygote:s0",         "u:object_r:adb_data_file:s0" },
	{ "u:r:kernel:s0",         "u:object_r:adb_data_file:s0" },
	{ "u:r:kernel:s0",         "u:object_r:tmpfs:s0" },
	{ "u:object_r:rootfs:s0",  "u:object_r:tmpfs:s0" },
	{ "u:r:dex2oat:s0",        "u:object_r:dex2oat_exec:s0" },
	{ "u:r:fsck_untrusted:s0", "u:r:fsck_untrusted:s0" },
	{ "u:r:shell:s0",          "u:r:su:s0" },
	{ "u:r:adbd:s0",           "u:r:adbroot:s0" },
	{ "u:r:untrusted_app:s0",  "u:object_r:magisk_file:s0" },
	{ "u:r:untrusted_app:s0",  "u:object_r:lsposed_file:s0" },
	{ NULL, NULL },
};

static bool dirty_pair(const char *scon, const char *tcon)
{
	int i;

	for (i = 0; dirty_pairs[i].s; i++) {
		if (is_same(scon, dirty_pairs[i].s) &&
		    is_same(tcon, dirty_pairs[i].t))
			return true;
	}
	return false;
}

static struct kretprobe kr_access;

/* Split "scon tcon tclass" and report whether the answer needs masking. */
static bool access_needs_mask(const char *q, char *scon, char *tcon)
{
	const char *p;
	int n;

	p = skip_blanks(q);
	n = 0;
	while (p[n] && !is_blank(p[n]) && n < CTX_MAX - 1)
		n++;
	if (n <= 0)
		return false;
	copy_nstr(scon, p, (size_t)n, CTX_MAX);
	p = skip_blanks(p + n);
	n = 0;
	while (p[n] && !is_blank(p[n]) && n < CTX_MAX - 1)
		n++;
	if (n <= 0)
		return false;
	copy_nstr(tcon, p, (size_t)n, CTX_MAX);

	return hidden_context(scon) || hidden_context(tcon) ||
	       dirty_pair(scon, tcon);
}

static int acc_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct acc_rec *r = (struct acc_rec *)ri->data;
	const char *buf;
	size_t size;
	char scon[CTX_MAX], tcon[CTX_MAX];

	if (!app_caller())
		return 0;

	/* struct file *file, char *buf, size_t size */
	buf = (const char *)regs_get_kernel_argument(regs, 1);
	size = (size_t)regs_get_kernel_argument(regs, 2);
	if (!buf || !size)
		return 0;

	copy_nstr(r->q, buf, size, sizeof(r->q));

	if (!access_needs_mask(r->q, scon, tcon))
		return 0;

	r->buf = (char *)buf;
	return 1;
}

/* --- the answer is "%x %x %x %x %u %x" --- */

static int hex_digit(unsigned int v)
{
	return v < 10 ? '0' + (int)v : 'a' + (int)(v - 10);
}

static int fmt_hex(char *p, u32 v)
{
	char tmp[8];
	int n = 0, i;

	do {
		tmp[n++] = hex_digit(v & 0xf);
		v >>= 4;
	} while (v);
	for (i = 0; i < n; i++)
		p[i] = tmp[n - 1 - i];
	return n;
}

static int fmt_dec(char *p, u32 v)
{
	char tmp[10];
	int n = 0, i;

	do {
		tmp[n++] = (char)('0' + (int)(v % 10));
		v /= 10;
	} while (v);
	for (i = 0; i < n; i++)
		p[i] = tmp[n - 1 - i];
	return n;
}

/* Returns the token length, or -1 when the token is not a hex number. */
static int parse_hex(const char *s, u32 *out)
{
	u32 v = 0;
	int n = 0;

	while (s[n] && !is_blank(s[n])) {
		u32 d;

		if (s[n] >= '0' && s[n] <= '9')
			d = (u32)(s[n] - '0');
		else if (s[n] >= 'a' && s[n] <= 'f')
			d = (u32)(s[n] - 'a' + 10);
		else if (s[n] >= 'A' && s[n] <= 'F')
			d = (u32)(s[n] - 'A' + 10);
		else
			return -1;
		v = (v << 4) | d;
		n++;
	}
	if (!n)
		return -1;
	*out = v;
	return n;
}

static int parse_dec(const char *s, u32 *out)
{
	u32 v = 0;
	int n = 0;

	while (s[n] && !is_blank(s[n])) {
		if (s[n] < '0' || s[n] > '9')
			return -1;
		v = v * 10 + (u32)(s[n] - '0');
		n++;
	}
	if (!n)
		return -1;
	*out = v;
	return n;
}

/*
 * Rebuild the answer with allowed and auditallow cleared.  auditdeny, seqno
 * and flags are kept: a genuine denial for this class still carries them.
 * Returns the new length, or -1 when the original answer was not understood.
 */
static ssize_t mask_answer(char *buf)
{
	const char *p = buf;
	u32 auditdeny = 0, seqno = 0, flags = 0, v;
	int off = 0, n;

	p = skip_blanks(p);
	n = parse_hex(p, &v);			/* allowed: dropped */
	if (n < 0)
		return -1;
	p = skip_blanks(p + n);
	n = parse_hex(p, &v);			/* 0xffffffff, constant */
	if (n < 0)
		return -1;
	p = skip_blanks(p + n);
	n = parse_hex(p, &v);			/* auditallow: dropped */
	if (n < 0)
		return -1;
	p = skip_blanks(p + n);
	n = parse_hex(p, &auditdeny);
	if (n < 0)
		return -1;
	p = skip_blanks(p + n);
	n = parse_dec(p, &seqno);
	if (n < 0)
		return -1;
	p = skip_blanks(p + n);
	n = parse_hex(p, &flags);
	if (n < 0)
		return -1;

	buf[off++] = '0';
	buf[off++] = ' ';
	off += fmt_hex(buf + off, 0xffffffffu);
	buf[off++] = ' ';
	buf[off++] = '0';
	buf[off++] = ' ';
	off += fmt_hex(buf + off, auditdeny);
	buf[off++] = ' ';
	off += fmt_dec(buf + off, seqno);
	buf[off++] = ' ';
	off += fmt_hex(buf + off, flags);
	buf[off] = '\0';

	return off;
}

static int acc_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct acc_rec *r = (struct acc_rec *)ri->data;
	ssize_t len;

	if ((long)regs_return_value(regs) <= 0)
		return 0;
	if (!r->buf)
		return 0;

	len = mask_answer(r->buf);
	if (len <= 0)
		return 0;

	regs_set_return_value(regs, (unsigned long)len);
	return 0;
}

/* ------------------------------------------------------------------------- */
/* mount tables                                                              */
/* ------------------------------------------------------------------------- */

/*
 * Any line mentioning one of these is dropped.  "magisk" covers
 * "source=magisk" and the "/product/bin/magisk" mount, "/adb/modules"
 * covers the overlay style module mounts the report flagged, and the
 * remaining entries cover the other root families.
 */
static const char *const hidden_mnt_parts[] = {
	"magisk",
	"/adb/modules",
	"/debug_ramdisk",
	"/data/adb",
	"/data/local/tmp",
	"lsposed",
	"zygisk",
	"kernelsu",
	"apatch",
	"/sbin",
	NULL,
};

struct mnt_rec {
	struct seq_file *m;
	size_t count;
};

static struct kretprobe kr_mountinfo;
static struct kretprobe kr_mounts;

static int mnt_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mnt_rec *r = (struct mnt_rec *)ri->data;
	struct seq_file *m;

	if (!app_caller())
		return 0;

	m = (struct seq_file *)regs_get_kernel_argument(regs, 0);
	if (!m)
		return 0;

	r->m = m;
	r->count = m->count;
	return 1;
}

static int mnt_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mnt_rec *r = (struct mnt_rec *)ri->data;
	struct seq_file *m = r->m;
	size_t len;
	int i;

	if ((int)(long)regs_return_value(regs) < 0)
		return 0;
	if (!m || m->count <= r->count)
		return 0;

	len = m->count - r->count;
	for (i = 0; hidden_mnt_parts[i]; i++) {
		if (has_substr_n(m->buf + r->count, len, hidden_mnt_parts[i])) {
			m->count = r->count;
			return 0;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------- */
/* registration                                                              */
/* ------------------------------------------------------------------------- */

static int reg(struct kretprobe *kr, const char *sym)
{
	int ret = register_kretprobe(kr);

	if (ret)
		pr_err(PFX "cannot hook %s (%d)\n", sym, ret);
	else
		pr_info(PFX "hooked %s\n", sym);
	return ret;
}

static void setup(struct kretprobe *kr, const char *sym,
		  kretprobe_handler_t entry, kretprobe_handler_t ret,
		  size_t data_size, int maxactive)
{
	kr->kp.symbol_name = sym;
	kr->entry_handler = entry;
	kr->handler = ret;
	kr->data_size = data_size;
	kr->maxactive = maxactive;
}

static int __init dsb_init(void)
{
	int ok = 0;

	setup(&kr_ctx, "security_context_to_sid", ctx_entry, ctx_ret,
	      sizeof(struct ctx_rec), 64);
	setup(&kr_procattr, "selinux_setprocattr", procattr_entry, procattr_ret,
	      sizeof(struct ctx_rec), 64);
	setup(&kr_wrctx, "sel_write_context", wrctx_entry, wrctx_ret,
	      sizeof(struct ctx_rec), 32);
	setup(&kr_access, "sel_write_access", acc_entry, acc_ret,
	      sizeof(struct acc_rec), 32);
	setup(&kr_mountinfo, "show_mountinfo", mnt_entry, mnt_ret,
	      sizeof(struct mnt_rec), 64);
	setup(&kr_mounts, "show_vfsmnt", mnt_entry, mnt_ret,
	      sizeof(struct mnt_rec), 64);

	if (!reg(&kr_ctx, "security_context_to_sid"))
		ok++;
	if (!reg(&kr_procattr, "selinux_setprocattr"))
		ok++;
	if (!reg(&kr_wrctx, "sel_write_context"))
		ok++;
	if (!reg(&kr_access, "sel_write_access"))
		ok++;
	if (!reg(&kr_mountinfo, "show_mountinfo"))
		ok++;
	if (!reg(&kr_mounts, "show_vfsmnt"))
		ok++;

	pr_info(PFX "loaded, %d/6 hooks active\n", ok);
	return 0;
}

static void __exit dsb_exit(void)
{
	unregister_kretprobe(&kr_mounts);
	unregister_kretprobe(&kr_mountinfo);
	unregister_kretprobe(&kr_access);
	unregister_kretprobe(&kr_wrctx);
	unregister_kretprobe(&kr_procattr);
	unregister_kretprobe(&kr_ctx);
	pr_info(PFX "unloaded\n");
}

module_init(dsb_init);
module_exit(dsb_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DirtySepolicy Bypass - kernel side hiding");
MODULE_AUTHOR("DirtySepolicy Bypass");
