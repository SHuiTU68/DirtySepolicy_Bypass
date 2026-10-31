# DirtySepolicy Bypass

<div align="center">

![Downloads](https://img.shields.io/github/downloads/flipphoneguy/DirtySepolicy_Bypass/total)

</div>

Zygisk module that defeats [LSPosed/DirtySepolicy](https://github.com/LSPosed/DirtySepolicy)
up to v2.2, any detector using the same App-Zygote SELinux-probe technique, and
the SELinux / Zygisk / audit surfaces exercised by
[Duck-Detector](https://github.com/eltavine/Duck-Detector-Refactoring).

## Detection vectors covered

DirtySepolicy v2.2 probes from inside App Zygote:

1. **`contextExists()`** — writes context strings to `/sys/fs/selinux/context`,
   queries `/sys/fs/selinux/access`, then `/proc/self/attr/current`.
2. **`checkSELinuxAccess()`** — resolves class/perm ids from
   `/sys/fs/selinux/class/` and queries `/sys/fs/selinux/access` directly.
3. **`readStatus()` / `avdSeqNo`** — reads `/sys/fs/selinux/status` counters
   and the `seqno` field of `access` responses to spot policy reloads.
4. **Indirect stock-context probes** — allow rules between stock contexts that
   only exist after a framework injected them.

Duck-Detector adds:

- **Dirty-policy oracles** — `fsck_untrusted sys_admin`, `adbd → adbroot`,
  `untrusted_app → magisk/ksu/lsposed/xposed`, `droidspacesd`, `msd_app`,
  `msd_daemon`, `zygote → adb_data_file`, rootfs/kernel tmpfs rules, …
- **SELinux integrity probes** — `mmap` of `/sys/fs/selinux/status`,
  `avc/cache_stats` lookup counters, `attr/current` timing.
- **Audit integrity probes** — parses `logcat -b events` for `type=1400 avc:
  denied` records, actor names (`su/magisk/ksud/…`), ZN-AuditPatch markers
  (`zn-auditpatch`, `libauditpatch.so`, `logd PLT hook success`) and the fake
  `tcontext=u:r:priv_app:s0:c512,c768`.
- **Zygisk injection probes** — `dl_iterate_phdr` solist/namespaces,
  `/proc/self/{maps,smaps,status,fd,task}`, environment variables, deleted
  fd traps, heap entropy, atexit tables.

## Hook table

| Hook | Target | Effect |
|---|---|---|
| `open`/`openat` | selinuxfs `access`, `context`, `status`, `policy`, `avc/cache_stats` | Track and classify fds |
| `write` | `access`, `context`, `/proc/*/attr/*` | Block hidden-context writes, stash access queries |
| `read`/`pread64` | `access` | Mask hidden permission bits, exact probes, force `seqno=1` |
| `read` | `status` | Rewrite `sequence` / `policyload` for the kernel baseline |
| `read`/`pread64` | `policy` | Erase framework strings from the binary policy blob |
| `read`/`pread64` | `avc/cache_stats` | Zero lookup/hit/miss counters |
| `mmap`/`mmap64` | `status` | Return `EACCES` (blocks the mmap-ABI probe) |
| `open`/`openat`/`fopen`/`fopen64` | `/proc/self/{maps,smaps,status,comm}`, `task/*/comm` | Serve a scrubbed anonymous memfd copy |
| `readlink`/`readlinkat` | `/proc/self/fd/*` | `ENOENT` for module/deleted `.so` targets |
| `dl_iterate_phdr` | linker solist | Hide module entries |
| `getenv`/`secure_getenv` | `TMP_PATH`, `MAGISK*`, `ZYGISK*`, … | Return `NULL` |
| `__android_log_write/buf_write/print/vprint` | AVC audit records | Drop leaking lines at the source |
| `read`/`pread64` (≤8 KiB) | logcat-style streams | Drop leaking AVC lines that come back |
| `selinux_check_access` / `security_compute_av(_flags)` | libselinux API | Same masking, for library-based detectors |

All hooks are installed with Zygisk PLT hooking across every loaded `.so` in
every app and system_server process.

## Hidden type patterns (`jni/rules.h`)

| Pattern | Catches |
|---|---|
| `:magisk` | `magisk`, `magisk_file`, `magisk_log_file`, `magisk32`, ... |
| `:kitsune` | KitsuneMask types |
| `:apatch` | APatch types |
| `:ksu` / `:kernelsu` | KernelSU types |
| `:lsposed` | `lsposed_file`, any `lsposed_*` |
| `:xposed` | `xposed_data`, `xposed_file`, any `xposed_*` |
| `:riru` | `riru_file`, any `riru_*` |
| `:adbroot` | `adbroot`, `adbroot_exec`, `adbroot_data_file` |
| `:supersu` / `:supolicy` | SuperSU legacy types |
| `:su:` | AOSP `u:r:su:s0` (trailing colon avoids false positives) |
| `:zygisk` / `:zygisknext` / `:zygisksu` / `:neozygisk` / `:rezygisk` | Zygisk variants |
| `:shamiko` | Shamiko artifacts |
| `:droidspacesd` / `:msd_app` / `:msd_daemon` | Duck-Detector custom domains |
| `:auditpatch` | ZN-AuditPatch residue types |

## Exact-match probe table

| scon | tcon | class | perm | Detects |
|---|---|---|---|---|
| `rootfs` | `tmpfs` | `filesystem` | `associate` | Magisk |
| `kernel` | `tmpfs` | `fifo_file` | `open` | Magisk |
| `kernel` | `adb_data_file` | `file` | `read` | KernelSU |
| `system_server` | `apk_data_file` | `file` | `execute` | LSPosed |
| `dex2oat` | `dex2oat_exec` | `file` | `execute_no_trans` | Xposed |
| `zygote` | `adb_data_file` | `dir` | `search` | ZygiskNext |
| `fsck_untrusted` | `fsck_untrusted` | `capability` | `sys_admin` | Duck dirty-policy |

## Zygisk injection hiding

`jni/stealth.cpp` makes the injected library invisible to a normal app:

- `/proc/self/maps`, `/proc/self/smaps`, `/proc/self/status`,
  `/proc/self/comm` and `task/*/comm` are served from an anonymous
  `memfd:jit-cache` copy with module paths removed, `TracerPid` zeroed and
  suspicious thread names rewritten.
- `dl_iterate_phdr` entries pointing at `/data/adb`, `magisk`, `zygisk`,
  `lsposed`, … are skipped.
- `readlink`/`readlinkat` return `ENOENT` for module or deleted-`.so` targets.
- `getenv`/`secure_getenv` hide `TMP_PATH`, `MAGISK*`, `ZYGISK*`, `KSU*`, …

Scrubbing is enabled **only for ordinary, non-root app processes** (uid ≥
10000 and without `PROCESS_GRANTED_ROOT`). Root-granted apps and
`system_server` keep the real `/data/adb` mappings, fd targets and linker
solist, so root tooling and the shell are unaffected.

`jni/avc.cpp` is a ZygiskNext-free port of [ZN-AuditPatch](https://github.com/aviraxp/ZN-AuditPatch):
instead of injecting `logd` it drops leaking AVC records from
`__android_log_*` and from `read()` buffers, so `logcat -b events` no longer
shows the hidden contexts. It never fabricates `u:r:priv_app:s0:c512,c768`,
which Duck-Detector treats as a forgery marker.

## Build

Two supported paths:

```sh
# GitHub Actions: .github/workflows/build.yml builds all ABIs and uploads
# dirtysepbypass-module (zip) as an artifact, and attaches it to tagged releases.

# Local build (Android NDK r26+ and python3):
export ANDROID_NDK_HOME=/path/to/ndk
./tools/build.sh
# -> dist/dirtysepbypass-v4.0.0.zip
```

`tools/build.sh` runs `ndk-build` for arm64-v8a, armeabi-v7a, x86 and x86_64,
copies each `libdirtysepbypass.so` to `module/zygisk/<abi>.so`, then packages
the flashable zip.

<details>
<summary>Manual single-ABI build (Termux)</summary>

```sh
cd jni
aarch64-linux-android-clang++ \
  -std=c++17 -fno-exceptions -fno-rtti \
  -fPIC -shared -O2 \
  -fvisibility=hidden -fvisibility-inlines-hidden \
  -fdata-sections -ffunction-sections \
  -nostdlib++ -Wall -Wextra \
  -Wl,--hash-style=both -Wl,--gc-sections \
  -Wl,-soname,libdirtysepbypass.so \
  -o ../module/zygisk/arm64-v8a.so \
  module.cpp stealth.cpp avc.cpp -llog
patchelf --remove-rpath ../module/zygisk/arm64-v8a.so
```

Add `-DDEBUG` for verbose logging.

</details>

## Install

Via Magisk app: **Modules > Install from storage > select the zip > Reboot.**
Or from a root shell:

```sh
su -c "magisk --install-module /sdcard/dirtysepbypass.zip"
su -c reboot
```

## Verify

1. Open DirtySepolicy. A successful bypass shows:

   ```
   OK: no dirty sepolicy found
   INFO: sequence=0 policyload=0
   ```

   Kernel < 6.10: `sequence=0 policyload=0`; kernel ≥ 6.10:
   `sequence=4 policyload=1`.

2. Run the audit tool (raw kernel state vs. hook tables):

   ```sh
   su -c "python3 tools/audit.py"
   ```

3. Debug builds log under the `selinuxfs` tag:

   ```sh
   su -c "logcat -d -s selinuxfs"
   ```

## Extending the bypass

If `audit.py` reports a `LEAK`:

- **New context name:** add the substring to `jni/rules.h` (`kHiddenTokens`)
  and `HOOK_BLOCKLIST` in `tools/audit.py`.
- **New indirect stock-context probe:** add the tuple to `kHiddenExact[]` in
  `jni/module.cpp` and `HOOK_EXACT_PROBES` in `tools/audit.py`.
- **New path / binary token:** extend `restricted_path()` / `kBinaryTokens`
  in `jni/rules.h`.

Rebuild, reflash, reboot, re-audit.

## Limitations

- **Substring blocklist.** New frameworks with novel type names need manual
  additions.
- **Exact-match table.** New indirect probes using stock contexts need manual
  additions.
- **No logd injection.** A plain Magisk Zygisk module cannot inject `logd`
  (this is what ZygiskNext provides to ZN-AuditPatch). Records are dropped
  inside hooked processes and when read back through `read()`; AVC records
  produced by entirely unhooked processes are not rewritten. `logcat` itself
  launched by the detector inherits the hook, so its child output is filtered.
- **Binary policy scrub is chunk-local.** A framework string split across two
  reads cannot be erased; a detector that reads the whole blob in one
  `read()` is covered.
- **Status values.** `sequence`/`policyload` patches assume the standard
  clean-boot baselines listed above.
- **memfd artifact.** Scrubbed files are served from `memfd:jit-cache`
  (a name ART also uses); the fd target remains visible as an anonymous
  inode by design.

## Compatibility

| Requirement | Notes |
|---|---|
| arm64-v8a, armeabi-v7a, x86, x86_64 | Built for all four ABIs. |
| Android >= 10 | App Zygote detection surface was added in Android 10. |
| Magisk >= 24 + Zygisk | Requires Zygisk API v5. KitsuneMask also works. |

## License

Apache 2.0
