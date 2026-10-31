# DirtySepolicy Bypass

<div align="center">

![Downloads](https://img.shields.io/github/downloads/SHuiTU68/DirtySepolicy_Bypass/total)

</div>

从 v5.0.0 开始，本模块**不再使用 Zygisk 注入**，改为一个可加载内核模块
（`dsb_kmod.ko`，由 Magisk 在 `post-fs-data` 阶段 `insmod`）。隐藏逻辑放在
内核里，探测应用无论用什么手段（原生 `syscall`、隔离进程、`app_zygote`
载体、直接读 `selinuxfs`）都得经过这些内核函数，因此覆盖面比进程内 PLT
hook 完整得多。

模块面向 **arm64、6.6 GKI 内核**（已在 OnePlus MT6991 /
`oneplus/mt6991_b_16.0.0_oneplus_ace5_ultra` 的
`6.6.118-4k-g1d453aabd9c2` 上构建验证），针对
[LSPosed/DirtySepolicy](https://github.com/LSPosed/DirtySepolicy) 与
[Duck-Detector](https://github.com/eltavine/Duck-Detector-Refactoring) 暴露的
SELinux / 挂载表检测项。

## 为什么放弃 Zygisk

上传的 Duck-Detector 报告（`PLC110`，2026-10-31）说明了进程内方案的边界：

| 报告里的现象 | 进程内 hook 为什么挡不住 |
|---|---|
| SELinux 上下文被识别为 `CONTEXT_RECOGNIZED` | 探测跑在 `app_zygote` 的隔离载体里，Zygisk 根本没有注入；并且它用原生 `open/write/read` 直读 `selinuxfs`，不经过 libselinux 的 PLT |
| `raw access` 出现 7 条"脏边"（rootfs→tmpfs、kernel→tmpfs、system_server→apk_data_file …） | `access` 的应答由内核 `sel_write_access` 生成，用户态只能改自己进程里读到的内容，改不了另一个进程 |
| Mount `DANGER`：`source=magisk`、`/debug_ramdisk`、`/adb/modules/PUIThemeCustomized/…` | `/proc/<pid>/mountinfo` 是全局视图，注入不到的应用照样能看到 |
| Memory `DANGER`：匿名可执行映射、`maps` 里的 `zygisk/arm64-v8a.so` | 后者是 Zygisk 自身的产物，去掉注入即消失 |

结论：要在**所有**探测路径上一致地隐藏，必须在内核侧做。

## 架构

`kmod/dsb_kmod.c` 安装 6 个 kretprobe，全部只对 **uid ≥ 10000** 的调用者
生效（普通应用、隔离进程 `90000+`、`app_zygote` 子进程都在内），root
（0）、shell（2000）、system（1000）与所有系统服务保持原样，框架照常运行。

| # | 目标函数 | 动作 |
|---|---|---|
| 1 | `security_context_to_sid` | 命中隐藏上下文时把成功（0）改成 `-EINVAL` |
| 2 | `selinux_setprocattr` | 写 `/proc/<pid>/attr/current` 命中隐藏上下文时返回 `-EINVAL` |
| 3 | `sel_write_context` | 写 `/sys/fs/selinux/context` 命中隐藏上下文时返回 `-EINVAL` |
| 4 | `sel_write_access` | 查询涉及隐藏上下文或脏边时，把 `access` 的六字段应答重写为全拒绝 |
| 5 | `show_mountinfo` | `/proc/<pid>/mountinfo` 命中隐藏挂载的行整行丢弃 |
| 6 | `show_vfsmnt` | `/proc/<pid>/mounts` 同上 |

### 上下文"不存在"比"存在但被拒"更安全

`/sys/fs/selinux/context` 与 `/proc/<pid>/attr/current` 对合法但被策略拒绝
的上下文返回 `EACCES(13)`，对策略里不存在的上下文返回 `EINVAL(22)`。
Duck 正是用这个差别判定 `magisk`/`magisk_file`/`lsposed_file` 的存在
（`CONTEXT_RECOGNIZED`）。hook 1–3 让这些名字一律表现为"策略里根本没有"，
与 KernelSU 的内核隐藏思路一致。

隐藏上下文匹配表（子串，覆盖 domain / file type / property type）：

```
magisk  lsposed  zygisk  kernelsu  ksu  apatch  adbroot  xposed
droidspaces  msd_app  msd_daemon  auditpatch  dirtysep  dsb_
```

### 脏边应答改写

hook 4 在 **entry** 里用查询字符串（`scon tcon tclass`）判断，不需要 SID
查找、不遍历策略，也完全不引用 SELinux 内部结构；命中后记下 `buf` 指针，
在返回处把

```
allowed  decided  auditallow  auditdeny  seqno  flags
```

重写成 `0 ffffffff 0 <auditdeny> <seqno> <flags>`，返回长度同步改成新长度
（`selinux_transaction_write` 用它来设置 transaction 长度）。覆盖的脏边：

| scon | tcon | 检测项 |
|---|---|---|
| `system_server` | `system_server` | execmem |
| `system_server` | `apk_data_file` | LSPosed 注入 |
| `zygote` | `adb_data_file` | ZygiskNext |
| `kernel` | `adb_data_file` | KernelSU |
| `kernel` | `tmpfs` | Magisk fifo |
| `rootfs` | `tmpfs` | Magisk associate |
| `dex2oat` | `dex2oat_exec` | Xposed |
| `fsck_untrusted` | `fsck_untrusted` | Dirty 策略 |
| `shell` | `su` | root 提权痕迹 |
| `adbd` | `adbroot` | adb root |
| `untrusted_app` | `magisk_file` | Magisk |
| `untrusted_app` | `lsposed_file` | LSPosed |

对照报告，控制项保持 ALLOWED（`app_zygote→app_zygote setcurrent`、
`app_zygote→kernel check_context`、`app_zygote→isolated_app dyntransition`）
和已经 DENIED 的项（`fsck_untrusted sys_admin`、`shell→su transition`、
`kernel→adb_data_file read`）都不在改写列表里。

### 挂载表

hook 5/6 在 entry 记录 `seq_file->count`，返回后若新增片段命中
`magisk`、`/adb/modules`、`/debug_ramdisk`、`/data/adb`、`/data/local/tmp`、
`lsposed`、`zygisk`、`kernelsu`、`apatch`、`/sbin` 之一，就把
`m->count` 回退到调用前的值——整行不出现，而不是在用户态做字符串替换。

## 模块保护与加载

设备内核是 GKI：`CONFIG_MODULE_SIG_PROTECT=y`（但无 `MODULE_SIG_FORCE`），
因此未签名模块可以加载，但被当作 vendor 模块，只能使用
`include/config/abi_gki_kmi_symbols`（vendor KMI 列表并集）里的符号。
本模块只需要 `register_kretprobe`、`unregister_kretprobe`、`_printk`、
`__stack_chk_fail` 和 `module_layout`，这些都在该并集里
（`register_kretprobe` 来自 QCOM 列表，`_printk`/`__stack_chk_fail` 来自
MTK 列表，`module_layout` 来自基线列）。

`CONFIG_MODVERSIONS=y` 的 CRC 校验靠 `tools/fixup-versions.py` 处理：
构建时没有 `Module.symvers`，`__versions` 节为空但**存在**。内核
`check_version()` 在节存在、无匹配条目时只打印一次警告并放行
（`versindex == 0` 才会走 `try_to_force_load`，那才是必须 `--force` 的
情况）；同时 `same_magic()` 因为 `__versions` 存在而跳过版本号前缀，
所以 CI 里从 codeload 下载的无 `.git` 源码树（vermagic 没有 `-g` 哈希）
也能加载。

## 构建

### GitHub Actions

`.github/workflows/build.yml` 安装 clang/lld/llvm 与内核构建依赖，缓存
`.kout`，调用 `tools/build.sh`，产出 `dirtysepbypass-module` artifact，
打 tag 时自动附到 release。

### 本地

```sh
sudo apt-get install -y clang lld llvm make bc flex bison libelf-dev \
                        libssl-dev dwarves python3 curl

# 复用已有内核源码/输出目录（推荐）
KERNEL_SRC=/path/to/android_kernel_oneplus_mt6991 KERNEL_OUT=/path/to/out \
  ./tools/build.sh
# 或不指定，脚本按固定 SHA 自动下载到 .kernel / .kout
./tools/build.sh
# -> dist/dirtysepbypass-v5.0.0.zip
```

`tools/build.sh` 执行 `gki_defconfig` → `modules_prepare` →
`M=kmod modules`，用 `fixup-versions.py` 清空 `__versions`，把
`dsb_kmod.ko` 放进 `module/kmod/`，再用 Python 打包 zip（`customize.sh`/
`post-fs-data.sh`/`update-binary` 置 0755）。

## 安装

Magisk 应用：**模块 → 从本地安装 → 选择 zip → 重启**。或：

```sh
su -c "magisk --install-module /sdcard/dirtysepbypass.zip"
su -c reboot
```

`post-fs-data.sh` 在 zygote 启动前 `insmod`，因此之后启动的所有应用都被
覆盖。`sepolicy.rule` 只为 magisk 域补上 `capability:sys_module` 和
`system:module_load`（`init_module` 会对调用者自身 SID 检查这两项）。

## 验证

```sh
# 1. 模块是否加载
cat /data/adb/modules/dirtysepbypass/load.log
dmesg | grep dsb_kmod
# 期望：hooked <6 个函数> / loaded, 6/6 hooks active

# 2. 以普通应用身份看不到 root 挂载（shell 看不到属正常）
su -c "su 2000 -c 'cat /proc/self/mountinfo'" | grep -Ei 'magisk|/adb/modules|/debug_ramdisk'

# 3. 复跑 Duck-Detector，SELinux/Mount 两项应不再报 DANGER
```

卸载：Magisk 里移除模块并重启（内核模块随重启消失）。

## 参考实现

- [Admirepowered/selinux_hook](https://github.com/Admirepowered/selinux_hook)
  —— 在 `security_context_to_sid` 上做 kprobe 的思路
- [tiann/KernelSU](https://github.com/tiann/KernelSU) —— 内核侧 SELinux 隐藏
- [maxsteeel/nomount](https://github.com/maxsteeel/nomount) —— mount 表隐藏的 LKM 实现

## 限制

- **只对普通应用（uid ≥ 10000）隐藏。** root、shell、system 与系统服务看到
  的仍是真实状态，这是刻意设计；如果检测器以 shell/root 身份运行，不在
  覆盖范围内。
- **仅 arm64 + 匹配的 GKI KMI。** 需要内核允许 kretprobe（本机
  `CONFIG_KPROBES=y`、`CONFIG_KALLSYMS_ALL=y`）并允许加载未签名模块。
  `security_context_to_sid`、`selinux_setprocattr`、`sel_write_*`、
  `show_mountinfo`、`show_vfsmnt` 都必须存在于 kallsyms（本机满足）。
- **子串黑名单。** 新框架的新类型名需要手动加进 `hidden_ctx_parts[]`；新
  的脏边需要加进 `dirty_pairs[]`。
- **挂载行整行丢弃。** 只处理 `/proc/<pid>/mountinfo` 和 `/proc/<pid>/mounts`；
  `statfs`/`getmntent` 以外的其他来源（例如 `/proc/self/mountstats`）未处理。
- **内核侧可检测性。** kprobe 对 root 可见（`/sys/kernel/debug/kprobes/list`、
  `dmesg`），普通应用不可见；模块本身也无法隐藏自己的 `insmod` 痕迹。
- **Memory 项。** 报告中的匿名可执行映射是 ART JIT 的正常行为，本模块
  不做处理；`maps` 里的 `zygisk/*.so` 已随 Zygisk 方案一起移除。
- **Dangerous Apps（Scene/HMA）。** 与 SELinux 隐藏无关，本模块不涉及。

## 许可

Apache 2.0
