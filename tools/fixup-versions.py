#!/usr/bin/env python3
"""Make a kernel .ko loadable on any GKI build of the same KMI.

Two things tie a module to a specific kernel build:

  * the vermagic string, and
  * the MODVERSIONS CRC table (__versions).

The kernel skips the release part of the vermagic when __versions is
present, so the module only has to match the configuration suffix
(" SMP preempt mod_unload modversions aarch64").  CRCs, however, are
computed from the exact source tree that built the kernel, and a module
built against a different tree gets "disagrees about version of symbol".

check_version() in kernel/module/version.c treats a __versions section
that exists but contains no matching entry as "broken toolchain, warn
once, let it go".  So the fix is to keep the section but empty it: the
release prefix is ignored, every symbol resolves, and the kernel only
prints one harmless "no symbol version" warning per load.

This script does that and sanity-checks the result.
"""

import struct
import sys

ELF_MAGIC = b"\x7fELF"
SHN_UNDEF = 0
SECTION_NAME = "__versions"
MODINFO_NAME = ".modinfo"


def read_elf(path):
    with open(path, "rb") as fh:
        data = bytearray(fh.read())

    if data[:4] != ELF_MAGIC or data[4] != 2 or data[5] != 1:
        raise SystemExit(f"{path}: not a little-endian ELF64 file")

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    def shdr(idx):
        off = e_shoff + idx * e_shentsize
        return {
            "offset": off,
            "name": struct.unpack_from("<I", data, off + 0x00)[0],
            "type": struct.unpack_from("<I", data, off + 0x04)[0],
            "flags": struct.unpack_from("<Q", data, off + 0x08)[0],
            "addr": struct.unpack_from("<Q", data, off + 0x10)[0],
            "sh_offset": struct.unpack_from("<Q", data, off + 0x18)[0],
            "size": struct.unpack_from("<Q", data, off + 0x20)[0],
            "addralign": struct.unpack_from("<Q", data, off + 0x30)[0],
        }

    strtab = shdr(e_shstrndx)
    names = data[strtab["sh_offset"]:strtab["sh_offset"] + strtab["size"]]

    sections = {}
    for idx in range(e_shnum):
        sh = shdr(idx)
        end = names.find(b"\x00", sh["name"])
        sh["name"] = names[sh["name"]:end].decode("utf-8", "replace")
        sections[sh["name"]] = sh

    return data, sections


def section_strings(data, sh):
    raw = data[sh["sh_offset"]:sh["sh_offset"] + sh["size"]]
    return [s.decode("utf-8", "replace") for s in raw.split(b"\x00") if s]


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <module.ko>")
    path = sys.argv[1]
    data, sections = read_elf(path)

    if MODINFO_NAME not in sections:
        raise SystemExit(f"{path}: no {MODINFO_NAME} section")

    vermagic = ""
    for line in section_strings(data, sections[MODINFO_NAME]):
        if line.startswith("vermagic="):
            vermagic = line[len("vermagic="):]
            break
    if "modversions" not in vermagic:
        raise SystemExit(f"{path}: unexpected vermagic: {vermagic!r}")
    suffix = vermagic.split(" ", 1)[1] if " " in vermagic else ""
    if "preempt" not in suffix or "mod_unload" not in suffix:
        raise SystemExit(f"{path}: unexpected vermagic suffix: {suffix!r}")

    if SECTION_NAME not in sections:
        raise SystemExit(
            f"{path}: no {SECTION_NAME} section; refusing to build a module "
            "that can only be loaded with modprobe --force"
        )

    sh = sections[SECTION_NAME]
    if sh["size"]:
        # sh_size lives at 0x20 inside a 64-byte Elf64_Shdr.
        struct.pack_into("<Q", data, sh["offset"] + 0x20, 0)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"cleared {SECTION_NAME} ({sh['size']} bytes)")
    else:
        print(f"{SECTION_NAME} already empty")

    print(f"vermagic: {vermagic}")


if __name__ == "__main__":
    main()
