"""Check SKSE hook sites (Address Library ID + offset) against a real executable.

A plugin written for AE 1.6.x carries offsets like RELOCATION_ID(53108, 53919) + 0x664. The ID
still resolves on 1.7.x (meh321 carries AE IDs forward), but the function body can be laid out
differently, so the offset can land inside an instruction. Writing a 5-byte call there corrupts
the code and the game dies far from the plugin (2026-09-26: PapyrusTweaks' doc-string hook
turned `mov r9d,[rip+0x016E6D0B]` into `mov r9d,[rip-0x179192F5]` in the SkyrimVM ctor).

Usage (paths default to the Mosais build; override with --exe / --lib):
    python hooksite.py site 53919+0x664 54006+0x71 ...    instruction at each site, boundary check
    python hooksite.py calls 53919                          every call/jmp in the function, targets as IDs
    python hooksite.py dis 53919 [--from 0x600 --to 0x700]  linear disassembly of a range

The disassembly is a linear sweep from the function's entry, which is exact for MSVC code up to
the first jump table; a site reported "MID-INSTRUCTION" is corrupted by a write at that address.
"""

import argparse
import os
import struct
import sys

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import addrlib  # noqa: E402

DEFAULT_EXE = "D:/SteamLibrary/steamapps/common/Skyrim Special Edition/SkyrimSE.exe"
DEFAULT_LIB = "F:/Mosais/mods/Address Library for SKSE Plugins/SKSE/Plugins/versionlib-1-7-104-0.bin"


class Image:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        nsec = struct.unpack_from("<H", self.data, pe + 6)[0]
        optsz = struct.unpack_from("<H", self.data, pe + 20)[0]
        self.image_base = struct.unpack_from("<Q", self.data, pe + 24 + 24)[0]
        self.sections = []
        sec0 = pe + 24 + optsz
        for i in range(nsec):
            o = sec0 + 40 * i
            name = self.data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, rsize, raw = struct.unpack_from("<IIII", self.data, o + 8)
            self.sections.append((name, va, vsize, raw, rsize))

    def section_of(self, rva):
        for s in self.sections:
            if s[1] <= rva < s[1] + max(s[2], s[4]):
                return s
        return None

    def read(self, rva, n):
        s = self.section_of(rva)
        if s is None:
            raise ValueError("RVA %#x is in no section" % rva)
        off = s[3] + (rva - s[1])
        return self.data[off:off + n]


class Resolver:
    def __init__(self, lib_path):
        self.lib = addrlib.read_bin(lib_path)
        self.by_off = {}
        for vid, off in self.lib.values.items():
            self.by_off.setdefault(off, vid)

    def rva(self, vid):
        off = self.lib.values.get(vid)
        if not off:
            raise KeyError("ID %d is not assigned in %s" % (vid, self.lib.version_string))
        return off

    def name(self, rva):
        vid = self.by_off.get(rva)
        return "ID %d" % vid if vid is not None else None


def parse_site(text):
    vid, _, off = text.partition("+")
    return int(vid, 0), int(off, 0) if off else 0


def sweep(img, start_rva, length):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    code = img.read(start_rva, length)
    return list(md.disasm(code, start_rva))


def target_of(ins):
    if ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j"):
        op = ins.op_str
        if op.startswith("0x"):
            try:
                return int(op, 16)
            except ValueError:
                return None
    return None


def fmt(ins, res, mark=""):
    t = target_of(ins)
    tail = ""
    if t is not None:
        n = res.name(t)
        tail = "   -> %s" % (n if n else "%#x" % t)
    return "%s%#9x  %-24s %s %s%s" % (mark, ins.address, ins.bytes.hex(" "), ins.mnemonic, ins.op_str, tail)


def cmd_site(args, img, res):
    bad = 0
    for text in args.sites:
        vid, off = parse_site(text)
        base = res.rva(vid)
        site = base + off
        insns = sweep(img, base, off + 64)
        at = [i for i in insns if i.address <= site < i.address + i.size]
        print("%s  (ID %d at %#x, site %#x)" % (text, vid, base, site))
        if not at:
            print("  no instruction covers the site")
            bad += 1
            continue
        i = at[0]
        idx = insns.index(i)
        state = "boundary" if i.address == site else "MID-INSTRUCTION (+%d into it)" % (site - i.address)
        if i.address != site:
            bad += 1
        print("  %s" % state)
        for j in insns[max(0, idx - args.before):idx + args.after + 1]:
            print("  " + fmt(j, res, ">> " if j is i else "   "))
    return 1 if bad else 0


def cmd_calls(args, img, res):
    base = res.rva(args.id)
    insns = sweep(img, base, args.length)
    for i in insns:
        if i.mnemonic == "call" or (i.mnemonic == "jmp" and target_of(i) is not None and not (base <= target_of(i) < base + args.length)):
            print("  +%#06x " % (i.address - base) + fmt(i, res))
        if args.stop_at_int3 and i.mnemonic == "int3":
            break
    return 0


def cmd_dis(args, img, res):
    base = res.rva(args.id)
    frm = int(args.frm, 0)
    to = int(args.to, 0)
    insns = sweep(img, base, to + 16)
    for i in insns:
        if frm <= i.address - base < to:
            print("  +%#06x " % (i.address - base) + fmt(i, res))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--lib", default=DEFAULT_LIB)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("site")
    s.add_argument("sites", nargs="+")
    s.add_argument("--before", type=int, default=3)
    s.add_argument("--after", type=int, default=3)
    c = sub.add_parser("calls")
    c.add_argument("id", type=lambda x: int(x, 0))
    c.add_argument("--length", type=lambda x: int(x, 0), default=0x1000)
    c.add_argument("--stop-at-int3", action="store_true")
    d = sub.add_parser("dis")
    d.add_argument("id", type=lambda x: int(x, 0))
    d.add_argument("--from", dest="frm", default="0")
    d.add_argument("--to", default="0x100")
    args = ap.parse_args(argv)
    img = Image(args.exe)
    res = Resolver(args.lib)
    return {"site": cmd_site, "calls": cmd_calls, "dis": cmd_dis}[args.cmd](args, img, res)


if __name__ == "__main__":
    sys.exit(main())
