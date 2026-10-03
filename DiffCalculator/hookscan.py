"""Find SKSE hook sites in plugin source and check each one on the real executable.

Scans C++ sources for an Address Library ID paired with an in-function offset in one statement:

    RELOCATION_ID(se, ae) ... REL::VariantOffset(se, ae, vr)   REL::Relocate(se, ae[, vr])
    RELOCATION_ID(se, ae) ... OFFSET(se, ae) / OFFSET_3(se, ae, vr)
    REL::VariantID(se, ae, vr) ... any of the above
    REL::ID(ae) , 0x...        (AE-only plugins)

and checks the AE pair (the one a plugin built with ENABLE_SKYRIM_AE uses on 1.7.x) with
hooksite: the offset must land on an instruction boundary, and a hook site is normally a call,
jmp or the start of a patchable instruction. 1.7.x kept the AE IDs but moved code inside some
functions, so a 1.6.x offset can land mid-instruction; a 5-byte call written there corrupts the
game (2026-09-26, PapyrusTweaks 53919+0x664).

    python hookscan.py <source dir> [<source dir> ...] [--all]

Verdicts: MID = offset inside an instruction (a write there is corruption, always a bug);
CALL/JMP = site is a call/jmp (normal for write_call/write_branch); OTHER = boundary, but not a
branch, check it against the hook's patch; NOID = ID not in the 1.7.x library. --all prints
CALL/JMP rows too. Exit status 1 when any MID or NOID row exists.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hooksite  # noqa: E402

NUM = r"(0x[0-9A-Fa-f]+|\d+)"
ID2 = re.compile(r"(?:RELOCATION_ID|REL::RelocationID|RelocationID)\s*\(\s*" + NUM + r"\s*,\s*" + NUM + r"\s*\)")
VID = re.compile(r"(?:REL::)?VariantID\s*\(\s*" + NUM + r"\s*,\s*" + NUM + r"\s*,\s*" + NUM + r"\s*\)")
AEID = re.compile(r"REL::ID\s*\(\s*" + NUM + r"\s*\)\s*,\s*" + NUM + r"\s*[}\)]")
OFF = re.compile(r"(?:VariantOffset|Relocate|OFFSET_3|OFFSET)\s*\(\s*" + NUM + r"\s*,\s*" + NUM + r"(?:\s*,\s*" + NUM + r")?\s*\)")
EXTS = (".h", ".hpp", ".hxx", ".cpp", ".cxx", ".cc", ".inl", ".ixx")
SKIP_DIRS = {".git", "build", "out", "extern", "vendor", "vcpkg_installed", "external", "third_party", "third-party", "third-party-source", "node_modules"}


def statements(text):
    """Yield (line number, statement text) split on ';' and '{'/'}' so an ID and its offset stay together."""
    line = 1
    buf = []
    start = 1
    for ch in text:
        if not buf:
            start = line
        buf.append(ch)
        if ch == "\n":
            line += 1
        if ch in ";":
            yield start, "".join(buf)
            buf = []
    if buf:
        yield start, "".join(buf)


def sites_in(path):
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    text = re.sub(r"//[^\n]*", "", text)
    for line, st in statements(text):
        ids = [(int(m.group(2), 0), m) for m in ID2.finditer(st)] + [(int(m.group(2), 0), m) for m in VID.finditer(st)]
        offs = list(OFF.finditer(st))
        if ids and offs:
            for n, (ae, _) in enumerate(ids):
                o = offs[min(n, len(offs) - 1)]
                ae_off = int(o.group(2), 0)
                if ae_off:
                    yield line, ae, ae_off, " ".join(st.split())[:160]
        for m in AEID.finditer(st):
            vid, off = int(m.group(1), 0), int(m.group(2), 0)
            if off:
                yield line, vid, off, " ".join(st.split())[:160]


def classify(img, res, vid, off):
    try:
        base = res.rva(vid)
    except KeyError:
        return "NOID", None
    site = base + off
    insns = hooksite.sweep(img, base, off + 32)
    at = [i for i in insns if i.address <= site < i.address + i.size]
    if not at:
        return "MID", None
    i = at[0]
    if i.address != site:
        return "MID", i
    if i.mnemonic == "call":
        return "CALL", i
    if i.mnemonic == "jmp":
        return "JMP", i
    return "OTHER", i


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--exe", default=hooksite.DEFAULT_EXE)
    ap.add_argument("--lib", default=hooksite.DEFAULT_LIB)
    args = ap.parse_args(argv)
    img = hooksite.Image(args.exe)
    res = hooksite.Resolver(args.lib)
    bad = 0
    total = 0
    for root in args.roots:
        seen = set()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS and not d.lower().startswith("build")]
            for fn in filenames:
                if not fn.lower().endswith(EXTS):
                    continue
                path = os.path.join(dirpath, fn)
                for line, vid, off, st in sites_in(path):
                    key = (vid, off)
                    if key in seen:
                        continue
                    seen.add(key)
                    total += 1
                    verdict, ins = classify(img, res, vid, off)
                    if verdict in ("MID", "NOID"):
                        bad += 1
                    if verdict in ("CALL", "JMP") and not args.all:
                        continue
                    desc = ""
                    if ins is not None:
                        desc = "%s %s" % (ins.mnemonic, ins.op_str)
                        if verdict == "MID":
                            desc = "+%d into [%s] %s" % (off - (ins.address - res.rva(vid)), ins.bytes.hex(" "), desc)
                    rel = os.path.relpath(path, root)
                    print("%-5s %s:%d  %d+%#x  %s\n        %s" % (verdict, rel, line, vid, off, desc, st))
        print("-- %s: %d distinct sites" % (root, len(seen)))
    print("== %d sites, %d MID/NOID" % (total, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
