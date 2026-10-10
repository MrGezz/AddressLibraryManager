"""Carry an AE in-function hook offset from 1.6.x to 1.7.x by matching the code around it.

Plugins written for AE 1.6.x hook `ID + offset`. 1.7.x kept the IDs but re-laid some function
bodies, so the offset can point at a different instruction (PapyrusTweaks 53919+0x664 on 1.7.104:
the call it wanted moved to +0x69C). This takes the instruction window at the offset in a
reference 1.6.x executable (decrypted with steamstub.py), finds the same window in the target
executable's copy of the function, and reports the new offset.

    python hookport.py site 53919+0x664 [...]            one or more sites
    python hookport.py scan <source dir> [...] [--all]  every site hookscan.py finds in the sources

Normalisation: a RIP-relative operand or branch target becomes the Address Library ID it points
at (resolved per version), an in-function branch becomes "J", so the window compares what the
code does, not where it sits. Verdicts:
  SAME     the window is at the same offset on the target (the hook is fine as written)
  MOVED    found at exactly one other offset: the source needs a 1.7.x offset
  AMBIG    found at several offsets (the nearest is printed; decide by hand)
  NOMATCH  not found; check the function by hand (hooksite.py dis)
  REFMID   the offset is not an instruction boundary on the reference either: it was written
           for another 1.6.x build, or it is not a code offset
  NOID     the ID is not in one of the libraries
  PORTED   (scan) the source names a 1.7.x offset of its own and the 1.6 site is carried to exactly it
  MISPORT  (scan) the source names a 1.7.x offset and the 1.6 site is carried somewhere else, or nowhere

When no window matches - a recompiled function differs in a register or a member offset around the site - a
site that is a direct call (or jmp out of the function) to a function with an ID is carried by call order: both
builds of the function make equally many such calls to it, and the n-th there is the n-th here. With one call
on each side that is SAME or MOVED outright (the line says "the only call"); with several it is SAME# / MOVED#
and wants one look at the site (hooksite.py site). A trailing "~" is the relaxed window (the site instruction and
the ones after it); a SAME~ whose site is also the only call to its function on both sides is SAME.
Exit status 1 when anything other than SAME or PORTED was printed.
"""

import argparse
import bisect
import os
import re
import struct
import sys

import capstone
from capstone import x86

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hooksite  # noqa: E402
import hookscan  # noqa: E402

LIBDIR = "F:/Mosais/mods/Address Library for SKSE Plugins/SKSE/Plugins"
DEFAULT_REF_EXE = "D:/b/ref/SkyrimSE-1.6.318.unpacked.exe"
DEFAULT_REF_LIB = LIBDIR + "/versionlib-1-6-318-0.bin"
WINDOW_BEFORE = 2
WINDOW_AFTER = 3


class Side:
    def __init__(self, exe, lib):
        self.img = hooksite.Image(exe)
        self.res = hooksite.Resolver(lib)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.md.skipdata = True
        self.pdata = self._pdata()

    def _pdata(self):
        ends = {}
        self.unwind = {}
        for name, va, vsize, raw, rsize in self.img.sections:
            if name == ".pdata":
                d = self.img.data[raw:raw + vsize]
                for o in range(0, len(d) - 11, 12):
                    b, e, u = struct.unpack_from("<III", d, o)
                    if b:
                        ends[b] = e
                        self.unwind[b] = u
        return ends

    def whole(self, base):
        """End of the function at base with every chunk the compiler split it into: the .pdata entry that starts
        where the last one ended belongs to it when its unwind info is chained (UNW_FLAG_CHAININFO). None when the
        function has no .pdata entry."""
        end = self.pdata.get(base)
        while end in self.pdata:
            try:
                chained = self.img.read(self.unwind[end], 1)[0] >> 3 & 4
            except ValueError:
                break
            if not chained:
                break
            end = self.pdata[end]
        return end

    def function(self, vid, need):
        base = self.res.rva(vid)
        end = self.pdata.get(base)
        length = max((end - base) if end else 0, need + 0x40, 0x200)
        code = self.img.read(base, length)
        return base, list(self.md.disasm(code, base))

    def extent(self, base, insns):
        """[base, end) of the function's own body: its .pdata entry, else the sweep."""
        end = self.pdata.get(base)
        return end if end else insns[-1].address + insns[-1].size

    def norm(self, ins, base, end):
        mn = ins.mnemonic
        parts = []
        if ins.id and ins.op_count(x86.X86_OP_IMM) and (mn == "call" or mn.startswith("j")):
            t = ins.operands[0].imm
            if mn != "call" and base <= t < end:
                return mn + " J"
            n = self.res.by_off.get(t)
            return "%s ID%s" % (mn, n if n is not None else "?")
        for op in (ins.operands if ins.id else []):
            if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                n = self.res.by_off.get(t)
                parts.append("[ID%s]" % n if n is not None else "[rip]")
        s = ins.op_str
        if parts:
            s = re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", lambda m, it=iter(parts): next(it), s)
        return mn + " " + s


def window(side, insns, idx, base, end, before, after):
    lo = max(0, idx - before)
    return [side.norm(i, base, end) for i in insns[lo:idx + after + 1]], idx - lo


def port(ref, tgt, vid, off, before=WINDOW_BEFORE, after=WINDOW_AFTER):
    try:
        rbase, rins = ref.function(vid, off)
        tbase, tins = tgt.function(vid, off + 0x400)
    except KeyError:
        return "NOID", None, ""
    rsite = rbase + off
    idx = [k for k, i in enumerate(rins) if i.address == rsite]
    if not idx:
        return "REFMID", None, ""
    idx = idx[0]
    rend = ref.extent(rbase, rins)
    tend = tgt.extent(tbase, tins)
    tnorm = [tgt.norm(i, tbase, tend) for i in tins]
    desc = "%s %s" % (rins[idx].mnemonic, rins[idx].op_str)
    # the full window first; then relaxed ("~"): the site instruction and the ones after it only
    for lead, mark in ((before, ""), (0, "~")) if before else ((0, ""),):
        want, pos = window(ref, rins, idx, rbase, rend, lead, after)
        hits = []
        for k in range(pos, len(tins) - (len(want) - pos) + 1):
            if tnorm[k - pos:k - pos + len(want)] == want:
                hits.append(tins[k].address - tbase)
        if off in hits:
            if mark:
                # the relaxed window and the call order agree: two independent readings of one site
                found = by_calls(ref, tgt, rins, tins, idx, rbase, tbase, rend, tend)
                if found and found[0] == "SAME":
                    return "SAME", off, "%s   [relaxed window; %s]" % (desc, found[2])
            return "SAME" + mark, off, desc
        if len(hits) == 1:
            return "MOVED" + mark, hits[0], desc
        if hits:
            return "AMBIG" + mark, min(hits, key=lambda h: abs(h - off)), desc
    found = by_calls(ref, tgt, rins, tins, idx, rbase, tbase, rend, tend)
    if found:
        return found[0], found[1], "%s   [%s]" % (desc, found[2])
    return "NOMATCH", None, desc


def direct_target(ins):
    if ins.id and ins.mnemonic in ("call", "jmp") and ins.op_count(x86.X86_OP_IMM):
        return ins.operands[0].imm
    return None


def by_calls(ref, tgt, rins, tins, idx, rbase, tbase, rend, tend):
    """(verdict, target offset, note) for a site that is a direct call - or a jmp out of the function - to a
    function with an ID, when the target's copy of the function makes as many of them; None otherwise."""
    site = rins[idx]
    there = direct_target(site)
    if there is None or (site.mnemonic == "jmp" and rbase <= there < rend):
        return None
    vid = ref.res.by_off.get(there)
    if vid is None:
        return None
    try:
        here = tgt.res.rva(vid)
    except KeyError:
        return None

    def sites(side, base, insns, end, target):
        whole = side.whole(base)
        if whole:
            insns = side.md.disasm(side.img.read(base, whole - base), base)
            end = whole
        return [i.address - base for i in insns if i.address < end and i.mnemonic == site.mnemonic and direct_target(i) == target]

    rsites = sites(ref, rbase, rins, rend, there)
    tsites = sites(tgt, tbase, tins, tend, here)
    if len(rsites) != len(tsites) or site.address - rbase not in rsites:
        return None
    n = rsites.index(site.address - rbase)
    same = tsites[n] == site.address - rbase
    if len(rsites) == 1:
        return ("SAME" if same else "MOVED"), tsites[n], "the only %s to ID %d on both" % (site.mnemonic, vid)
    return ("SAME#" if same else "MOVED#"), tsites[n], "%s %d of %d to ID %d" % (site.mnemonic, n + 1, len(rsites), vid)


VTABLE_HEADER = "D:/b/clib/ng-9.0.1/include/RE/Offsets_VTABLE.h"


def vtable_ids(header=VTABLE_HEADER):
    """VTABLE_<Name> -> list of AE IDs (one per vtable of the class), from CommonLibSSE-NG's table."""
    out = {}
    text = open(header, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r"VTABLE_(\w+)\{\s*((?:REL::VariantID\([^)]*\)\s*,?\s*)+)\}", text):
        out[m.group(1)] = [int(v.split(",")[1]) for v in re.findall(r"VariantID\(([^)]*)\)", m.group(2))]
    return out


def vtable_slot(side, vid, slot):
    base = side.res.rva(vid)
    ptr = struct.unpack("<Q", side.img.read(base + 8 * slot, 8))[0] - side.img.image_base
    return side.res.by_off.get(ptr), ptr


def vtable_port(ref, tgt, vid, slot, span=64):
    """SAME when the slot holds the same function ID on both; MOVED(n) when the reference slot's function sits
    at slot n on the target; NOMATCH otherwise (the function has no ID, or it is gone from this vtable)."""
    rid, rptr = vtable_slot(ref, vid, slot)
    tid, _ = vtable_slot(tgt, vid, slot)
    if rid is not None and rid == tid:
        return "SAME", slot, rid
    if rid is not None:
        for n in range(max(0, slot - span), slot + span):
            try:
                if vtable_slot(tgt, vid, n)[0] == rid:
                    return "MOVED", n, rid
            except (ValueError, struct.error):
                break
    return "NOMATCH", None, rid if rid is not None else "%#x" % rptr


ID_PATTERNS = [
    re.compile(r"(?:RELOCATION_ID|RelocationID)\s*\(\s*(\d+)\s*,\s*(\d+)"),
    re.compile(r"VariantID\s*\(\s*(\d+)\s*,\s*(\d+)\s*,"),
]


def source_ids(roots):
    """AE IDs named in C++ sources: {id: first 'file:line'}; plus VTABLE_<Name> names used."""
    ids, vtables = {}, {}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [x for x in dirnames if x.lower() not in hookscan.SKIP_DIRS and not x.lower().startswith("build")]
            for fn in filenames:
                if not fn.lower().endswith(hookscan.EXTS):
                    continue
                path = os.path.join(dirpath, fn)
                for ln, line in enumerate(open(path, encoding="utf-8", errors="replace"), 1):
                    code = line.split("//")[0]
                    for pat in ID_PATTERNS:
                        for m in pat.finditer(code):
                            ids.setdefault(int(m.group(2)), "%s:%d" % (os.path.relpath(path, root), ln))
                    for m in re.finditer(r"VTABLE_(\w+)", code):
                        vtables.setdefault(m.group(1), "%s:%d" % (os.path.relpath(path, root), ln))
    return ids, vtables


def text_section(side):
    for name, va, vsize, raw, rsize in side.img.sections:
        if name == ".text":
            return va, side.img.data[raw:raw + vsize]


def remap_by_callers(ref, tgt, vid):
    """A function the target library dropped: find each reference caller's call to it, and read which ID the
    same caller calls at the same offset on the target. Returns {new_id: [(caller_id, offset)]}."""
    target = ref.res.rva(vid)
    va, code = text_section(ref)
    starts = sorted(ref.pdata)
    found = {}
    for i in range(len(code) - 5):
        if code[i] != 0xE8 or va + i + 5 + struct.unpack_from("<i", code, i + 1)[0] != target:
            continue
        k = bisect.bisect_right(starts, va + i) - 1
        fstart = starts[k] if k >= 0 else None
        cid = ref.res.by_off.get(fstart)
        if cid is None:
            continue
        try:
            tb, tins = tgt.function(cid, (va + i - fstart) + 0x40)
        except KeyError:
            continue
        for ins in tins:
            if ins.address - tb == va + i - fstart and ins.mnemonic == "call" and ins.op_str.startswith("0x"):
                nid = tgt.res.by_off.get(int(ins.op_str, 16))
                found.setdefault(nid, []).append((cid, va + i - fstart))
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref-exe", default=DEFAULT_REF_EXE)
    ap.add_argument("--ref-lib", default=DEFAULT_REF_LIB)
    ap.add_argument("--exe", default=hooksite.DEFAULT_EXE)
    ap.add_argument("--lib", default=hooksite.DEFAULT_LIB)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("site")
    s.add_argument("sites", nargs="+")
    c = sub.add_parser("scan")
    c.add_argument("roots", nargs="+")
    c.add_argument("--all", action="store_true")
    v = sub.add_parser("vtable", help="Class:slot[:vtable#] ... e.g. JumpHandler:0x4 BSWaterShader:0x6 VirtualMachine:0x3:3")
    v.add_argument("items", nargs="+")
    i = sub.add_parser("ids", help="every AE ID and VTABLE_ name in the sources must exist on the target")
    i.add_argument("roots", nargs="+")
    args = ap.parse_args(argv)
    ref = Side(args.ref_exe, args.ref_lib)
    tgt = Side(args.exe, args.lib)
    bad = 0
    if args.cmd == "ids":
        ids, vtables = source_ids(args.roots)
        vt = vtable_ids()
        for name, where in sorted(vtables.items()):
            for vid in vt.get(name, []):
                ids.setdefault(vid, "VTABLE_%s (%s)" % (name, where))
        for vid, where in sorted(ids.items()):
            if tgt.res.lib.values.get(vid):
                continue
            bad += 1
            onref = bool(ref.res.lib.values.get(vid))
            remap = remap_by_callers(ref, tgt, vid) if onref else {}
            print("MISSING  AE %-7d %s  (on 1.6.318: %s)%s" % (vid, where, "yes" if onref else "no",
                  "  remap: " + ", ".join("ID %s via %s" % (n, ["%d+%#x" % c for c in cs]) for n, cs in remap.items()) if remap else ""))
        print("== %d AE IDs checked, %d missing on the target" % (len(ids), bad))
        return 1 if bad else 0
    if args.cmd == "vtable":
        ids = vtable_ids()
        for item in args.items:
            parts = item.split(":")
            name, slot = parts[0], int(parts[1], 0)
            which = int(parts[2], 0) if len(parts) > 2 else 0
            if name not in ids:
                print("NOVTBL   %s (no VTABLE_%s in %s)" % (item, name, VTABLE_HEADER))
                bad += 1
                continue
            vid = ids[name][which]
            verdict, n, fid = vtable_port(ref, tgt, vid, slot)
            bad += verdict != "SAME"
            print("%-8s %s[%d] (AE %d) slot %#x -> %s   fn %s" % (verdict, name, which, vid, slot, "%#x" % n if n is not None else "-",
                                                                   ("ID %d" % fid) if isinstance(fid, int) else fid))
        return 1 if bad else 0
    if args.cmd == "site":
        for text in args.sites:
            vid, off = hooksite.parse_site(text)
            v, n, d = port(ref, tgt, vid, off)
            bad += v != "SAME"
            print("%-8s %d+%#x -> %s   %s" % (v, vid, off, "%#x" % n if n is not None else "-", d))
        return 1 if bad else 0
    for root in args.roots:
        seen = set()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [x for x in dirnames if x.lower() not in hookscan.SKIP_DIRS and not x.lower().startswith("build")]
            for fn in sorted(filenames):
                if not fn.lower().endswith(hookscan.EXTS):
                    continue
                path = os.path.join(dirpath, fn)
                for line, vid, off, st, later in hookscan.sites_in(path):
                    if (vid, off) in seen:
                        continue
                    seen.add((vid, off))
                    v, n, d = port(ref, tgt, vid, off)
                    if later is not None:
                        carried = n == later and v.rstrip("~#") in ("SAME", "MOVED")
                        d += "   (%s; the source's 1.7.x offset is %#x)" % (v, later)
                        v = "PORTED" if carried else "MISPORT"
                    if v not in ("SAME", "PORTED"):
                        bad += 1
                    elif not args.all:
                        continue
                    print("%-8s %s:%d  %d+%#x -> %s   %s\n         %s" % (
                        v, os.path.relpath(path, root), line, vid, off, "%#x" % n if n is not None else "-", d, st))
        print("-- %s: %d distinct sites" % (root, len(seen)))
    print("== %d not SAME" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
