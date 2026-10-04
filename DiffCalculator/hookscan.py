"""Find SKSE hook sites in plugin source and check each one on the real executable.

Scans C++ sources for an Address Library ID paired with an in-function offset in one statement:

    RELOCATION_ID(se, ae) ... REL::VariantOffset(se, ae, vr)   REL::Relocate(se, ae[, vr])
    RELOCATION_ID(se, ae) ... OFFSET(se, ae) / OFFSET_3(se, ae, vr)
    REL::VariantID(se, ae, vr) ... any of the above
    REL::ID(ae) , 0x...        (AE-only plugins)
    RELOCATION_ID(se, ae).address() + 0x1A6   (one literal for every runtime)

or split over two statements, the id naming a variable and the offset added where the variable is used:

    REL::Relocation<std::uintptr_t> hook{ RELOCATION_ID(se, ae) };
    trampoline.write_call<5>(hook.address() + REL::Relocate(se, ae), thunk);     (or "+ 0x1A")

The variable is the one the id's statement declares; a later declaration of the same name replaces it. A
declaration may carry a base offset of its own - REL::Relocation target{ RELOCATION_ID(se, ae), 0x4C } or
VAR_NUM(se, ae) in the literal's place - which is a site itself and is added to every later offset. An id followed
by anything else is not followed: a guessed base would report a site that does not exist.

An offset may be preceded by the one a later runtime needs:

    hook.address() + (REL::Module::IsAtLeast(SKSE::RUNTIME_SSE_1_7_99) ? 0x678 : REL::Relocate(0x4DC, 0x667))

The number behind the "?" is the 1.7.x offset and is the one checked here; the offset behind the ":" stays the
site's 1.6 offset, which hookport.py carries from its reference executable and compares with the source's.

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

A site is an offset the sources contain, not a hook the plugin installs: the scan does not know whether the
function around it is ever called (Ultimate NPC Dodging's on_set_rotation::install is commented out at its one
call). Read the call before deciding what a bad site costs.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hooksite  # noqa: E402

NUM = r"(0x[0-9A-Fa-f]+|\d+)"


def num(name):
    return r"(?P<%s>0x[0-9A-Fa-f]+|\d+)" % name


# "IsAtLeast(RUNTIME_SSE_1_7_99) ? 0x678 : " ahead of an offset, with or without the parenthesis the "+" needs
LATER = (r"(?:\(\s*)?(?:(?:REL::)?(?:Module::)?IsAtLeast\s*\(\s*(?:SKSE::)?RUNTIME_SSE_1_7_\d+\s*\)\s*\?\s*"
         + num("later") + r"\s*:\s*)?")
PICK = r"(?:REL::)?(?:VariantOffset|Relocate|OFFSET_3|OFFSET)\s*\(\s*" + num("se") + r"\s*,\s*" + num("ae") + r"(?:\s*,\s*" + num("vr") + r")?\s*\)"
ID2 = re.compile(r"(?:RELOCATION_ID|REL::RelocationID|RelocationID)\s*\(\s*" + NUM + r"\s*,\s*" + NUM + r"\s*\)")
VID = re.compile(r"(?:REL::)?VariantID\s*\(\s*" + NUM + r"\s*,\s*" + NUM + r"\s*,\s*" + NUM + r"\s*\)")
AEID = re.compile(r"REL::ID\s*\(\s*" + num("id") + r"\s*\)\s*,\s*" + LATER + num("off") + r"\s*[}\)]")
OFF = re.compile(LATER + PICK)
# the variable a statement declares from an id, and that variable's address with an offset added
DECLARED = re.compile(r"([A-Za-z_]\w*)\s*[\{\(=]\s*$")
DIRECT = re.compile(r"\s*\.\s*(?:address|get)\s*\(\s*\)\s*\+\s*" + LATER + num("off"))
BASE = re.compile(r"\s*,\s*" + LATER + r"(?:VAR_NUM\s*\(\s*" + num("se") + r"\s*,\s*" + num("ae") + r"\s*\)|" + num("lit") + r")\s*[\}\)]")
USED = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\.\s*(?:address|get)\s*\(\s*\)\s*\+\s*" + LATER + r"(?:" + PICK + r"|" + num("lit") + r")")
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


def later_of(match):
    text = match.group("later")
    return int(text, 0) if text else None


def sites_in(path):
    """Yield (line, AE id, offset, statement, later) per site; later is the 1.7.x offset the source names, or None."""
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    text = re.sub(r"//[^\n]*", "", text)
    declared = {}
    for line, st in statements(text):
        shown = " ".join(st.split())[:160]
        ids = [(int(m.group(2), 0), m) for m in ID2.finditer(st)] + [(int(m.group(2), 0), m) for m in VID.finditer(st)]
        offs = list(OFF.finditer(st))
        for use in USED.finditer(st):
            known = declared.get(use.group("name"))
            if known is None:
                continue
            ae, start, start_later = known
            ae_off = int(use.group("ae") or use.group("lit"), 0)
            later = later_of(use)
            if later is not None or start_later is not None:
                later = (start if start_later is None else start_later) + (ae_off if later is None else later)
            if start + ae_off:
                yield line, ae, start + ae_off, shown, later
        for ae, m in ids:
            direct = DIRECT.match(st, m.end())
            if direct and int(direct.group("off"), 0):
                yield line, ae, int(direct.group("off"), 0), shown, later_of(direct)
        if ids and not offs:
            for ae, m in ids:
                name = DECLARED.search(st[:m.start()])
                rest = st[m.end():].lstrip()
                base = BASE.match(st, m.end())
                start_later = None
                if base:
                    start = int(base.group("ae") or base.group("lit"), 0)
                    start_later = later_of(base)
                    if start:
                        yield line, ae, start, shown, start_later
                elif rest[:1] == ",":
                    name = None
                else:
                    start = 0
                if name:
                    declared[name.group(1)] = (ae, start, start_later)
        if ids and offs:
            for n, (ae, _) in enumerate(ids):
                o = offs[min(n, len(offs) - 1)]
                ae_off = int(o.group("ae"), 0)
                if ae_off:
                    yield line, ae, ae_off, shown, later_of(o)
        for m in AEID.finditer(st):
            vid, off = int(m.group("id"), 0), int(m.group("off"), 0)
            if off:
                yield line, vid, off, shown, later_of(m)


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
                for line, vid, off, st, later in sites_in(path):
                    site = off if later is None else later
                    key = (vid, site)
                    if key in seen:
                        continue
                    seen.add(key)
                    total += 1
                    verdict, ins = classify(img, res, vid, site)
                    if verdict in ("MID", "NOID"):
                        bad += 1
                    if verdict in ("CALL", "JMP") and not args.all:
                        continue
                    desc = ""
                    if ins is not None:
                        desc = "%s %s" % (ins.mnemonic, ins.op_str)
                        if verdict == "MID":
                            desc = "+%d into [%s] %s" % (site - (ins.address - res.rva(vid)), ins.bytes.hex(" "), desc)
                    if later is not None:
                        desc += "   (the source's 1.7.x offset; %#x before)" % off
                    rel = os.path.relpath(path, root)
                    print("%-5s %s:%d  %d+%#x  %s\n        %s" % (verdict, rel, line, vid, site, desc, st))
        print("-- %s: %d distinct sites" % (root, len(seen)))
    print("== %d sites, %d MID/NOID" % (total, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
