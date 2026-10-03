"""Which SKSE plugins carry CommonLib Address Library ids that the runtime's library does not contain.

A plugin resolves most CommonLib ids lazily, the first time the function or variable is used, so a missing id does
not stop the game at SKSE load: it stops it later ("Failed to find the id within the address library", or a crash
with readers that are not exact), when the code path first runs in the world. A main-menu smoke launch cannot see
these. This scan finds them in the binaries.

    python holescan.py <versionlib bin> (--mo2 <instance dir> <profile> | --dll <dll> [<dll> ...])
                       --clib <CommonLib root> [<CommonLib root> ...]

1. Every RELOCATION_ID / RelocationID / VariantID(se, ae, ...) in the CommonLib trees whose AE id the library lacks
   is a hole pair, named by the CommonLib function (or header) it sits in.
2. RELOCATION_ID(se, AE_CHECK(runtime, old, new)) is recorded as a replacement: a DLL built from such a tree carries
   both the old and the new AE id, and a runtime at or after that version uses the new one.
3. A DLL "carries" a hole pair when both ids occur within 64 bytes of each other in .text/.rdata/.data (the two ids
   of one RELOCATION_ID are compiled next to each other). A pair whose replacement id also occurs next to it, and is
   in the library, is reported as REPLACED; every other one as HOLE.

A HOLE says the function is linked, not that it runs: RelWithDebInfo links with /OPT:NOREF, which keeps every
function of a used CommonLib object. Check the plugin's sources (and CommonLib's own callers) for calls before
fixing anything. The DLL's own reader decides what a missing id does at runtime; the markers column shows the
CommonLib family ("Failed to find the id" = exact lookup that stops the game with a message box)."""
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import addrlib  # noqa: E402

WINDOW = 64
PAIR = re.compile(r"(RELOCATION_ID|RelocationID|VariantID)\s*\(\s*(\d+)\s*,\s*(\d+)")
CHECK = re.compile(r"RELOCATION_ID\s*\(\s*(\d+)\s*,\s*AE_CHECK\s*\(\s*[\w:]+\s*,\s*(\d+)\s*,\s*(\d+)\s*\)")
FUNC = re.compile(r"^[\w:<>,\s\*&~]*?\b(\w+)::(\w+)\s*\(")
MARKERS = ("Failed to find the id within the address library", "failed to open address library file",
           "Address library file is truncated", "CommonLibSSEOffsets-v")


def usage():
    sys.stderr.write(__doc__ or "")
    sys.exit(2)


def parse_args(argv):
    if len(argv) < 4:
        usage()
    lib, rest = argv[0], argv[1:]
    dlls, roots, mode = [], [], None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--mo2":
            inst, prof = rest[i + 1], rest[i + 2]
            dlls += served_dlls(inst, prof)
            i += 3
            continue
        if a in ("--dll", "--clib"):
            mode = a
        elif mode == "--dll":
            dlls.append(a)
        elif mode == "--clib":
            roots.append(a)
        else:
            usage()
        i += 1
    if not dlls or not roots:
        usage()
    return lib, dlls, roots


def served_dlls(inst, prof):
    """The DLL SKSE loads for each name: modlist.txt lists the highest priority first."""
    mods = [l[1:].rstrip("\r\n") for l in open(os.path.join(inst, "profiles", prof, "modlist.txt"), encoding="utf-8")
            if l.startswith("+")]
    seen, out = set(), []
    for m in mods:
        d = os.path.join(inst, "mods", m, "SKSE", "Plugins")
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.lower().endswith(".dll") and f.lower() not in seen:
                seen.add(f.lower())
                out.append(os.path.join(d, f))
    return out


def scan_trees(roots, lib):
    holes, replaced = {}, {}
    for root in roots:
        for base in ("src", "include"):
            for dp, _, files in os.walk(os.path.join(root, base)):
                for f in files:
                    if not f.endswith((".cpp", ".h", ".hpp", ".inl")):
                        continue
                    p = os.path.join(dp, f)
                    owner = ""
                    for line in open(p, encoding="utf-8", errors="replace"):
                        m = FUNC.match(line)
                        if m and not line.lstrip().startswith(("//", "return", "using")):
                            owner = "%s::%s" % (m.group(1), m.group(2))
                        name = owner if p.endswith(".cpp") else os.path.basename(p)
                        for m in PAIR.finditer(line):
                            se, ae = int(m.group(2)), int(m.group(3))
                            if se and ae and se != ae and ae not in lib:
                                holes.setdefault((se, ae), name)
                        for m in CHECK.finditer(line):
                            se, old, new = int(m.group(1)), int(m.group(2)), int(m.group(3))
                            if old not in lib:
                                holes.setdefault((se, old), name)
                                replaced[(se, old)] = new
    return holes, replaced


def sections(d):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    so = pe + 24 + opt
    for i in range(n):
        name = d[so + i * 40: so + i * 40 + 8].rstrip(b"\0").decode(errors="replace")
        _, _, rsize, raw = struct.unpack_from("<IIII", d, so + i * 40 + 8)
        if name in (".text", ".rdata", ".data"):
            yield d[raw: raw + rsize]


def near(blob, a, b):
    pa, pb = struct.pack("<I", a), struct.pack("<I", b)
    i = blob.find(pa)
    while i != -1:
        if blob.find(pb, max(0, i - WINDOW), i + WINDOW) != -1:
            return True
        i = blob.find(pa, i + 1)
    return False


def main(argv):
    binp, dlls, roots = parse_args(argv)
    lib = addrlib.read_bin(binp).values
    holes, replaced = scan_trees(roots, lib)
    print("library %s: %d ids | hole pairs in %d CommonLib tree(s): %d (%d with an AE_CHECK replacement)"
          % (os.path.basename(binp), len(lib), len(roots), len(holes), len(replaced)))
    open_holes = 0
    for dll in dlls:
        d = open(dll, "rb").read()
        blobs = list(sections(d))
        marks = sorted({m for m in MARKERS if m.encode() in d or m.encode("utf-16-le") in d})
        rows = []
        for (se, ae), fn in holes.items():
            if not any(near(b, ae, se) for b in blobs):
                continue
            new = replaced.get((se, ae))
            if new is not None and new in lib and any(near(b, ae, new) for b in blobs):
                rows.append(("REPLACED", fn, se, ae, "runtime uses %d" % new))
            else:
                rows.append(("HOLE", fn, se, ae, ""))
        if not rows:
            continue
        mod = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(dll))))
        print("\n%s  [%s]  reader: %s" % (os.path.basename(dll), mod, "exact, stops the game with a message box"
              if MARKERS[0] in marks else "unknown (" + ", ".join(marks) + ")"))
        for verdict, fn, se, ae, note in sorted(rows):
            open_holes += verdict == "HOLE"
            print("   %-8s %-46s se=%-6d ae=%-6d %s" % (verdict, fn[:46], se, ae, note))
    print("\n%d DLL(s) scanned; %d HOLE pair(s) linked - check each for callers" % (len(dlls), open_holes))


if __name__ == "__main__":
    main(sys.argv[1:])
