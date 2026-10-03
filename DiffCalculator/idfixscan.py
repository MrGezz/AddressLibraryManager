"""Which SKSE plugins carry a CommonLib Address Library id pair that a newer CommonLib corrected.

A wrong AE id is worse than a missing one: the library has it, so the plugin resolves it without complaint and on AE
calls whatever function that id names - the neighbour when the id is off by one, the other runtime's function when
the SE and AE ids were swapped, an unrelated function when the AE build inlined the original away. This scan reads
the corrections from a CommonLib repository's own history and finds the served DLLs that still carry an old pair.

    python idfixscan.py <CommonLib repo> <old commit> <new commit> (--mo2 <instance dir> <profile> | --dll <dll> ...)

The corrections are the RELOCATION_ID / REL::ID lines a diff hunk removes, matched to the lines it adds:
  MOVED    same SE id, another AE id (CombatBehaviorThread's ids shifted by one, InventoryChanges::GetItemCount)
  SWAPPED  the SE and AE ids traded places (InventoryEntryData::SetWorn): both orders compile to the same two
           constants, so the verdict comes from the order they are stored in - RELOCATION_ID(se, ae) keeps se first
  RETIRED  the AE id became 0: the AE executable inlined the function, the old id names something else
  REMOVED  the function left CommonLib with no replacement in that hunk
  AE17     the AE id became AE_CHECK(1.7.99, old, new): absent from the 1.7.x library (holescan's HOLE case)
  SINGLE   one REL::ID for both runtimes became a pair - on AE the SE number was looked up. Reported only as a hint:
           a lone 4-byte number is common, read the plugin's sources
A DLL carries an old pair when both ids sit within 64 bytes in .text/.rdata/.data and the corrected pair does not.
Carried says linked, not called (RelWithDebInfo keeps every function of a used CommonLib object): read the plugin's
sources for calls before rebuilding it against the newer CommonLib."""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from holescan import WINDOW, near, sections, served_dlls  # noqa: E402

PAIR = re.compile(r"(?:RELOCATION_ID|RelocationID|VariantID)\s*\(\s*(\d+)\s*,\s*(AE_CHECK\s*\([^)]*\)|\d+)")
CHECK = re.compile(r"AE_CHECK\s*\(\s*[\w:]+\s*,\s*(\d+)\s*,\s*(\d+)\s*\)")
SINGLE = re.compile(r"REL::ID\s*\(\s*(\d+)\s*\)")


def _ids(line):
    """[(kind, se, ae, ae_new)] of one source line: kind pair / check / single."""
    out = []
    for m in PAIR.finditer(line):
        se, ae = int(m.group(1)), m.group(2)
        c = CHECK.match(ae)
        if c:
            out.append(("check", se, int(c.group(1)), int(c.group(2))))
        else:
            out.append(("pair", se, int(ae), None))
    if not out:
        for m in SINGLE.finditer(line):
            out.append(("single", int(m.group(1)), None, None))
    return out


def corrections(repo, old, new):
    """[(verdict, function, (old se, old ae), (new se, new ae) or None)] from `git diff old new`."""
    diff = subprocess.run(["git", "-C", repo, "diff", "-U6", old, new, "--", "include", "src"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    out, hunk, fname, ctx = [], None, "", ""

    def flush(h):
        if not h:
            return
        removed, added = h["-"], h["+"]
        for kind, se, ae, _, fn in removed:
            if kind == "single":
                twin = next((a for a in added if a[0] in ("pair", "check") and a[1] == se), None)
                if twin:
                    out.append(("SINGLE", fn, (se,), (twin[1], twin[2])))
                continue
            twin = next((a for a in added if a[1] == se and a[0] in ("pair", "check")), None)
            swap = next((a for a in added if a[0] == "pair" and a[1] == ae and a[2] == se), None)
            if swap:
                out.append(("SWAPPED", fn, (se, ae), (swap[1], swap[2])))
            elif twin and twin[0] == "check" and twin[2] == ae:
                out.append(("AE17", fn, (se, ae), (se, twin[3])))
            elif twin and twin[2] == 0:
                out.append(("RETIRED", fn, (se, ae), (se, 0)))
            elif twin and twin[2] != ae:
                out.append(("MOVED", fn, (se, ae), (se, twin[2])))
            elif not twin:
                out.append(("REMOVED", fn, (se, ae), None))

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            fname = line[6:]
            continue
        if line.startswith("@@"):
            flush(hunk)
            hunk = {"-": [], "+": [], "fn": fname.rsplit("/", 1)[-1]}
            continue
        if hunk is None or line.startswith(("---", "+++")):
            continue
        body = line[1:]
        # the nearest function head above the id names it: "type Class::Name(args)" at the start of a line
        m = DEF.match(body)
        if m and line[:1] in " -" and not body.lstrip().startswith(("return", "if", "for", "while", "static", "//")):
            hunk["fn"] = "%s::%s" % (m.group(1), m.group(2)) if m.group(1) else m.group(2)
        if line[:1] in "+-":
            hunk[line[0]].extend(i + (hunk["fn"],) for i in _ids(body))
    flush(hunk)
    return out


DEF = re.compile(r"^\s*(?:[\w:<>,\*&]+\s+)+?(?:(\w+)::)?(\w+)\s*\([^;]*$")


def order(blob, first, second):
    """True when `first` is stored before `second` within the window somewhere in the blob."""
    pa, pb = first.to_bytes(4, "little"), second.to_bytes(4, "little")
    i = blob.find(pa)
    while i != -1:
        if blob.find(pb, i + 1, i + WINDOW) != -1:
            return True
        i = blob.find(pa, i + 1)
    return False


def main(argv):
    if len(argv) < 5:
        sys.stderr.write(__doc__ or "")
        return 2
    repo, old, new, rest = argv[0], argv[1], argv[2], argv[3:]
    dlls = []
    if rest[0] == "--mo2":
        dlls = served_dlls(rest[1], rest[2])
    elif rest[0] == "--dll":
        dlls = rest[1:]
    fixes = corrections(repo, old, new)
    print("%d corrected id pair(s) between %s and %s" % (len(fixes), old[:9], new[:9]))
    for v, fn, o, n in fixes:
        print("   %-8s %-62s %s -> %s" % (v, fn[:62], o, n))
    hits = 0
    for dll in dlls:
        d = open(dll, "rb").read()
        blobs = list(sections(d))
        rows = []
        for v, fn, o, n in fixes:
            if v == "SINGLE":
                continue
            se, ae = o
            if not any(near(b, se, ae) for b in blobs):
                continue
            if v == "SWAPPED":
                if any(order(b, se, ae) for b in blobs) and not any(order(b, ae, se) for b in blobs):
                    rows.append((v, fn, o, n, "stored in the old order"))
                continue
            if v in ("MOVED", "AE17") and n and any(near(b, n[0], n[1]) for b in blobs):
                continue                    # the corrected pair is there too: built from the newer tree
            rows.append((v, fn, o, n, ""))
        if not rows:
            continue
        hits += len(rows)
        mod = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(dll))))
        print("\n%s  [%s]" % (os.path.basename(dll), mod))
        for v, fn, o, n, note in rows:
            print("   %-8s %-56s %s -> %s %s" % (v, fn[:56], o, n, note))
    print("\n%d DLL(s) scanned; %d old pair(s) carried - read each plugin's sources for calls" % (len(dlls), hits))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
