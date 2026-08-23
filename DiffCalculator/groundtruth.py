"""Extract (old offset -> new offset) ground-truth pairs from an SKSE "address update" commit.

    python groundtruth.py <skse64 repo> <commit> <out.tsv>

SKSE keeps every game address as a literal in RelocAddr<> / RelocPtr<> declarations, so the
commit that moves SKSE from one runtime to the next is a list of hand-verified pairs: each
'-' line carries the old offset and the matching '+' line (same declaration name, same file)
the new one.  Used to validate the diff calculator.
"""

import re
import subprocess
import sys

DECL = re.compile(
    r"^([-+])\s*(?:static\s+)?(?:const\s+)?Reloc(Addr|Ptr)\s*<[^>]*>\s*(\w+)\s*\(\s*0x([0-9A-Fa-f]+)(?:\s*\+\s*0x([0-9A-Fa-f]+))?\s*\)")


def main():
    repo, commit, out = sys.argv[1:4]
    text = subprocess.run(["git", "show", "--format=", commit], cwd=repo, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    old = {}
    new = {}
    path = ""
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            continue
        m = DECL.match(line)
        if not m:
            continue
        sign, kind, name, hx, plus = m.groups()
        v = int(hx, 16) + (int(plus, 16) if plus else 0)
        (old if sign == "-" else new)[(path, name)] = (v, kind)
    pairs = []
    for key, (o, kind) in old.items():
        if key in new:
            pairs.append((key[0], key[1], kind, o, new[key][0]))
    pairs.sort(key=lambda p: p[3])
    with open(out, "w", encoding="utf-8") as f:
        f.write("file\tname\tkind\told\tnew\n")
        for p in pairs:
            f.write("%s\t%s\t%s\t0x%08X\t0x%08X\n" % p)
    unchanged = sum(1 for p in pairs if p[3] == p[4])
    print("%d declarations removed, %d added, %d paired (%d unchanged), written %s" % (len(old), len(new), len(pairs), unchanged, out))


if __name__ == "__main__":
    main()
