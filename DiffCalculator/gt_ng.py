"""Ground-truth pairs for a Skyrim SE 1.5.97 -> AE/1.7 diff from CommonLibSSE-NG.

    python gt_ng.py <CommonLibSSE-NG include dir> <version-1-5-97-0.bin> <versionlib-<ae>.bin> <out.tsv>

CommonLibSSE-NG spells every dual-runtime address as RELOCATION_ID(se, ae) (also RelocationID
/ VariantID), which pairs a 1.5.97 Address Library ID with its AE ID.  Resolving both sides
through the two published bins gives hand-verified (old offset -> new offset) pairs in the
groundtruth.py TSV layout (file, name, kind, old, new), usable with fndiff.py --gt.
"""
import os
import re
import sys

import addrlib

PAIR = re.compile(r"(RELOCATION_ID|RelocationID|VariantID)\(\s*(\d+)\s*,\s*(\d+)")


def main():
    inc, se_bin, ae_bin, out = sys.argv[1:5]
    se = addrlib.read_bin(se_bin).values
    ae = addrlib.read_bin(ae_bin).values
    pairs = {}
    for root, _dirs, files in os.walk(inc):
        for name in files:
            if not name.endswith((".h", ".cpp", ".inl")):
                continue
            path = os.path.join(root, name)
            text = open(path, encoding="utf-8", errors="replace").read()
            for m in PAIR.finditer(text):
                pairs.setdefault((int(m.group(2)), int(m.group(3))), os.path.relpath(path, inc).replace(os.sep, "/"))
    rows = []
    missing_se = missing_ae = 0
    for (s, a), path in sorted(pairs.items()):
        if s not in se:
            missing_se += 1
            continue
        if a not in ae:
            missing_ae += 1
            continue
        rows.append((path, "%d_%d" % (s, a), "Addr", se[s], ae[a]))
    rows.sort(key=lambda r: r[3])
    with open(out, "w", encoding="utf-8") as f:
        f.write("file\tname\tkind\told\tnew\n")
        for r in rows:
            f.write("%s\t%s\t%s\t0x%08X\t0x%08X\n" % r)
    print("%d SE/AE pairs in NG, %d without a 1.5.97 entry, %d without an entry in the new library, %d written to %s"
          % (len(pairs), missing_se, missing_ae, len(rows), out))


if __name__ == "__main__":
    main()
