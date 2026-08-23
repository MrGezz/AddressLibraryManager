"""Feasibility statistics for diffing one runtime against another.

    python stats.py <old.exe> <old versionlib bin> <new.exe> [--gt <ground truth tsv>] [--cache <dir>]

Reports where the old Address Library IDs live (function starts, leaf functions, inside
functions, data sections), how many functions of each image have a unique masked hash, how
many unique hashes match across the two images, and - with a ground-truth table from
groundtruth.py - how many of those known pairs the hash match reproduces.
"""

import sys
from collections import Counter

import addrlib
import fnhash


def main():
    args = sys.argv[1:]
    gt = None
    cache = None
    pos = []
    i = 0
    while i < len(args):
        if args[i] == "--gt":
            gt = args[i + 1]
            i += 2
        elif args[i] == "--cache":
            cache = args[i + 1]
            i += 2
        else:
            pos.append(args[i])
            i += 1
    old_exe, old_bin, new_exe = pos
    lib = addrlib.read_bin(old_bin)
    print("old library: %s %s, %d ids" % (lib.module, lib.version_string, len(lib.values)))

    pe_old, fns_old = fnhash.build(old_exe, extra_starts=sorted(set(lib.values.values())), cache_dir=cache)
    pe_new, fns_new = fnhash.build(new_exe, cache_dir=cache)
    print("old: %s, %d functions" % (pe_old.file_version(), len(fns_old)))
    print("new: %s, %d functions" % (pe_new.file_version(), len(fns_new)))

    # where do the old ids live?
    starts = {f.begin: f for f in fns_old}
    import bisect
    fn_begins = [f.begin for f in fns_old]
    cat = Counter()
    for vid, off in lib.values.items():
        s = pe_old.section_of(off)
        if s is None:
            cat["outside image"] += 1
        elif not s.executable:
            cat["data " + s.name] += 1
        elif off in starts:
            cat["function start (leaf)" if starts[off].leaf else "function start (.pdata)"] += 1
        else:
            j = bisect.bisect_right(fn_begins, off) - 1
            f = fns_old[j] if j >= 0 else None
            if f is not None and any(b <= off < e for b, e in f.ranges):
                cat["inside function"] += 1
            else:
                cat["code, not in any function"] += 1
    for k, v in sorted(cat.items(), key=lambda kv: -kv[1]):
        print("  %-28s %7d" % (k, v))

    # hash statistics
    ho = Counter(f.hash for f in fns_old)
    hn = Counter(f.hash for f in fns_new)
    uo = {f.hash: f for f in fns_old if ho[f.hash] == 1}
    un = {f.hash: f for f in fns_new if hn[f.hash] == 1}
    both = set(uo) & set(un)
    print("unique hashes: old %d / %d, new %d / %d, unique-unique matches %d" % (len(uo), len(fns_old), len(un), len(fns_new), len(both)))
    covered_ids = sum(1 for off in lib.values.values() if off in starts and starts[off].hash in both)
    print("old ids at a uniquely matched function start: %d of %d" % (covered_ids, len(lib.values)))

    if gt:
        pairs = []
        for line in open(gt, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) < 5 or p[0] == "file":
                continue
            pairs.append((p[1], int(p[3], 16), int(p[4], 16)))
        ok = bad = nostart = unmatched = 0
        for name, o, n in pairs:
            f = starts.get(o)
            if f is None:
                nostart += 1
                continue
            if f.hash in both:
                if un[f.hash].begin == n:
                    ok += 1
                else:
                    bad += 1
                    print("  MISMATCH %s old 0x%X -> predicted 0x%X, truth 0x%X" % (name, o, un[f.hash].begin, n))
            else:
                unmatched += 1
        print("ground truth: %d pairs; at function start %d: correct %d, wrong %d, not uniquely matched %d; not a function start %d" % (
            len(pairs), len(pairs) - nostart, ok, bad, unmatched, nostart))


if __name__ == "__main__":
    main()
