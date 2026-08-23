"""Build the bin (and relib column) to ship from an fndiff run, keeping only the methods that
survived every check, so that a plugin needing a dropped ID fails at load instead of using a
wrong address.

    python conservative.py <fndiff out dir> <old bin> [--relib-in <relib> --relib-out <path>]
                           [--drop m1,m2,...]

Writes <out dir>/conservative/versionlib-<ver>.bin and, with --relib-*, the database with the
same reduced column. Prints the per-method counts kept and dropped.
"""

import os
import sys
from collections import Counter

import addrlib
import relib as relibmod

DROP = ("locality-sim", "locality-1", "callgraph-vote", "ref-weak", "vtable-1", "shift2", "piece", "inner-align", "shift-code")


def main():
    args = sys.argv[1:]
    pos = []
    relib_in = relib_out = None
    drop = set(DROP)
    i = 0
    while i < len(args):
        if args[i] == "--relib-in":
            relib_in = args[i + 1]; i += 2
        elif args[i] == "--relib-out":
            relib_out = args[i + 1]; i += 2
        elif args[i] == "--drop":
            drop = set(args[i + 1].split(",")); i += 2
        else:
            pos.append(args[i]); i += 1
    out_dir, old_bin = pos
    old = addrlib.read_bin(old_bin)
    kept = {}
    counts = Counter()
    dropped = Counter()
    new_ver = None
    for name in os.listdir(out_dir):
        if name.startswith("versionlib-") and name.endswith(".bin"):
            full = addrlib.read_bin(os.path.join(out_dir, name))
            new_ver = full.version
    if new_ver is None:
        print("no versionlib bin in", out_dir)
        return 1
    for line in open(os.path.join(out_dir, "report.tsv"), encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if p[0] == "id" or not p[2]:
            continue
        vid, noff, how = int(p[0]), int(p[2], 16), p[3]
        if how in drop:
            dropped[how] += 1
            continue
        kept[vid] = noff
        counts[how] += 1
    cdir = os.path.join(out_dir, "conservative")
    os.makedirs(cdir, exist_ok=True)
    lib = addrlib.VersionLib(new_ver, old.module, old.pointer_size, kept)
    path = os.path.join(cdir, addrlib.bin_name(new_ver))
    addrlib.write_bin(path, lib)
    print("kept %d ids (%s)" % (len(kept), ", ".join("%s %d" % kv for kv in counts.most_common())))
    print("dropped %d ids (%s)" % (sum(dropped.values()), ", ".join("%s %d" % kv for kv in dropped.most_common())))
    print("wrote", path)
    back = addrlib.read_bin(path)
    assert back.values == kept, "round-trip mismatch"
    if relib_in and relib_out:
        db = relibmod.read_relib(relib_in)
        key = tuple(new_ver)
        hashes = {}
        full_relib = os.path.join(out_dir, "skyrimae.relib")
        if os.path.isfile(full_relib):
            fdb = relibmod.read_relib(full_relib)
            if key in fdb.versions:
                hashes = {k: v for k, v in fdb.versions[key].hashes.items() if k in kept}
        db.versions[key] = relibmod.Library(key, values=kept, hashes=hashes)
        relibmod.write_relib(relib_out, db)
        print("wrote %s (+%s: %d ids, %d hashes)" % (relib_out, ".".join(map(str, key)), len(kept), len(hashes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
