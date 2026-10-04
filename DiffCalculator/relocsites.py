"""List the Address Library ids and in-function sites of sources that use KernalsEgg's Shared library.

    python relocsites.py <versionlib bin> <source dir> [<source dir> ...]

Those plugins (Scrambled Bugs, Bug Fixes SSE and the rest of that collection) do not use CommonLib's RELOCATION_ID;
they write

    Relocation::AddressLibrary::GetSingleton().GetAddress(SKYRIM_RELOCATE(se, ae)) + SKYRIM_RELOCATE(seOff, aeOff)

so srcids.py does not see them. This prints, per source dir, every AE id with whether the library has it, and
one line "id+0xoffset" per site in the form hookport.py takes:

    python hookport.py site $(python relocsites.py <bin> <dir> --sites)

Exit code 1 when an id is missing from the library.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import addrlib  # noqa: E402
import srcids  # noqa: E402

NUMBER = r"(0x[0-9A-Fa-f]+|\d+)"
RELOCATE = r"SKYRIM_RELOCATE\s*\(\s*" + NUMBER + r"\s*,\s*" + NUMBER + r"\s*\)"
SITE = re.compile(r"GetAddress\s*\(\s*" + RELOCATE + r"\s*\)(?:\s*\+\s*(?:" + RELOCATE + r"|" + NUMBER + r"))?")


def scan(root):
    """Rows (file, line, ae id, ae offset or None)."""
    rows = []
    for path in srcids.sources(root):
        text = srcids.read(path)
        for m in SITE.finditer(text):
            offset = m.group(4) or m.group(5)
            rows.append((os.path.relpath(path, root), text.count("\n", 0, m.start()) + 1, int(m.group(2), 0),
                         int(offset, 0) if offset else None))
    return rows


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        sys.stderr.write(__doc__ or "")
        return 2
    lib = addrlib.read_bin(args[0])
    missing = 0
    for root in args[1:]:
        rows = scan(root)
        sites = sorted({(r[2], r[3]) for r in rows if r[3] is not None})
        if "--sites" in sys.argv:
            print(" ".join("%d+0x%X" % site for site in sites))
            continue
        ids = sorted({r[2] for r in rows})
        lacking = [i for i in ids if not lib.values.get(i)]
        missing += len(lacking)
        print("%s: %d id(s), %d missing from %s, %d in-function site(s)" % (root, len(ids), len(lacking),
                                                                            lib.version_string, len(sites)))
        for r in rows:
            if not lib.values.get(r[2]):
                print("   MISSING %-7d %s:%d" % (r[2], r[0], r[1]))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
