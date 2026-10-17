"""Which Address Library ids a plugin's OWN sources name, and whether the runtime's library has them.

    python srcids.py <versionlib bin> <source dir> [<source dir> ...] [--all]

holescan.py answers the question for CommonLib's ids from the built DLL. A plugin also names ids itself -
RELOCATION_ID(se, ae), REL::RelocationID(se, ae), REL::VariantID(se, ae, vr), REL::ID(n) - and those never pass
through CommonLib's tables. This reads the sources (extern/, external/, lib/, build/ and vcpkg trees are skipped;
a call may be split over lines; comments are ignored) and looks every AE id up in the library: an id the library
lacks is listed as MISSING with the file and line that asks for it. With --all the ids that are present are listed
too, with their offsets.

An id may be given by name (REL::VariantID(Offsets::kFooSE, Offsets::kFoo, Offsets::kFooVR)): integer constants
and #defines of the scanned sources are collected first and the name is looked up among them by its last
component. A name that has no definition, or two definitions with different values, is listed as UNRESOLVED -
it was not checked, so it counts as a failure. A macro that hands one of its arguments on as the AE id
(#define AutoPtr(Type, Name, SE, AE) ... RELOCATION_ID(SE, AE)) is followed to its uses.

An offset added to an id ("+ 0x1A", REL::Relocate(se, ae)) is printed beside it: a call or branch written at such a
site lands wherever the instruction moved to in this runtime, so each one needs its bytes read
(hooksite.py / hookport.py) before the plugin is trusted. The count in the summary line is hookscan.py's, which also
follows an id into the variable it initialises (the offset is then added in a later statement). REL::Offset / REL::VariantOffset carry addresses of one
executable and are listed as RAW: they hold for no other runtime. Exit code 1 when an id is missing or unresolved.

So do offsets added to the image base itself, REL::Module::get().base() + 0x12466BC (a constant may stand for the
number): each is listed as IMAGE with the id the address falls in on the library's runtime ("93210+0x1BC"), which is
what hooksite.py / hookport.py take, and a name that is not a constant of the sources as IMAGE ?. A variable that
takes the bare image base ("auto base = REL::Module::get().base();") is listed as BASE: the offsets added to it
elsewhere are not followed, so read them by hand. IMAGE and BASE rows hold for one executable and never fail the run.
"""
import bisect
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import addrlib  # noqa: E402

SKIP = {"extern", "external", "lib", "build", "vcpkg_installed", ".git", "out", ".vs", "vendor"}
ARG = r"((?:[A-Za-z_][\w:]*)|\d+)"
PAIR = re.compile(r"(RELOCATION_ID|REL::RelocationID|RelocationID|REL::VariantID|VariantID)\s*\(\s*" + ARG +
                  r"\s*,\s*" + ARG)
SINGLE = re.compile(r"REL::ID\s*[\(\{]\s*" + ARG + r"\s*[\)\}]")
RAW = re.compile(r"(REL::VariantOffset|REL::Offset)\s*[\(\{]\s*(0x[0-9A-Fa-f]+|\d+)(?:\s*,\s*(0x[0-9A-Fa-f]+|\d+))?")
IMAGE_BASE = r"(?:REL::)?Module::get\s*\(\s*\)\s*\.\s*base\s*\(\s*\)"
IMAGE = re.compile(IMAGE_BASE + r"\s*\+\s*(0x[0-9A-Fa-f]+|[A-Za-z_][\w:]*|\d+)")
BASE_VAR = re.compile(r"\b([A-Za-z_]\w*)\s*(?:=|\{)\s*" + IMAGE_BASE + r"\s*\}?\s*;")
OFFSET = re.compile(r"REL::Relocate\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)|\+\s*(0x[0-9A-Fa-f]+)")
CONSTANT = re.compile(r"\b(?:constexpr|const)\b[^;=(){}\n]*?\b([A-Za-z_]\w*)\s*(?:=\s*|\{\s*|\(\s*)"
                      r"(0x[0-9A-Fa-f]+|\d+)\s*(?:[uU]?[lL]{0,2})\s*[\}\)]?\s*;")
DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+\(?(0x[0-9A-Fa-f]+|\d+)\)?[ \t]*$", re.M)
MACRO = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(([^)\n]*)\)((?:[^\n\\]|\\[^\n]|\\\n)*)", re.M)
LINE_COMMENT = re.compile(r"//[^\n]*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
NOT_NEWLINE = re.compile(r"[^\n]")


def sources(root):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP]
        for name in files:
            if os.path.splitext(name)[1].lower() in (".cpp", ".h", ".hpp", ".cc", ".inl", ".cxx"):
                yield os.path.join(base, name)


def blank(match):
    return NOT_NEWLINE.sub(" ", match.group(0))


def read(path):
    """A source file with its comments blanked and every position kept: a commented-out id is not asked for."""
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
    return BLOCK_COMMENT.sub(blank, LINE_COMMENT.sub(blank, text))


def constants(texts):
    """name -> value for the integer constants of the sources; None for a name defined with two values."""
    table = {}
    for text in texts:
        for m in list(CONSTANT.finditer(text)) + list(DEFINE.finditer(text)):
            value = int(m.group(2), 0)
            if table.setdefault(m.group(1), value) != value:
                table[m.group(1)] = None
    return table


def wrappers(texts):
    """Macros that hand an argument on as the AE id (#define AutoPtr(Type, Name, SE, AE) ... RELOCATION_ID(SE, AE)):
    name -> position of that argument counted from the end, which a comma inside an earlier template argument
    does not shift."""
    found = {}
    for text in texts:
        for m in MACRO.finditer(text):
            params = [p.strip() for p in m.group(2).split(",")]
            inner = PAIR.search(m.group(3))
            if inner and inner.group(3) in params:
                found[m.group(1)] = params.index(inner.group(3)) - len(params)
    return found


def call_arguments(text, start):
    """The arguments of the call whose opening parenthesis is at start, split at its top-level commas."""
    depth, args, last = 0, [], start + 1
    for i in range(start, min(len(text), start + 4000)):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[last:i].strip())
                return args
        elif ch == "," and depth == 1:
            args.append(text[last:i].strip())
            last = i + 1
    return []


def resolve(arg, table):
    """(value, name): the id an argument stands for; value None when the name could not be resolved."""
    if arg.isdigit():
        return int(arg), ""
    return table.get(arg.rsplit("::", 1)[-1]), arg


def scan(root, lib):
    """Rows (file, line, kind, ae id or None, offset in the library, site note, name)."""
    texts = {path: read(path) for path in sources(root)}
    table = constants(texts.values())
    macros = wrappers(texts.values())
    rows = []
    for path, text in texts.items():
        # inside a wrapper macro's own definition the arguments are its parameters, not ids
        bodies = [(m.start(), m.end()) for m in MACRO.finditer(text) if m.group(1) in macros]
        inside = lambda pos: any(a <= pos < b for a, b in bodies)  # noqa: E731
        found = [(m.start(), m.end(), m.group(1), m.group(3)) for m in PAIR.finditer(text) if not inside(m.start())]
        found += [(m.start(), m.end(), "REL::ID", m.group(1)) for m in SINGLE.finditer(text)]
        for name, index in macros.items():
            for m in re.finditer(r"\b%s\s*\(" % re.escape(name), text):
                args = call_arguments(text, m.end() - 1)
                if not inside(m.start()) and len(args) >= -index and re.fullmatch(ARG, args[index]):
                    found.append((m.start(), m.end(), name, args[index]))
        rel = os.path.relpath(path, root)
        for start, end, kind, arg in sorted(found):
            line = text.count("\n", 0, start) + 1
            # "REL::ID id" in a parameter list and "REL::ID(a_id)" forwarding a parameter name no id
            if not arg.isdigit() and arg.rsplit("::", 1)[-1] not in table and "::" not in arg and kind == "REL::ID":
                continue
            ae, name = resolve(arg, table)
            # the offset belongs to the same statement: look as far as its end
            stop = text.find(";", end)
            tail = text[end:stop] if stop != -1 and stop - end < 400 else text[end:end + 200]
            off = OFFSET.search(tail)
            site = ""
            if off:
                site = "ae+%s" % off.group(2) if off.group(2) else "+%s" % off.group(3)
            rows.append((rel, line, kind, ae, lib.values.get(ae, 0) if ae is not None else 0, site, name))
        for m in RAW.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            rows.append((rel, line, "RAW", -1, int(m.group(3) or m.group(2), 0), m.group(1), ""))
        for m in IMAGE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            arg = m.group(1)
            value = int(arg, 0) if arg[0].isdigit() else table.get(arg.rsplit("::", 1)[-1])
            rows.append((rel, line, "IMAGE", -1, value, containing_id(lib, value), "" if arg[0].isdigit() else arg))
        for m in BASE_VAR.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            rows.append((rel, line, "BASE", -1, None, m.group(1), ""))
    return rows


_by_offset = {}


def containing_id(lib, rva):
    """'<id>+0x<delta>': the id at or below an image offset in the library (a function's start when the address
    is code), or '' when there is none."""
    if rva is None:
        return ""
    key = id(lib)
    if key not in _by_offset:
        _by_offset[key] = sorted((off, vid) for vid, off in lib.values.items())
    table = _by_offset[key]
    i = bisect.bisect_right(table, (rva, float("inf"))) - 1
    if i < 0:
        return ""
    off, vid = table[i]
    return "%d+%#x" % (vid, rva - off)


def site_count(root):
    """In-function sites of a source tree as hookscan.py finds them: distinct (AE id, offset) pairs."""
    import hookscan
    return len({(ae, off) for path in sources(root) for _, ae, off, _, _ in hookscan.sites_in(path)})


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_all = "--all" in sys.argv
    if len(args) < 2:
        sys.stderr.write(__doc__ or "")
        return 2
    lib = addrlib.read_bin(args[0])
    failures = 0
    for root in args[1:]:
        rows = scan(root, lib)
        ids = [r for r in rows if r[2] not in ("RAW", "IMAGE", "BASE")]
        named = sorted({r[3] for r in ids if r[3] is not None})
        lacking = sorted({r[3] for r in ids if r[3] is not None and not r[4]})
        unresolved = sorted({r[6] for r in ids if r[3] is None})
        sites = site_count(root)
        raw = [r for r in rows if r[2] == "RAW"]
        image = [r for r in rows if r[2] == "IMAGE"]
        bases = [r for r in rows if r[2] == "BASE"]
        print("%s: %d id(s) named, %d missing from %s, %d unresolved name(s), %d with an in-function offset, "
              "%d raw offset(s), %d image offset(s), %d image base variable(s)"
              % (root, len(named), len(lacking), lib.version_string, len(unresolved), sites, len(raw), len(image),
                 len(bases)))
        for r in rows:
            where = "%s:%d" % (r[0], r[1])
            label = " = %s" % r[6] if r[6] else ""
            if r[2] == "RAW":
                print("   RAW       %#9x  %s (%s)" % (r[4], where, r[5]))
            elif r[2] == "IMAGE":
                if r[4] is None:
                    print("   IMAGE ?   %s  %s (not a constant of these sources: read by hand)" % (r[6], where))
                else:
                    print("   IMAGE     %#9x  %s %s%s" % (r[4], where, r[5], label))
            elif r[2] == "BASE":
                print("   BASE      %s  %s (image base kept in a variable: its offsets are not followed)" % (r[5], where))
            elif r[3] is None:
                print("   UNRESOLVED %s  %s (%s)" % (r[6], where, r[2]))
            elif not r[4]:
                print("   MISSING %-7d %s  (%s) %s%s" % (r[3], where, r[2], r[5], label))
            elif show_all or r[5]:
                print("   %-7d %#9x  %s %s%s" % (r[3], r[4], where, r[5], label))
        failures += len(lacking) + len(unresolved)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
