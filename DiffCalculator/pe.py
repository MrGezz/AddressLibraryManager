"""Minimal PE32+ reader: sections, exception directory (.pdata -> function ranges), base
relocations (DIR64 pointer slots), and file version from the VS_VERSIONINFO resource.

Everything is expressed as RVAs (offsets from the image base), which is what the Address
Library stores.
"""

import bisect
import struct


class Section:
    __slots__ = ("name", "va", "vsize", "raw", "rawsize", "flags")

    def __init__(self, name, va, vsize, raw, rawsize, flags):
        self.name, self.va, self.vsize, self.raw, self.rawsize, self.flags = name, va, vsize, raw, rawsize, flags

    @property
    def end(self):
        return self.va + max(self.vsize, self.rawsize)

    @property
    def executable(self):
        return bool(self.flags & 0x20000000)


class Function:
    __slots__ = ("begin", "end", "fragments")

    def __init__(self, begin, end):
        self.begin = begin
        self.end = end
        self.fragments = []  # (begin, end) of chained-unwind fragments that belong to this function

    @property
    def size(self):
        return self.end - self.begin


class PE:
    def __init__(self, path):
        self.path = path
        d = self.data = open(path, "rb").read()
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE image: " + path)
        nsec, = struct.unpack_from("<H", d, pe + 6)
        optsz, = struct.unpack_from("<H", d, pe + 20)
        opt = pe + 24
        magic, = struct.unpack_from("<H", d, opt)
        if magic != 0x20B:
            raise ValueError("not PE32+: " + path)
        self.image_base, = struct.unpack_from("<Q", d, opt + 24)
        self.size_of_image, = struct.unpack_from("<I", d, opt + 56)
        ndirs, = struct.unpack_from("<I", d, opt + 108)
        self.dirs = [struct.unpack_from("<II", d, opt + 112 + 8 * i) for i in range(ndirs)]
        sec = opt + optsz
        self.sections = []
        for i in range(nsec):
            name = d[sec + i * 40:sec + i * 40 + 8].rstrip(b"\0").decode("latin1")
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", d, sec + i * 40 + 8)
            flags, = struct.unpack_from("<I", d, sec + i * 40 + 36)
            self.sections.append(Section(name, va, vsize, raw, rawsize, flags))
        self._sec_starts = [s.va for s in self.sections]
        self._functions = None
        self._relocs = None

    # -- addressing -------------------------------------------------------------------
    def section_of(self, rva):
        i = bisect.bisect_right(self._sec_starts, rva) - 1
        if i >= 0 and rva < self.sections[i].end:
            return self.sections[i]
        return None

    def rva_to_off(self, rva):
        s = self.section_of(rva)
        if s is None or rva >= s.va + s.rawsize:
            return None
        return s.raw + (rva - s.va)

    def read(self, rva, n):
        o = self.rva_to_off(rva)
        if o is None:
            return b""
        return self.data[o:o + n]

    def u32(self, rva):
        return struct.unpack_from("<I", self.data, self.rva_to_off(rva))[0]

    def u64(self, rva):
        return struct.unpack_from("<Q", self.data, self.rva_to_off(rva))[0]

    def in_image(self, va):
        return self.image_base <= va < self.image_base + self.size_of_image

    # -- exception directory --------------------------------------------------------
    def runtime_functions(self):
        rva, size = self.dirs[3]
        off = self.rva_to_off(rva)
        out = []
        for i in range(size // 12):
            b, e, u = struct.unpack_from("<III", self.data, off + 12 * i)
            out.append((b, e, u))
        return out

    def functions(self):
        """Function list with chained-unwind fragments folded into their parent, sorted by begin."""
        if self._functions is not None:
            return self._functions
        funcs = {}
        chained = []
        for b, e, u in self.runtime_functions():
            if u & 1:  # low bit set: u points to another RUNTIME_FUNCTION (not seen in MSVC output, but legal)
                chained.append((b, e, None))
                continue
            uo = self.rva_to_off(u)
            flags = self.data[uo] >> 3
            if flags & 4:  # UNW_FLAG_CHAININFO
                count = self.data[uo + 2]
                parent = uo + 4 + ((count + 1) & ~1) * 2
                pb, = struct.unpack_from("<I", self.data, parent)
                chained.append((b, e, pb))
            else:
                funcs[b] = Function(b, e)
        # chained fragments may chain to another fragment; resolve to the root function
        rf = {b: (e, pb) for b, e, pb in chained}
        for b, e, pb in chained:
            seen = 0
            while pb is not None and pb not in funcs and pb in rf and seen < 16:
                pb = rf[pb][1]
                seen += 1
            if pb in funcs:
                funcs[pb].fragments.append((b, e))
            else:
                funcs[b] = Function(b, e)  # orphan fragment: treat as its own function
        self._functions = sorted(funcs.values(), key=lambda f: f.begin)
        self._fn_starts = [f.begin for f in self._functions]
        # fragment -> owner lookup
        self._frag_owner = {}
        for f in self._functions:
            for fb, fe in f.fragments:
                self._frag_owner[fb] = f
        self._frag_starts = sorted(self._frag_owner)
        return self._functions

    def function_at(self, rva):
        """Function whose main body or fragment contains rva (None if not in a function)."""
        self.functions()
        i = bisect.bisect_right(self._fn_starts, rva) - 1
        if i >= 0:
            f = self._functions[i]
            if f.begin <= rva < f.end:
                return f
        i = bisect.bisect_right(self._frag_starts, rva) - 1
        if i >= 0:
            fb = self._frag_starts[i]
            f = self._frag_owner[fb]
            for b, e in f.fragments:
                if b <= rva < e:
                    return f
        return None

    # -- relocations ----------------------------------------------------------------
    def relocs(self):
        """Sorted RVAs of every DIR64 relocation slot (absolute 8-byte pointers in the image)."""
        if self._relocs is not None:
            return self._relocs
        rva, size = self.dirs[5]
        off = self.rva_to_off(rva)
        end = off + size
        out = []
        while off + 8 <= end:
            page, bsize = struct.unpack_from("<II", self.data, off)
            if bsize < 8:
                break
            n = (bsize - 8) // 2
            for i in range(n):
                e, = struct.unpack_from("<H", self.data, off + 8 + 2 * i)
                if e >> 12 == 10:
                    out.append(page + (e & 0xFFF))
            off += bsize
        self._relocs = sorted(out)
        return self._relocs

    def pointer_targets(self):
        """{slot rva: target rva} for every DIR64 slot whose value points inside the image."""
        out = {}
        for slot in self.relocs():
            o = self.rva_to_off(slot)
            if o is None:
                continue
            v, = struct.unpack_from("<Q", self.data, o)
            if self.in_image(v):
                out[slot] = v - self.image_base
        return out

    # -- version resource -----------------------------------------------------------
    def file_version(self):
        """(major, minor, build, revision) from VS_FIXEDFILEINFO, or None."""
        rva, size = self.dirs[2]
        if not rva:
            return None
        blob = self.read(rva, size)
        i = blob.find(b"\xbd\x04\xef\xfe")  # VS_FIXEDFILEINFO signature
        if i < 0:
            return None
        ms, ls = struct.unpack_from("<II", blob, i + 8)
        return (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        pe = PE(p)
        fns = pe.functions()
        frag = sum(len(f.fragments) for f in fns)
        print("%s  version %s  base 0x%X  image 0x%X" % (p, pe.file_version(), pe.image_base, pe.size_of_image))
        for s in pe.sections:
            print("  %-8s va 0x%08X size 0x%08X %s" % (s.name, s.va, s.end - s.va, "X" if s.executable else ""))
        print("  %d functions (%d chained fragments folded), %d DIR64 relocation slots" % (len(fns), frag, len(pe.relocs())))
