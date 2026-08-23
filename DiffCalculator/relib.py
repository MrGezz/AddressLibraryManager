"""Address Library Manager database (.relib / .rename) reader and writer.

Byte-for-byte compatible with Database.SaveOffsets / LoadOffsets and Library.WriteToStream /
ReadFromStream in ../Manager.cs (save version 2):

    int32   save version (2)
    uint64  HighVID
    int32   PointerSize
    byte    has TargetModuleName, then a .NET BinaryWriter string (7-bit length prefix, UTF-8)
    int32   version count, then per version:
        int32 n, n x uint32 version numbers
        byte  has OverwriteTargetModuleName, then BinaryWriter string
        int64 BaseAddress
        int32 value count, then (uint64 id, uint32 offset) pairs
        int32 hash count,  then (uint64 id, uint64 hash) pairs

.rename: first line "2", then "<id> <name>" lines.
"""

import struct
import sys


class Library:
    def __init__(self, version, base_address=0x140000000, module=None, values=None, hashes=None):
        self.version = tuple(version)
        self.base_address = base_address
        self.module = module
        self.values = dict(values or {})
        self.hashes = dict(hashes or {})

    @property
    def version_string(self):
        return ".".join(str(x) for x in self.version)


class Database:
    def __init__(self):
        self.high_vid = 0
        self.pointer_size = 8
        self.module = None
        self.versions = {}  # version tuple -> Library
        self.names = {}     # id -> name

    def sorted_versions(self):
        return sorted(self.versions)


def _read_string(d, pos):
    n = 0
    shift = 0
    while True:
        b = d[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return d[pos:pos + n].decode("utf-8"), pos + n


def _write_string(w, s):
    b = s.encode("utf-8")
    n = len(b)
    while n >= 0x80:
        w.append((n & 0x7F) | 0x80)
        n >>= 7
    w.append(n)
    w += b


def read_relib(path):
    d = open(path, "rb").read()
    db = Database()
    pos = 0
    ver, = struct.unpack_from("<i", d, pos)
    pos += 4
    if ver < 1 or ver > 2:
        raise ValueError("unsupported relib save version %d" % ver)
    db.high_vid, db.pointer_size = struct.unpack_from("<Qi", d, pos)
    pos += 12
    if d[pos]:
        db.module, pos = _read_string(d, pos + 1)
    else:
        pos += 1
    count, = struct.unpack_from("<i", d, pos)
    pos += 4
    for _ in range(count):
        n, = struct.unpack_from("<i", d, pos)
        pos += 4
        nums = struct.unpack_from("<%dI" % n, d, pos)
        pos += 4 * n
        module = None
        if d[pos]:
            module, pos = _read_string(d, pos + 1)
        else:
            pos += 1
        base, = struct.unpack_from("<q", d, pos)
        pos += 8
        c, = struct.unpack_from("<i", d, pos)
        pos += 4
        values = {}
        if c:
            raw = struct.unpack_from("<" + "QI" * c, d, pos)
            pos += 12 * c
            values = dict(zip(raw[0::2], raw[1::2]))
        hashes = {}
        if ver >= 2:
            c, = struct.unpack_from("<i", d, pos)
            pos += 4
            if c:
                raw = struct.unpack_from("<" + "QQ" * c, d, pos)
                pos += 16 * c
                hashes = dict(zip(raw[0::2], raw[1::2]))
        db.versions[tuple(nums)] = Library(nums, base, module, values, hashes)
    if pos != len(d):
        raise ValueError("%d trailing bytes in %s" % (len(d) - pos, path))
    return db


def relib_bytes(db):
    w = bytearray()
    w += struct.pack("<iQi", 2, db.high_vid, db.pointer_size)
    if db.module is not None:
        w.append(1)
        _write_string(w, db.module)
    else:
        w.append(0)
    versions = db.sorted_versions()
    w += struct.pack("<i", len(versions))
    for v in versions:
        lib = db.versions[v]
        w += struct.pack("<i", len(lib.version))
        w += struct.pack("<%dI" % len(lib.version), *lib.version)
        if lib.module is not None:
            w.append(1)
            _write_string(w, lib.module)
        else:
            w.append(0)
        w += struct.pack("<q", lib.base_address)
        items = sorted(lib.values.items())
        w += struct.pack("<i", len(items))
        for k, val in items:
            w += struct.pack("<QI", k, val)
        items = sorted(lib.hashes.items())
        w += struct.pack("<i", len(items))
        for k, val in items:
            w += struct.pack("<QQ", k, val)
    return bytes(w)


def write_relib(path, db):
    with open(path, "wb") as f:
        f.write(relib_bytes(db))


def read_rename(path):
    names = {}
    with open(path, encoding="utf-8-sig") as f:
        first = f.readline()
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line[0] in ";#":
                continue
            k, _, v = line.partition(" ")
            names[int(k)] = v
    return names


def main():
    for p in sys.argv[1:]:
        db = read_relib(p)
        again = relib_bytes(db)
        orig = open(p, "rb").read()
        print("%s: module %s, pointer %d, HighVID %d, %d versions, roundtrip %s" % (
            p, db.module, db.pointer_size, db.high_vid, len(db.versions),
            "byte-identical" if again == orig else "DIFFERS"))
        for v in db.sorted_versions():
            lib = db.versions[v]
            print("  %-14s base 0x%X  %7d ids  %7d hashes  %s" % (lib.version_string, lib.base_address, len(lib.values), len(lib.hashes), lib.module or ""))


if __name__ == "__main__":
    main()
