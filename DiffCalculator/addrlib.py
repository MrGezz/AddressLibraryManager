"""Address Library binary (version-*.bin / versionlib-*.bin) reader / writer, formats 1, 2 and 5.

Format 2 (every AE library up to 1.6.1179; format 1 is the identical packing under the SE
1.5.x "version-" name) mirrors Library.WriteAddressLibrary / WritePackedPair in ../Manager.cs
exactly, so a file read with read_bin() and written back with write_bin() is byte-identical
(see selftest()).  Layout:

    int32  format (1 or 2)
    int32  version[4]
    int32  module name length, then the name bytes (UTF-8)
    int32  pointer size
    int32  pair count
    pairs  first pair: byte 0, uint64 id, uint64 offset; then packed pairs:
           mask byte: low nibble = id encoding, high nibble = offset encoding (bit 3 = both
           offsets divided by pointer size before encoding)
             0 raw uint64 | 1 prev+1 | 2 prev+u8 | 3 prev-u8 | 4 prev+u16 | 5 prev-u16 | 6 u16 | 7 u32

Format 5 (introduced with the 1.7.99 library, 2026-08-20) is a dense table indexed by ID, read
by commonlib-shared's REL::IDDB::load_v5 / HEADER_V5 (the reference reader):

    int32   format (5)
    uint32  version[4]
    char    module name[64], NUL padded
    int32   pointer size
    int32   data format (0 in every file seen; reserved)
    int32   offset count N (= highest id + 1)
    uint32  offset[N], offset[id] == 0 means the id is not assigned

The reader memory-maps the file and indexes offset[id] directly, so an ID can never carry
offset 0 and the table length is part of the contract (an id >= N is out of range).
"""

import struct
import sys

FORMAT_PACKED_SE = 1   # version-*.bin, Skyrim SE 1.5.x: same packing as format 2, different tag
FORMAT_PACKED = 2
FORMAT_DENSE = 5
V5_NAME_LEN = 64
V5_HEADER = struct.Struct("<i4I%dsiii" % V5_NAME_LEN)  # 96 bytes


def format_for(version):
    """meh321 switched to the dense format with 1.7.99; older libraries stay packed."""
    v = tuple(version)
    return FORMAT_DENSE if v[:2] >= (1, 7) else FORMAT_PACKED


class VersionLib:
    def __init__(self, version=(0, 0, 0, 0), module="", pointer_size=8, values=None, format=None, data_format=0):
        self.version = tuple(version)
        self.module = module
        self.pointer_size = pointer_size
        self.values = dict(values or {})  # id -> offset (from image base)
        self.format = format              # 2, 5, or None = format_for(version)
        self.data_format = data_format    # format-5 header field, reserved

    @property
    def version_string(self):
        return "%d.%d.%d.%d" % self.version

    @property
    def effective_format(self):
        return self.format if self.format else format_for(self.version)

    def by_offset(self):
        out = {}
        for k, v in self.values.items():
            out.setdefault(v, k)
        return out


def read_bin(path):
    d = open(path, "rb").read()
    fmt, = struct.unpack_from("<i", d, 0)
    if fmt in (FORMAT_PACKED_SE, FORMAT_PACKED):
        return _read_packed(path, d, fmt)
    if fmt == FORMAT_DENSE:
        return _read_dense(path, d)
    raise ValueError("%s: unsupported format %d (Address Library formats 1, 2 and 5 are supported)" % (path, fmt))


def _read_dense(path, d):
    if len(d) < V5_HEADER.size:
        raise ValueError("%s: truncated format-5 header" % path)
    fmt, v0, v1, v2, v3, name, psize, data_format, count = V5_HEADER.unpack_from(d, 0)
    module = name.split(b"\0", 1)[0].decode("utf-8")
    end = V5_HEADER.size + 4 * count
    if end != len(d):
        raise ValueError("%s: %d offsets declared but %d bytes follow the header" % (path, count, len(d) - V5_HEADER.size))
    table = struct.unpack_from("<%dI" % count, d, V5_HEADER.size)
    values = {vid: off for vid, off in enumerate(table) if off}
    return VersionLib((v0, v1, v2, v3), module, psize, values, FORMAT_DENSE, data_format)


def _read_packed(path, d, fmt):
    pos = 0

    def u(fmt):
        nonlocal pos
        v = struct.unpack_from(fmt, d, pos)
        pos += struct.calcsize(fmt)
        return v if len(v) > 1 else v[0]

    u("<i")  # format, already checked
    version = u("<4i")
    nlen = u("<i")
    module = d[pos:pos + nlen].decode("utf-8")
    pos += nlen
    psize = u("<i")
    count = u("<i")
    values = {}
    pvid = poff = 0
    for i in range(count):
        mask = u("<B")
        low = mask & 0xF
        high = mask >> 4
        scaled = bool(high & 8)
        high &= 7
        if low == 0:
            vid = u("<Q")
        elif low == 1:
            vid = pvid + 1
        elif low == 2:
            vid = pvid + u("<B")
        elif low == 3:
            vid = pvid - u("<B")
        elif low == 4:
            vid = pvid + u("<H")
        elif low == 5:
            vid = pvid - u("<H")
        elif low == 6:
            vid = u("<H")
        else:
            vid = u("<I")
        pref = poff // psize if scaled else poff
        if high == 0:
            off = u("<Q")
        elif high == 1:
            off = pref + 1
        elif high == 2:
            off = pref + u("<B")
        elif high == 3:
            off = pref - u("<B")
        elif high == 4:
            off = pref + u("<H")
        elif high == 5:
            off = pref - u("<H")
        elif high == 6:
            off = u("<H")
        else:
            off = u("<I")
        if scaled:
            off *= psize
        values[vid] = off
        pvid, poff = vid, off
    if pos != len(d):
        raise ValueError("%s: %d trailing bytes" % (path, len(d) - pos))
    return VersionLib(version, module, psize, values, fmt)


def _pack_pair(w, vid, off, pvid, poff, sz):
    low = 0
    high = 0
    if off % sz == 0 and poff % sz == 0:
        off //= sz
        poff //= sz
        high |= 8
    vdiff = vid - pvid
    odiff = off - poff
    if vid == pvid + 1:
        low = 1
    elif 0 <= vdiff <= 0xFF:
        low = 2
    elif vdiff < 0 and -vdiff <= 0xFF:
        low = 3
    elif 0 <= vdiff <= 0xFFFF:
        low = 4
    elif vdiff < 0 and -vdiff <= 0xFFFF:
        low = 5
    elif vid <= 0xFFFF:
        low = 6
    elif vid <= 0xFFFFFFFF:
        low = 7
    if off == poff + 1:
        high |= 1
    elif 0 <= odiff <= 0xFF:
        high |= 2
    elif odiff < 0 and -odiff <= 0xFF:
        high |= 3
    elif 0 <= odiff <= 0xFFFF:
        high |= 4
    elif odiff < 0 and -odiff <= 0xFFFF:
        high |= 5
    elif off <= 0xFFFF:
        high |= 6
    elif off <= 0xFFFFFFFF:
        high |= 7
    w.append(((high & 0xF) << 4) | low)
    if low == 0:
        w += struct.pack("<Q", vid)
    elif low == 2:
        w += struct.pack("<B", vdiff)
    elif low == 3:
        w += struct.pack("<B", -vdiff)
    elif low == 4:
        w += struct.pack("<H", vdiff)
    elif low == 5:
        w += struct.pack("<H", -vdiff)
    elif low == 6:
        w += struct.pack("<H", vid)
    elif low == 7:
        w += struct.pack("<I", vid)
    h = high & 7
    if h == 0:
        w += struct.pack("<Q", off)
    elif h == 2:
        w += struct.pack("<B", odiff)
    elif h == 3:
        w += struct.pack("<B", -odiff)
    elif h == 4:
        w += struct.pack("<H", odiff)
    elif h == 5:
        w += struct.pack("<H", -odiff)
    elif h == 6:
        w += struct.pack("<H", off)
    elif h == 7:
        w += struct.pack("<I", off)


def _version4(lib):
    return list(lib.version)[:4] + [0] * (4 - len(lib.version))


def _packed_bytes(lib, fmt):
    w = bytearray()
    w += struct.pack("<i", fmt)
    w += struct.pack("<4i", *_version4(lib))
    name = lib.module.encode("utf-8")
    w += struct.pack("<i", len(name)) + name
    w += struct.pack("<i", lib.pointer_size)
    items = sorted(lib.values.items())
    w += struct.pack("<i", len(items))
    first = True
    pvid = poff = 0
    for vid, off in items:
        if first:
            w.append(0)
            w += struct.pack("<QQ", vid, off)
            first = False
        else:
            _pack_pair(w, vid, off, pvid, poff, lib.pointer_size)
        pvid, poff = vid, off
    return bytes(w)


def _dense_bytes(lib):
    name = lib.module.encode("utf-8")
    if len(name) >= V5_NAME_LEN:
        raise ValueError("module name %r does not fit the %d-byte format-5 field" % (lib.module, V5_NAME_LEN))
    count = (max(lib.values) + 1) if lib.values else 0
    table = bytearray(4 * count)
    for vid, off in lib.values.items():
        if vid < 0:
            raise ValueError("negative id %d" % vid)
        if not 0 < off <= 0xFFFFFFFF:
            raise ValueError("id %d: offset %#x cannot be stored in a format-5 table (0 means unassigned, 32-bit)" % (vid, off))
        struct.pack_into("<I", table, 4 * vid, off)
    return V5_HEADER.pack(FORMAT_DENSE, *_version4(lib), name, lib.pointer_size, lib.data_format, count) + bytes(table)


def to_bytes(lib, fmt=None):
    fmt = fmt or lib.effective_format
    if fmt in (FORMAT_PACKED_SE, FORMAT_PACKED):
        return _packed_bytes(lib, fmt)
    if fmt == FORMAT_DENSE:
        return _dense_bytes(lib)
    raise ValueError("unsupported format %r" % (fmt,))


def write_bin(path, lib, fmt=None):
    with open(path, "wb") as f:
        f.write(to_bytes(lib, fmt))


def bin_name(version, fmt=None):
    """versionlib-*.bin for AE/1.7 libraries, version-*.bin for the format-1 SE 1.5.x ones."""
    root = "version" if fmt == FORMAT_PACKED_SE else "versionlib"
    return "%s-%d-%d-%d-%d.bin" % ((root,) + tuple(version))


def selftest(path):
    lib = read_bin(path)
    again = to_bytes(lib, lib.format)
    orig = open(path, "rb").read()
    print("%s: format %d, %s, %s, %d ids, ptr %d, roundtrip %s" % (
        path, lib.format, lib.version_string, lib.module, len(lib.values), lib.pointer_size,
        "byte-identical" if again == orig else "DIFFERS (%d vs %d bytes)" % (len(again), len(orig))))
    return again == orig


if __name__ == "__main__":
    ok = all(selftest(p) for p in sys.argv[1:])
    sys.exit(0 if ok else 1)
