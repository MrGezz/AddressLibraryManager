"""Function inventory and relocation-masked instruction hashing for one executable.

A function's token stream is its decoded instruction sequence with everything that moves
between builds masked out: RIP-relative displacements, call/jump targets outside the
function, and immediates/displacements that are absolute image addresses.  Two builds of
the same source therefore produce the same hash for a function whose code did not change,
regardless of where the linker put it or what it references.

Functions come from the exception directory (.pdata); x64 leaf functions have no unwind
info, so the gaps between .pdata ranges are split on int3 (0xCC) padding runs and every
non-padding chunk is treated as a candidate leaf function.

    python fnhash.py <exe> [--cache <dir>]     prints an inventory summary
"""

import hashlib
import os
import pickle
import struct
import sys

from iced_x86 import Code, Decoder, FlowControl, OpKind

from pe import PE

IMM_KINDS = frozenset((OpKind.IMMEDIATE8, OpKind.IMMEDIATE16, OpKind.IMMEDIATE32, OpKind.IMMEDIATE64,
                       OpKind.IMMEDIATE8TO16, OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64,
                       OpKind.IMMEDIATE32TO64, OpKind.IMMEDIATE8_2ND))
BR_KINDS = frozenset((OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64))
U64 = 0xFFFFFFFFFFFFFFFF


CACHE_FORMAT = "v4"
END_FLOW = frozenset((FlowControl.RETURN, FlowControl.UNCONDITIONAL_BRANCH, FlowControl.INDIRECT_BRANCH,
                      FlowControl.INTERRUPT, FlowControl.EXCEPTION))


class Func:
    __slots__ = ("begin", "end", "ranges", "leaf", "hash", "ips", "calls", "datarefs", "absrefs", "ntok", "codes")

    def __init__(self, begin, end, ranges, leaf):
        self.begin = begin
        self.end = end
        self.ranges = ranges          # [(begin, end)] main body first, then chained fragments
        self.leaf = leaf              # True when discovered from a .pdata gap (no unwind info)
        self.hash = 0
        self.ips = ()                 # instruction start RVAs in decode order
        self.calls = ()               # (instruction index, target rva, is_call) for branches leaving the function
        self.datarefs = ()            # (instruction index, target rva) for RIP-relative operands
        self.absrefs = ()             # (instruction index, target rva) for absolute-address immediates
        self.ntok = 0
        self.codes = b""              # uint16 iced Code value per instruction, decode order (for similarity)

    @property
    def size(self):
        return sum(e - b for b, e in self.ranges)


class _Unpickler(pickle.Unpickler):
    """Caches written by `python fnhash.py` reference __main__.Func; map both spellings here."""

    def find_class(self, module, name):
        if name == "Func" and module in ("__main__", "fnhash"):
            return Func
        return super().find_class(module, name)


def _extract(pe, fn):
    base = pe.image_base
    ranges = fn.ranges
    tok = bytearray()
    codes = bytearray()
    ips = []
    calls = []
    datarefs = []
    absrefs = []
    for b, e in ranges:
        dec = Decoder(64, pe.read(b, e - b), ip=base + b)
        for ins in dec:
            ips.append(ins.ip - base)
            idx = len(ips) - 1
            code = ins.code
            codes += struct.pack("<H", code)
            if code == Code.INVALID:
                tok += b"?"
                continue
            tok += struct.pack("<H", code)
            for i in range(ins.op_count):
                k = ins.op_kind(i)
                if k == OpKind.REGISTER:
                    tok += struct.pack("<H", ins.op_register(i))
                elif k == OpKind.MEMORY:
                    if ins.is_ip_rel_memory_operand:
                        tok += b"R"
                        datarefs.append((idx, ins.ip_rel_memory_address - base))
                    else:
                        d = ins.memory_displacement
                        if ins.memory_base == 0 and ins.memory_index == 0 and pe.in_image(d):
                            tok += b"A"
                            absrefs.append((idx, d - base))
                        else:
                            tok += b"M" + struct.pack("<HHQ", ins.memory_base, ins.memory_index, d & U64)
                elif k in BR_KINDS:
                    t = ins.near_branch_target - base
                    inside = False
                    for rb, re_ in ranges:
                        if rb <= t < re_:
                            inside = True
                            break
                    if inside:
                        tok += b"I" + struct.pack("<i", ins.near_branch_target - ins.ip)
                    else:
                        tok += b"X"
                        calls.append((idx, t, 1 if ins.is_call_near else 0))
                elif k in IMM_KINDS:
                    v = ins.immediate(i) & U64
                    if pe.in_image(v):
                        tok += b"A"
                        absrefs.append((idx, v - base))
                    else:
                        tok += b"V" + struct.pack("<Q", v)
                else:
                    tok += b"K" + bytes((k & 0xFF,))
    fn.hash = int.from_bytes(hashlib.blake2b(bytes(tok), digest_size=8).digest(), "little")
    fn.ips = tuple(ips)
    fn.calls = tuple(calls)
    fn.datarefs = tuple(datarefs)
    fn.absrefs = tuple(absrefs)
    fn.ntok = len(tok)
    fn.codes = bytes(codes)


def _flow_splits(pe, b, e):
    """16-byte aligned addresses inside [b, e) that follow a ret / jmp / int3 / ud2: the places
    where one leaf function ends and the next begins when no int3 padding separates them."""
    out = []
    dec = Decoder(64, pe.read(b, e - b), ip=pe.image_base + b)
    for ins in dec:
        # Split after every ret / jmp / int3 / ud2: MSVC does not align leaf functions and
        # import thunks sit back to back, so alignment cannot be trusted. Over-splitting a
        # multi-return function into pieces is harmless because both images split the same way.
        if ins.flow_control in END_FLOW:
            nxt = ins.next_ip - pe.image_base
            if nxt < e:
                out.append(nxt)
    return out


def _leaf_candidates(pe, covered):
    """Split every executable-section gap not covered by .pdata on int3 padding runs."""
    out = []
    data = pe.data
    for s in pe.sections:
        if not s.executable:
            continue
        sec_end = s.va + s.rawsize
        pos = s.va
        # covered is sorted [(b, e)]; walk it in lockstep
        import bisect
        i = bisect.bisect_left(covered, (pos, 0))
        while pos < sec_end:
            if i < len(covered) and covered[i][0] <= pos:
                pos = max(pos, covered[i][1])
                i += 1
                continue
            gap_end = covered[i][0] if i < len(covered) else sec_end
            gap_end = min(gap_end, sec_end)
            off = pe.rva_to_off(pos)
            if off is None:
                break
            chunk = data[off:off + (gap_end - pos)]
            j = 0
            n = len(chunk)
            while j < n:
                while j < n and chunk[j] == 0xCC:
                    j += 1
                if j >= n:
                    break
                k = j
                while k < n and chunk[k] != 0xCC:
                    k += 1
                if k - j >= 2:
                    out.append((pos + j, pos + k))
                j = k
            pos = gap_end
    return out


def inventory(pe, extra_starts=()):
    """All functions of the image: .pdata functions (fragments folded) plus leaf candidates.

    extra_starts: known code addresses (e.g. from an Address Library) that must start a
    function even when they sit inside a gap chunk; the chunk is split there."""
    fns = []
    covered = []
    for f in pe.functions():
        ranges = [(f.begin, f.end)] + sorted(f.fragments)
        fns.append(Func(f.begin, f.end, ranges, False))
        covered.extend(ranges)
    covered.sort()
    import bisect
    splits = sorted(set(extra_starts))
    for b, e in _leaf_candidates(pe, covered):
        i = bisect.bisect_right(splits, b)
        j = bisect.bisect_left(splits, e)
        cuts = sorted(set(splits[i:j]) | set(_flow_splits(pe, b, e)))
        starts = [b] + cuts
        ends = cuts + [e]
        for sb, se in zip(starts, ends):
            fns.append(Func(sb, se, [(sb, se)], True))
    fns.sort(key=lambda f: f.begin)
    return fns


def build(path, extra_starts=(), cache_dir=None):
    pe = PE(path)
    key = None
    if cache_dir:
        st = os.stat(path)
        key = os.path.join(cache_dir, "%s-%d-%d-%d-%s.pickle" % (os.path.basename(path), st.st_size, int(st.st_mtime), len(extra_starts), CACHE_FORMAT))
        if os.path.isfile(key):
            with open(key, "rb") as f:
                return pe, _Unpickler(f).load()
    fns = inventory(pe, extra_starts)
    for fn in fns:
        _extract(pe, fn)
    if key:
        os.makedirs(cache_dir, exist_ok=True)
        with open(key, "wb") as f:
            pickle.dump(fns, f, protocol=pickle.HIGHEST_PROTOCOL)
    return pe, fns


def main():
    args = sys.argv[1:]
    cache = None
    starts = ()
    paths = []
    i = 0
    while i < len(args):
        if args[i] == "--cache":
            cache = args[i + 1]
            i += 2
        elif args[i] == "--starts":
            # split leaf-function gaps at the code addresses an Address Library bin knows
            import addrlib
            starts = sorted(set(addrlib.read_bin(args[i + 1]).values.values()))
            i += 2
        else:
            paths.append(args[i])
            i += 1
    for p in paths:
        pe, fns = build(p, extra_starts=starts, cache_dir=cache)
        from collections import Counter
        hc = Counter(f.hash for f in fns)
        uniq = sum(1 for f in fns if hc[f.hash] == 1)
        leaf = sum(1 for f in fns if f.leaf)
        print("%s: %d functions (%d leaf candidates), %d with a unique hash, %d instructions" % (
            p, len(fns), leaf, uniq, sum(len(f.ips) for f in fns)))


if __name__ == "__main__":
    main()
