"""Carry Address Library IDs from one SkyrimSE.exe build to the next without IDA.

    python fndiff.py <old.exe> <old versionlib bin> <new.exe> --out <dir>
                     [--cache <dir>] [--gt <ground truth tsv>] [--emit-added]
                     [--relib <skyrimae.relib> --relib-out <path>]

Matching, in order of confidence:
  hash        the function's relocation-masked instruction stream is unique in both images
  callgraph   a matched caller pair refers to it at the same call/data-reference position
              (hash-equal caller pairs give exact positions; others need agreement)
  locality    it is the only unmatched function between two matched neighbours, or the most
              similar opcode stream among the unmatched functions in that window
  inner       an address inside a matched function: same instruction index (hash-equal
              pairs) or aligned opcode streams
  ref         data: a matched function pair references old/new at the same operand position
  vtable      data: a run of pointer slots whose targets are matched functions
  shift       data/code with matched neighbours on both sides that moved by the same delta

Writes the IDADiffCalculator file set the Address Library Manager imports (output.txt,
output_unmatched_prev.txt, output_unmatched_next.txt, output_hash_prev.txt,
output_hash_next.txt), the runtime bin for the new version, report.tsv with one line per
old ID (id, old, new, method, section) and, with --relib, the updated database.
"""

import bisect
import difflib
import os
import re
import struct
import sys
from collections import Counter, defaultdict

import addrlib
import fnhash
import relib as relibmod


class Image:
    def __init__(self, path, extra_starts=(), cache=None):
        self.path = path
        self.pe, self.fns = fnhash.build(path, extra_starts, cache)
        self.by_begin = {f.begin: f for f in self.fns}
        self.begins = [f.begin for f in self.fns]
        ivals = []
        for f in self.fns:
            for b, e in f.ranges:
                ivals.append((b, e, f))
        ivals.sort(key=lambda t: t[0])
        self.ivals = ivals
        self.iv_starts = [t[0] for t in ivals]
        self.by_hash = defaultdict(list)
        for f in self.fns:
            self.by_hash[f.hash].append(f)
        self.ptr = self.pe.pointer_targets()
        self.ptr_by_target = defaultdict(list)
        for s, t in self.ptr.items():
            self.ptr_by_target[t].append(s)
        self._ipidx = {}

    def locate(self, rva):
        i = bisect.bisect_right(self.iv_starts, rva) - 1
        if i >= 0:
            b, e, f = self.ivals[i]
            if b <= rva < e:
                return f
        return None

    def ipidx(self, f):
        d = self._ipidx.get(f.begin)
        if d is None:
            d = {ip: i for i, ip in enumerate(f.ips)}
            self._ipidx[f.begin] = d
        return d

    def is_code(self, rva):
        s = self.pe.section_of(rva)
        return s is not None and s.executable

    def section_name(self, rva):
        s = self.pe.section_of(rva)
        return s.name if s else "?"


_ANON = re.compile(rb"\?A0x[0-9a-f]{8}")      # anonymous-namespace hash, differs per build
_LAMBDA = re.compile(rb"lambda_[0-9a-f]+")    # lambda class hash, differs when the source moves


def norm_name(raw):
    return _ANON.sub(b"?A0x", _LAMBDA.sub(b"lambda_", raw))


def rtti_name(img, vt):
    """(normalised class name, offset-in-object) of the MSVC vtable at rva vt, via the RTTI
    Complete Object Locator stored in the slot before it; None if that slot is not one."""
    col = img.ptr.get(vt - 8)
    if col is None:
        return None
    d = img.pe.read(col, 24)
    if len(d) < 24:
        return None
    sig, off, _cd, td, _chd, self_rva = struct.unpack("<6I", d)
    if sig != 1 or self_rva != col:
        return None
    name = img.pe.read(td + 16, 160).split(b"\0", 1)[0]
    if not name.startswith(b".?A"):
        return None
    return norm_name(name), off


def rtti_objects(img):
    """Every RTTI-described object of an image.

    objs:  rva -> (kind, key) for vtables, Complete Object Locators, TypeDescriptors,
           ClassHierarchyDescriptors, BaseClassArrays, BaseClassDescriptors (keyed by the
           sorted set of (class, index) positions they appear at) and global object instances
           in .data (a pointer slot holding a vtable with RTTI).
    index: (kind, key) -> rva, or None when the key is ambiguous in this image."""
    pe = img.pe
    objs = {}
    bcd_keys = defaultdict(set)
    seen_chd = set()
    for slot, target in img.ptr.items():
        d = pe.read(target, 24)
        if len(d) < 24:
            continue
        sig, off, _cd, tdr, chd, self_rva = struct.unpack("<6I", d)
        if sig != 1 or self_rva != target:
            continue
        raw = pe.read(tdr + 16, 160).split(b"\0", 1)[0]
        if not raw.startswith(b".?A"):
            continue
        name = norm_name(raw)
        objs[slot + 8] = ("vtable", (name, off))
        objs[target] = ("col", (name, off))
        objs[tdr] = ("td", name)
        if chd in seen_chd:
            continue
        seen_chd.add(chd)
        objs[chd] = ("chd", name)
        h = pe.read(chd, 16)
        if len(h) != 16:
            continue
        _sig, _attr, nb, bca = struct.unpack("<4I", h)
        objs[bca] = ("bca", name)
        for i in range(min(nb, 128)):
            b = pe.read(bca + 4 * i, 4)
            if len(b) == 4:
                bcd_keys[struct.unpack("<I", b)[0]].add((name, i))
    for rva, keys in bcd_keys.items():
        objs[rva] = ("bcd", tuple(sorted(keys)))
    vt_keys = {rva: key for rva, (kind, key) in objs.items() if kind == "vtable"}
    for slot, target in img.ptr.items():
        k = vt_keys.get(target)
        if k is not None and slot not in objs and img.section_name(slot) == ".data":
            objs[slot] = ("obj", k)
    index = {}
    for rva, kk in objs.items():
        if kk in index:
            if index[kk] != rva:
                index[kk] = None
        else:
            index[kk] = rva
    return objs, index


_STR8 = re.compile(rb"[\x20-\x7e]{4,}\0")
_STR16 = re.compile(rb"(?:[\x20-\x7e]\0){4,}\0\0")


def string_index(img):
    """Content -> rva of every NUL-terminated ASCII / UTF-16 run in .rdata (None if duplicated)."""
    out = {}
    for s in img.pe.sections:
        if s.name != ".rdata":
            continue
        data = img.pe.data[s.raw:s.raw + s.rawsize]
        for rx in (_STR8, _STR16):
            for m in rx.finditer(data):
                key = m.group(0)
                rva = s.va + m.start()
                if key in out:
                    if out[key] != rva:
                        out[key] = None
                else:
                    out[key] = rva
    return out


def string_at(img, off):
    raw = img.pe.read(off, 1024)
    if off > 0 and img.pe.read(off - 1, 1) not in (b"\0", b""):
        return None  # inside a longer string
    for rx in (_STR8, _STR16):
        m = rx.match(raw)
        if m:
            return m.group(0)
    return None


def similarity(a, b):
    if not a.codes or not b.codes:
        return 0.0
    sm = difflib.SequenceMatcher(None, a.codes, b.codes, autojunk=False)
    if sm.quick_ratio() < 0.5:
        return sm.quick_ratio()
    if len(a.codes) > 16000 or len(b.codes) > 16000:
        return sm.quick_ratio()
    return sm.ratio()


class Matcher:
    def __init__(self, old, new, relevant=None):
        self.old = old
        self.new = new
        self.fmap = {}
        self.rmap = {}
        self.method = {}
        self.rejected = {}
        self.pmap = {}    # old leaf piece begin -> (new chunk begin, instruction index inside it)
        self.relevant = relevant  # old function begins worth the expensive locality pass (None = all)
        self._blk = {}

    def match(self, o, n, how):
        self.fmap[o.begin] = n.begin
        self.rmap[n.begin] = o.begin
        self.method[o.begin] = how

    def unmatch(self, ob, why):
        nb = self.fmap.pop(ob)
        self.rmap.pop(nb, None)
        self.method.pop(ob, None)
        self.rejected[ob] = why

    # -- opcode-stream alignment for pairs whose hashes differ ---------------------------
    def blocks(self, o, n):
        """difflib matching blocks (byte offsets into .codes, 2 bytes per instruction)."""
        key = (o.begin, n.begin)
        b = self._blk.get(key)
        if b is None:
            if len(o.codes) > 40000 or len(n.codes) > 40000:
                b = []
            else:
                sm = difflib.SequenceMatcher(None, o.codes, n.codes, autojunk=False)
                b = [(a, c, s) for a, c, s in sm.get_matching_blocks() if s]
            self._blk[key] = b
        return b

    @staticmethod
    def map_index(blocks, idx):
        p = idx * 2
        for a, c, s in blocks:
            if a <= p < a + s:
                q = c + (p - a)
                return q // 2 if q % 2 == 0 else None
            if a > p:
                break
        return None

    # -- phase 1 ----------------------------------------------------------------------
    def phase_unique(self):
        c = 0
        for h, lo in self.old.by_hash.items():
            ln = self.new.by_hash.get(h)
            if ln and len(lo) == 1 and len(ln) == 1:
                self.match(lo[0], ln[0], "hash")
                c += 1
        return c

    # -- phase 2: reference propagation ---------------------------------------------------
    def collect_votes(self):
        """old target -> Counter((new target, strong)) from every matched pair's references."""
        fvotes = defaultdict(Counter)
        dvotes = defaultdict(Counter)
        for ob, nb in self.fmap.items():
            o = self.old.by_begin[ob]
            n = self.new.by_begin[nb]
            strong = o.hash == n.hash
            same_shape = len(o.calls) == len(n.calls) and len(o.datarefs) == len(n.datarefs) and len(o.absrefs) == len(n.absrefs)
            if strong or same_shape:
                for (_, to, co), (_, tn, cn) in zip(o.calls, n.calls):
                    if co == cn:
                        self._vote(fvotes, dvotes, to, tn, strong)
                for (_, to), (_, tn) in zip(o.datarefs, n.datarefs):
                    self._vote(fvotes, dvotes, to, tn, strong)
                for (_, to), (_, tn) in zip(o.absrefs, n.absrefs):
                    self._vote(fvotes, dvotes, to, tn, strong)
                continue
            # changed function: align the opcode streams and vote through matching blocks
            blocks = self.blocks(o, n)
            if not blocks:
                continue
            ncalls = {i: (t, c) for i, t, c in n.calls}
            ndata = {i: t for i, t in n.datarefs}
            nabs = {i: t for i, t in n.absrefs}
            for i, to, co in o.calls:
                j = self.map_index(blocks, i)
                if j is not None and j in ncalls and ncalls[j][1] == co:
                    self._vote(fvotes, dvotes, to, ncalls[j][0], False)
            for i, to in o.datarefs:
                j = self.map_index(blocks, i)
                if j is not None and j in ndata:
                    self._vote(fvotes, dvotes, to, ndata[j], False)
            for i, to in o.absrefs:
                j = self.map_index(blocks, i)
                if j is not None and j in nabs:
                    self._vote(fvotes, dvotes, to, nabs[j], False)
        return fvotes, dvotes

    def _vote(self, fvotes, dvotes, to, tn, strong):
        if to in self.old.by_begin:
            fvotes[to][(tn, strong)] += 1
        elif not self.old.is_code(to) and not self.new.is_code(tn):
            dvotes[to][(tn, strong)] += 1

    def resolve_fvotes(self, fvotes):
        claims = defaultdict(list)  # tn -> [(score, strong votes, total votes, to)]
        for to, cnt in fvotes.items():
            if to in self.fmap:
                continue
            fo = self.old.by_begin[to]
            total = sum(cnt.values())
            by_tn = Counter()
            strong_by_tn = Counter()
            for (tn, strong), c in cnt.items():
                by_tn[tn] += c
                if strong:
                    strong_by_tn[tn] += c
            tn, c = by_tn.most_common(1)[0]
            if tn in self.rmap or tn not in self.new.by_begin:
                continue
            if c * 10 < total * 6:
                continue
            fn = self.new.by_begin[tn]
            hash_eq = fo.hash == fn.hash
            s = strong_by_tn[tn]
            if not (hash_eq or s >= 1 or c >= 2):
                continue
            score = (1 if hash_eq else 0, s, c)
            claims[tn].append((score, to, hash_eq, s))
        added = 0
        for tn, lst in claims.items():
            lst.sort(reverse=True)
            score, to, hash_eq, s = lst[0]
            if len(lst) > 1 and lst[1][0] == score:
                continue
            how = "callgraph" if hash_eq else ("callgraph-strong" if s else "callgraph-vote")
            self.match(self.old.by_begin[to], self.new.by_begin[tn], how)
            added += 1
        return added

    # -- phase 3: locality ------------------------------------------------------------------
    def phase_locality(self):
        added = 0
        matched_old = sorted(self.fmap)
        new_unmatched = [f for f in self.new.fns if f.begin not in self.rmap]
        nu_begins = [f.begin for f in new_unmatched]
        old_unmatched = [f for f in self.old.fns if f.begin not in self.fmap]
        ou_begins = [f.begin for f in old_unmatched]
        for o in old_unmatched:
            if o.begin in self.fmap:
                continue
            if self.relevant is not None and o.begin not in self.relevant:
                continue
            i = bisect.bisect_left(matched_old, o.begin)
            a = matched_old[i - 1] if i > 0 else None
            b = matched_old[i] if i < len(matched_old) else None
            wstart = self.new.by_begin[self.fmap[a]].end if a is not None else 0
            wend = self.fmap[b] if b is not None else 1 << 62
            ostart = self.old.by_begin[a].end if a is not None else 0
            oend = b if b is not None else 1 << 62
            if wend <= wstart:
                continue
            lo = bisect.bisect_left(nu_begins, wstart)
            hi = bisect.bisect_left(nu_begins, wend)
            cands = [f for f in new_unmatched[lo:hi] if f.begin not in self.rmap]
            if not cands:
                continue
            olo = bisect.bisect_left(ou_begins, ostart)
            ohi = bisect.bisect_left(ou_begins, oend)
            olds = [f for f in old_unmatched[olo:ohi] if f.begin not in self.fmap]
            # duplicates: a hash that is not unique in the image is usually unique between two
            # matched neighbours, and runs of identical functions keep their link order
            same_n = [f for f in cands if f.hash == o.hash]
            if same_n:
                same_o = [f for f in olds if f.hash == o.hash]
                if len(same_n) == 1 and len(same_o) == 1:
                    self.match(o, same_n[0], "hash-local")
                    added += 1
                elif len(same_n) == len(same_o):
                    for a, b in zip(same_o, same_n):
                        self.match(a, b, "hash-order")
                        added += 1
                continue  # ambiguous counts: leave it to the reference votes
            if len(cands) == 1 and len(olds) == 1:
                n = cands[0]
                if 0.5 <= n.size / max(o.size, 1) <= 2.0 and similarity(o, n) >= 0.5:
                    self.match(o, n, "locality-1")
                    added += 1
                continue
            if o.leaf and len(o.codes) >= 6:
                # a leaf piece that was split at a library address in the old image may still be
                # merged into a larger chunk in the new one: look for its opcode stream inside
                # the window's chunks
                hits = []
                for n in cands:
                    if not n.leaf or len(n.codes) < len(o.codes):
                        continue
                    p = n.codes.find(o.codes)
                    while p != -1 and len(hits) < 2:
                        if p % 2 == 0:
                            hits.append((n, p // 2))
                        p = n.codes.find(o.codes, p + 1)
                    if len(hits) > 1:
                        break
                if len(hits) == 1:
                    n, idx = hits[0]
                    self.pmap[o.begin] = (n.begin, idx)
                    continue
            if len(o.ips) < 6:
                continue  # opcode similarity of a handful of instructions proves nothing
            if len(cands) > 64:
                # a wrong anchor can open a huge window; keep the candidates closest in size
                cands = sorted(cands, key=lambda n: abs(n.size - o.size))[:64]
            scored = sorted(((similarity(o, n), n) for n in cands), key=lambda t: -t[0])
            best, n = scored[0]
            second = scored[1][0] if len(scored) > 1 else 0.0
            if best >= 0.75 and best - second >= 0.1:
                self.match(o, n, "locality-sim")
                added += 1
        return added

    def verify(self, log):
        """Drop matches that their own callers or callees contradict (everything but hash/callgraph)."""
        fv, _ = self.collect_votes()
        rejected = Counter()
        # link order is preserved almost everywhere: a small function whose displacement differs
        # from its neighbours' by megabytes is a hash coincidence, not a match
        keys = sorted(self.fmap)
        deltas = [self.fmap[k] - k for k in keys]
        for i, ob in enumerate(keys):
            o = self.old.by_begin[ob]
            if len(o.ips) >= 64:
                continue
            around = deltas[max(0, i - 5):i] + deltas[i + 1:i + 6]
            if len(around) < 4:
                continue
            around.sort()
            med = around[len(around) // 2]
            if abs(deltas[i] - med) > 0x200000:
                rejected["order:" + self.method.get(ob, "?")] += 1
                self.unmatch(ob, "displacement %+d vs neighbours %+d" % (deltas[i], med))
        for ob in list(self.fmap):
            how = self.method[ob]
            if how in ("callgraph", "inner"):
                continue
            if how == "hash" and len(self.old.by_begin[ob].ips) >= 32:
                continue
            nb = self.fmap[ob]
            cnt = fv.get(ob)
            if cnt:
                total = sum(cnt.values())
                mine = sum(c for (tn, _), c in cnt.items() if tn == nb)
                if total >= 2 and mine * 2 < total:
                    self.unmatch(ob, "caller votes %d of %d" % (mine, total))
                    rejected[how] += 1
                    continue
            o = self.old.by_begin[ob]
            n = self.new.by_begin[nb]
            if o.calls and len(o.calls) == len(n.calls):
                agree = dis = 0
                for (_, to, _), (_, tn, _) in zip(o.calls, n.calls):
                    m = self.fmap.get(to)
                    if m is None:
                        continue
                    if m == tn:
                        agree += 1
                    else:
                        dis += 1
                if agree + dis >= 2 and agree * 2 < agree + dis:
                    self.unmatch(ob, "callees agree %d disagree %d" % (agree, dis))
                    rejected[how] += 1
        log("verification rejected %d matches: %s" % (sum(rejected.values()), dict(rejected)))

    def run(self, log):
        log("hash-unique: %d" % self.phase_unique())
        for rnd in range(16):
            total = 0
            while True:
                fv, _ = self.collect_votes()
                a = self.resolve_fvotes(fv)
                total += a
                if not a:
                    break
            log("round %d: propagation +%d" % (rnd, total))
            b = self.phase_locality()
            log("round %d: locality +%d" % (rnd, b))
            if total + b == 0:
                break
        self.verify(log)
        by = Counter(self.method.values())
        log("function matches by method: %s" % ", ".join("%s %d" % kv for kv in by.most_common()))
        return self.collect_votes()[1]


def main():
    args = sys.argv[1:]
    pos = []
    out = cache = gt = relib_in = relib_out = None
    emit_added = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--out":
            out = args[i + 1]; i += 2
        elif a == "--cache":
            cache = args[i + 1]; i += 2
        elif a == "--gt":
            gt = args[i + 1]; i += 2
        elif a == "--relib":
            relib_in = args[i + 1]; i += 2
        elif a == "--relib-out":
            relib_out = args[i + 1]; i += 2
        elif a == "--emit-added":
            emit_added = True; i += 1
        else:
            pos.append(a); i += 1
    if len(pos) != 3 or not out:
        print(__doc__)
        return 2
    old_exe, old_bin, new_exe = pos
    os.makedirs(out, exist_ok=True)
    logf = open(os.path.join(out, "fndiff.log"), "w", encoding="utf-8")

    def log(msg):
        print(msg)
        logf.write(msg + "\n")
        logf.flush()

    lib = addrlib.read_bin(old_bin)
    log("old library %s %s: %d ids" % (lib.module, lib.version_string, len(lib.values)))
    old = Image(old_exe, extra_starts=sorted(set(lib.values.values())), cache=cache)
    new = Image(new_exe, cache=cache)
    old_ver = old.pe.file_version()
    new_ver = new.pe.file_version()
    log("old image %s: %d functions; new image %s: %d functions" % (old_ver, len(old.fns), new_ver, len(new.fns)))
    if tuple(old_ver) != tuple(lib.version):
        log("WARNING: old exe version %s does not match the library version %s" % (old_ver, lib.version_string))

    relevant = set()
    for off in lib.values.values():
        f = old.locate(off)
        if f is not None:
            relevant.add(f.begin)
    log("old functions carrying at least one id: %d" % len(relevant))
    m = Matcher(old, new, relevant)
    dvotes = m.run(log)
    log("functions matched: %d of %d old (%d new unmatched)" % (len(m.fmap), len(old.fns), len(new.fns) - len(m.rmap)))

    # data references: a hash-equal pair's reference is exact; weak votes must be unanimous
    dmap = {}
    for to, cnt in dvotes.items():
        by_tn = Counter()
        strong = Counter()
        for (tn, s), c in cnt.items():
            by_tn[tn] += c
            if s:
                strong[tn] += c
        tn, c = by_tn.most_common(1)[0]
        total = sum(by_tn.values())
        if strong:
            stn, sc = strong.most_common(1)[0]
            if sc == sum(strong.values()):
                dmap[to] = (stn, "ref")
            continue
        if c == total and c >= 2:
            dmap[to] = (tn, "ref-weak")

    # RTTI: everything reachable from a Complete Object Locator is named by its class, and
    # .rdata string literals by their content
    objs_old, _ = rtti_objects(old)
    _, index_new = rtti_objects(new)
    strings_new = string_index(new)
    rtti_hits = Counter()
    rmap = {}
    for off in set(lib.values.values()):
        if old.is_code(off):
            continue
        kk = objs_old.get(off)
        if kk is not None:
            target = index_new.get(kk)
            if target is not None:
                rmap[off] = (target, "rtti-" + kk[0])
                rtti_hits[kk[0]] += 1
            continue
        if old.section_name(off) == ".rdata":
            s = string_at(old, off)
            if s is not None:
                target = strings_new.get(s)
                if target is not None:
                    rmap[off] = (target, "string")
                    rtti_hits["string"] += 1
    log("named data objects placed: %s" % dict(rtti_hits))

    def vtable(d):
        if d not in old.ptr:
            return None
        seq = []
        s = d
        while s in old.ptr and len(seq) < 16:
            t = old.ptr[s]
            seq.append(m.fmap.get(t))
            s += 8
        known = [k for k, t in enumerate(seq) if t is not None]
        if not known:
            return None
        k0 = known[0]
        cands = [slot - 8 * k0 for slot in new.ptr_by_target.get(seq[k0], [])]
        good = [c for c in cands if all(new.ptr.get(c + 8 * k) == seq[k] for k in known)]
        if len(good) == 1:
            return good[0], ("vtable" if len(known) >= 2 else "vtable-1")
        return None

    # resolve every old id
    result = {}     # id -> (new offset, method)
    unmatched = {}  # id -> reason
    shift_anchors = {"code": {}, "data": {}}
    for ob, nb in m.fmap.items():
        shift_anchors["code"][ob] = nb
    for to, (tn, _) in dmap.items():
        shift_anchors["data"][to] = tn

    def shift(off, kind):
        anchors = shift_anchors[kind]
        keys = anchors.get("_sorted")
        if keys is None:
            keys = sorted(k for k in anchors if k != "_sorted")
            anchors["_sorted"] = keys
        i = bisect.bisect_left(keys, off)
        if i == 0 or i >= len(keys):
            return None
        sec = old.section_name(off)
        a, b = keys[i - 1], keys[i]
        da, db = anchors[a] - a, anchors[b] - b
        if da == db and off - a <= 0x4000 and b - off <= 0x4000 and old.section_name(a) == sec == old.section_name(b):
            return off + da, "shift"
        # wider window, but then the two nearest anchors on each side must all agree
        if i >= 2 and i + 1 < len(keys):
            ks = keys[i - 2:i + 2]
            ds = [anchors[k] - k for k in ks]
            if len(set(ds)) == 1 and off - ks[0] <= 0x20000 and ks[-1] - off <= 0x20000 and all(old.section_name(k) == sec for k in ks):
                return off + ds[0], "shift2"
        return None

    for vid, off in sorted(lib.values.items()):
        if off in m.fmap:
            result[vid] = (m.fmap[off], m.method[off])
            continue
        if old.is_code(off):
            f = old.locate(off)
            if f is None:
                n = shift(off, "code")
                if n is not None:
                    result[vid] = (n[0], "shift-code")
                else:
                    unmatched[vid] = "code outside any function"
                continue
            if f.begin not in m.fmap:
                if f.begin in m.pmap:
                    nb, base_idx = m.pmap[f.begin]
                    idx = old.ipidx(f).get(off)
                    nf = new.by_begin[nb]
                    if idx is not None and base_idx + idx < len(nf.ips):
                        result[vid] = (nf.ips[base_idx + idx], "piece")
                    else:
                        unmatched[vid] = "inside a piece, not at an instruction"
                    continue
                unmatched[vid] = "inside a rejected match" if f.begin in m.rejected else (
                    "inside unmatched leaf chunk" if f.leaf else "inside unmatched function")
                continue
            nf = new.by_begin[m.fmap[f.begin]]
            idx = old.ipidx(f).get(off)
            if idx is None:
                if f.hash == nf.hash:
                    result[vid] = (nf.begin + (off - f.begin), "inner-delta")
                else:
                    unmatched[vid] = "not an instruction start in a changed function"
                continue
            if f.hash == nf.hash and idx < len(nf.ips):
                result[vid] = (nf.ips[idx], "inner")
                continue
            j = m.map_index(m.blocks(f, nf), idx)
            hit = nf.ips[j] if j is not None and j < len(nf.ips) else None
            if hit is not None:
                result[vid] = (hit, "inner-align")
            else:
                unmatched[vid] = "instruction not aligned in changed function"
            continue
        # data
        if off in rmap:
            result[vid] = rmap[off]
            continue
        if off in dmap:
            result[vid] = dmap[off]
            continue
        vt = vtable(off)
        if vt is not None:
            result[vid] = vt
            continue
        n = shift(off, "data")
        if n is not None:
            result[vid] = n
        else:
            unmatched[vid] = "data without references or anchors"

    # ---- structured records -----------------------------------------------------------------
    # Exception-handling tables, catch/throw type records and RVA tables are referenced by no
    # instruction, but they are built from RVAs of things already matched: translate the RVA
    # fields and look the translated record up in the new image.
    import numpy as np
    vals = []
    posl = []
    secarr = {}
    for s in new.pe.sections:
        if s.name not in (".rdata", ".data"):
            continue
        n = s.rawsize // 4
        arr = np.frombuffer(new.pe.data, dtype="<u4", count=n, offset=s.raw).astype(np.int64)
        secarr[s.name] = (s.va, arr)
        vals.append(arr)
        posl.append(s.va + 4 * np.arange(n, dtype=np.int64))
    vals = np.concatenate(vals)
    posl = np.concatenate(posl)
    order = np.argsort(vals, kind="stable")
    svals = vals[order]
    spos = posl[order]
    del vals, posl, order

    def positions(v):
        lo = int(np.searchsorted(svals, v, "left"))
        hi = int(np.searchsorted(svals, v, "right"))
        return lo, hi

    def fetch(sec, rvas):
        """dwords of the new image at the given rvas (same section), -1 where out of range."""
        va, arr = secarr[sec]
        idx = (rvas - va) // 4
        valid = (rvas >= va) & (idx < len(arr)) & ((rvas - va) % 4 == 0)
        out = np.full(len(rvas), -1, dtype=np.int64)
        out[valid] = arr[idx[valid]]
        return out

    size_old = old.pe.size_of_image
    data_res = {}
    for vid, (noff, _) in result.items():
        o = lib.values[vid]
        if not old.is_code(o):
            data_res[o] = noff

    def translate_code(rva):
        if rva in m.fmap:
            return m.fmap[rva]
        f = old.locate(rva)
        if f is None:
            return None
        if f.begin in m.pmap:
            nb, base_idx = m.pmap[f.begin]
            idx = old.ipidx(f).get(rva)
            nf = new.by_begin[nb]
            return nf.ips[base_idx + idx] if idx is not None and base_idx + idx < len(nf.ips) else None
        if f.begin not in m.fmap:
            return None
        nf = new.by_begin[m.fmap[f.begin]]
        idx = old.ipidx(f).get(rva)
        if idx is None:
            return nf.begin + (rva - f.begin) if f.hash == nf.hash else None
        if f.hash == nf.hash:
            return nf.ips[idx] if idx < len(nf.ips) else None
        j = m.map_index(m.blocks(f, nf), idx)
        return nf.ips[j] if j is not None and j < len(nf.ips) else None

    def translate(rva):
        return translate_code(rva) if old.is_code(rva) else data_res.get(rva)

    def match_record(off):
        raw = old.pe.read(off, 16)
        sec = old.section_name(off)
        for nbytes in (16, 8):
            if len(raw) < nbytes:
                continue
            words = struct.unpack("<%dI" % (nbytes // 4), raw[:nbytes])
            anchors = []
            consts = []
            for i, w in enumerate(words):
                if 0x1000 <= w < size_old:
                    t = translate(w)
                    if t is not None:
                        anchors.append((i, t))
                else:
                    consts.append((i, w))
            if not anchors or len(anchors) + len(consts) < 2:
                continue
            # anchor on the rarest translated value
            i0, t0, lo, hi = None, None, 0, 1 << 30
            for i, t in anchors:
                a, b = positions(t)
                if b - a < hi - lo:
                    i0, t0, lo, hi = i, t, a, b
            if hi - lo == 0 or hi - lo > 20000 or sec not in secarr:
                continue
            bases = spos[lo:hi] - 4 * i0
            va, arr = secarr[sec]
            mask = (bases >= va) & (bases < va + 4 * len(arr))
            for i, t in anchors:
                if i != i0:
                    mask &= fetch(sec, bases + 4 * i) == t
            for i, w in consts:
                mask &= fetch(sec, bases + 4 * i) == w
            hits = bases[mask]
            if len(hits) == 1:
                return int(hits[0])
        return None

    for rnd in range(3):
        added = 0
        for vid, why in list(unmatched.items()):
            off = lib.values[vid]
            if old.is_code(off):
                continue
            n = match_record(off)
            if n is not None:
                result[vid] = (n, "record")
                data_res[off] = n
                del unmatched[vid]
                added += 1
        log("record pass %d: +%d" % (rnd, added))
        if not added:
            break

    # independent check: every resolved vtable must name the same class at the same offset
    vt_ok = Counter()
    vt_bad = Counter()
    for vid, (noff, how) in list(result.items()):
        a = rtti_name(old, lib.values[vid])
        if a is None:
            continue
        if rtti_name(new, noff) == a:
            vt_ok[how] += 1
        else:
            vt_bad[how] += 1
            del result[vid]
            unmatched[vid] = "rtti class name mismatch"
    log("RTTI check on resolved vtables: %d confirmed %s" % (sum(vt_ok.values()), dict(vt_ok)))
    log("                               %d rejected %s" % (sum(vt_bad.values()), dict(vt_bad)))
    # a resolved address must stay in the section of the same name
    moved = Counter()
    for vid, (noff, how) in list(result.items()):
        if old.section_name(lib.values[vid]) != new.section_name(noff):
            moved[how] += 1
            del result[vid]
            unmatched[vid] = "section mismatch"
    log("section-mismatch rejections: %d %s" % (sum(moved.values()), dict(moved)))

    by_method = Counter(v[1] for v in result.values())
    log("ids resolved: %d of %d" % (len(result), len(lib.values)))
    for k, v in sorted(by_method.items(), key=lambda kv: -kv[1]):
        log("  %-18s %7d" % (k, v))
    reasons = Counter(unmatched.values())
    log("ids unresolved: %d" % len(unmatched))
    for k, v in reasons.most_common(8):
        log("  %-60s %7d" % (k[:60], v))

    # ground truth
    if gt:
        pairs = []
        for line in open(gt, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) < 5 or p[0] == "file":
                continue
            pairs.append((p[1], int(p[3], 16), int(p[4], 16)))
        by_off = lib.by_offset()
        ok = bad = nolib = nores = 0
        for name, o, n in pairs:
            vid = by_off.get(o)
            if vid is None:
                nolib += 1
                continue
            r = result.get(vid)
            if r is None:
                nores += 1
                log("  GT unresolved %s 0x%X (%s)" % (name, o, unmatched.get(vid)))
            elif r[0] == n:
                ok += 1
            else:
                bad += 1
                log("  GT WRONG %s old 0x%X -> 0x%X via %s, truth 0x%X" % (name, o, r[0], r[1], n))
        log("ground truth: %d pairs, %d not in old library, %d correct, %d wrong, %d unresolved" % (len(pairs), nolib, ok, bad, nores))

    # outputs -----------------------------------------------------------------------------
    base = old.pe.image_base
    with open(os.path.join(out, "report.tsv"), "w", encoding="utf-8") as f:
        f.write("id\told\tnew\tmethod\tsection\n")
        for vid, off in sorted(lib.values.items()):
            r = result.get(vid)
            if r:
                f.write("%d\t0x%X\t0x%X\t%s\t%s\n" % (vid, off, r[0], r[1], old.section_name(off)))
            else:
                f.write("%d\t0x%X\t\tUNRESOLVED: %s\t%s\n" % (vid, off, unmatched[vid], old.section_name(off)))
    with open(os.path.join(out, "output.txt"), "w", encoding="utf-8") as f:
        f.write("fndiff %s -> %s\n\n" % (lib.version_string, ".".join(map(str, new_ver))))
        seen = set()
        for vid, (noff, _) in sorted(result.items()):
            off = lib.values[vid]
            if off in seen:
                continue
            seen.add(off)
            f.write("0x%X\t0x%X\n" % (base + off, base + noff))
    with open(os.path.join(out, "output_unmatched_prev.txt"), "w", encoding="utf-8") as f:
        for vid in sorted(unmatched):
            f.write("0x%X\n" % (base + lib.values[vid]))
    with open(os.path.join(out, "output_unmatched_next.txt"), "w", encoding="utf-8") as f:
        if emit_added:
            for fn in new.fns:
                if fn.begin not in m.rmap and not fn.leaf:
                    f.write("0x%X\n" % (base + fn.begin))
    with open(os.path.join(out, "output_hash_prev.txt"), "w", encoding="utf-8") as f:
        for fn in old.fns:
            f.write("0x%X\t%d\n" % (base + fn.begin, fn.hash))
    with open(os.path.join(out, "output_hash_next.txt"), "w", encoding="utf-8") as f:
        for fn in new.fns:
            f.write("0x%X\t%d\n" % (base + fn.begin, fn.hash))

    newlib = addrlib.VersionLib(new_ver, lib.module, lib.pointer_size, {vid: r[0] for vid, r in result.items()})
    bin_path = os.path.join(out, addrlib.bin_name(new_ver))
    addrlib.write_bin(bin_path, newlib)
    log("wrote %s (%d ids)" % (bin_path, len(newlib.values)))

    if relib_in and relib_out:
        db = relibmod.read_relib(relib_in)
        key = tuple(new_ver)
        if key in db.versions and db.versions[key].values:
            log("relib already has %s with %d ids - not replaced" % (".".join(map(str, key)), len(db.versions[key].values)))
        else:
            hashes = {}
            for vid, (noff, _) in result.items():
                fn = new.by_begin.get(noff)
                if fn is not None:
                    hashes[vid] = fn.hash
            db.versions[key] = relibmod.Library(key, values=newlib.values, hashes=hashes)
            relibmod.write_relib(relib_out, db)
            log("wrote %s (+%s: %d ids, %d hashes)" % (relib_out, ".".join(map(str, key)), len(newlib.values), len(hashes)))
    logf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
