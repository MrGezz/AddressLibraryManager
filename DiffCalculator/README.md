# DiffCalculator — carry Address Library IDs to a new executable without IDA

The Address Library Manager's "create new version … cross-diff import" expects the five text
files meh321's IDADiffCalculator plugin writes from IDA. This folder produces the same files
from the executables alone, and additionally writes the runtime `versionlib-*.bin` and an
updated `.relib` directly, so a game update can be handled headless:

```
python fndiff.py <old.exe> <old versionlib bin> <new.exe> --out <dir> --cache <cache dir>
                 [--gt <ground truth tsv>] [--relib <skyrimae.relib> --relib-out <path>] [--emit-added]
```

Outputs in `<dir>`: `output.txt`, `output_unmatched_prev.txt`, `output_unmatched_next.txt`,
`output_hash_prev.txt`, `output_hash_next.txt` (the Manager's import set, absolute addresses),
`versionlib-<new version>.bin`, `report.tsv` (one line per old ID: id, old, new, method,
section — or `UNRESOLVED: <reason>`), `fndiff.log`.

## Modules

| File | What it does | Verified how |
| --- | --- | --- |
| `addrlib.py` | reads/writes format 1 (SE `version-*.bin`), 2 (AE packed, `WritePackedPair` from `Manager.cs`) and 5 (the dense table meh321 introduced with 1.7.99: 96-byte header, `uint32 offset[id]`, 0 = unassigned — the layout commonlib-shared's `REL::IDDB::load_v5` memory-maps); `format_for(version)` picks 1 / 2 / 5 the way meh321 ships them | `python addrlib.py <bin>` round-trips `versionlib-1-6-317-0.bin` (format 2, 415,815 ids) and `versionlib-1-7-104-0.bin` (format 5, 435,162 ids) byte-identically (2026-09-12) |
| `relib.py` | reads/writes the Manager's `.relib` database and `.rename` names | `python relib.py skyrimae.relib` round-trips byte-identically; database now holds 14 versions, 1.6.317.0 through 1.7.104.0; all 13 pre-existing columns verified intact after adding the 1.7.104 column (2026-09-12) |
| `pe.py` | PE32+ sections, `.pdata` functions (chained unwind fragments folded), DIR64 relocations, file version | function counts / section maps printed by `python pe.py <exe>` |
| `fnhash.py` | per-function features: relocation-masked instruction hash (iced-x86), instruction IPs, outgoing calls, RIP-relative and absolute data references, opcode stream; leaf functions from `.pdata` gaps split at int3 padding, 16-aligned ret/jmp boundaries and known library addresses; pickled cache | ground truth below |
| `fndiff.py` | the matcher (methods in the module docstring: hash → callgraph → locality → inner / ref / vtable / shift) and all writers | `--gt` |
| `groundtruth.py` | `(old, new)` pairs from an SKSE "address update" commit (`RelocAddr`/`RelocPtr` literals) | 170 pairs for `ebc8000` (1.6.1170 → 1.7.99) in `data/` |
| `stats.py` | feasibility numbers only | – |

Requires Python 3.12 and `pip install iced-x86`.

## Before you run it

- **Unpack the old executable.** Steam builds up to 1.6.1170 are SteamStub 3.1 wrapped with an
  AES-encrypted `.text` (entropy 8.0 bits/byte; `.bind` section present). Decoding ciphertext
  "works" and matches nothing. Run it through Steamless (`Steamless.CLI.exe --quiet <exe>`;
  build from `github.com/atom0s/Steamless` with `-p:TargetFrameworkVersion=v4.8`). Offsets are
  RVAs and survive unpacking. 1.7.99 shipped with code encryption off.
- Never point it at a file inside an MO2 instance or the game folder for writing; copy first.
- Use a short `--cache` path on a local disk; the pickles are ~100 MB per executable and the
  first extraction takes a few minutes each.
- Keep the ground-truth table fresh: `python groundtruth.py <skse64 repo> <commit> data/gt-<old>-<new>.tsv`
  from the SKSE commit that moved to the new runtime, and always run with `--gt`.

## First run: 1.6.1170 → 1.7.99 (2026-08-23)

352,833 of 428,461 IDs resolved in 7.5 minutes (feature caches prebuilt: ~4 min per
executable); SKSE ground truth 143 correct / 0 wrong / 1 unresolved; RTTI check 8,494
confirmed / 18 rejected; verification rejected 118 function matches, among them 12
unique-hash coincidences caught by the link-order check. `conservative.py` then drops the
methods the checks showed to be fallible and writes the bin to ship (346,280 IDs) plus the
reduced `.relib` column; that is what went into `..\..\Runtime 1.7.99\`
and `..\..\AddressLibraryDatabase\skyrimae.relib` (the pre-1.7.99 database is kept at
`D:\tmp\icz-build\skyrimae.relib.before-1.7.99`). Raw outputs: `D:\tmp\icz-build\fndiff-1799\`.

Limits: a derived bin only knows IDs the old library had. Plugins rebuilt against the
official 1.7.99 library can use IDs meh321 created for it (EngineFixes 7.0.21 uses 523661
and 527785, above `HighVID` 522614) — those need the official bin. What is still missing,
in order of size: 55k data IDs nothing references or names (constant pools, tables without
RVAs), 16k IDs inside leaf chunks that found no counterpart, 4k inside unmatched functions.

## Scored against the official 1.7.99 library (2026-08-23)

meh321 published `versionlib-1-7-99-0.bin` on 2026-08-20 (format 5, 435,154 IDs up to
565,072: it keeps 392,696 of the 428,461 1.6.1170 IDs, drops 35,765 and adds 42,458 new
ones). The derived bins were scored against it; the full table is in
`..\..\Runtime 1.7.99\Address Library\diff\official-vs-derived.txt`:

| derived bin | shared with official | agree | wrong |
| --- | --- | --- | --- |
| conservative (346,280) | 334,844 | 333,445 (99.58 %) | 1,399 |
| full (352,833) | 340,786 | 339,196 (99.53 %) | 1,590 |

Per method the error is 0.0 % for the RTTI and string anchors, 0.1 % `hash`, 0.2–0.5 %
`ref`/`shift`/`vtable`/`record`/`hash-local`, 1.1 % `hash-order` (702 of the 1,399 —
runs of identical tiny stubs where one was inserted or removed shift every match by one
slot), 1.3–1.6 % callgraph, 3–5 % `piece`/`locality-sim`. So the checks ranked the methods
correctly, the conservative cut was worth it, and `hash-order` needs a run-length check
before the next update. 11,436 IDs the derived bin placed are absent from the official
library (meh321 dropped them), so agreement on the shared set is the only metric.

The official bin is what ships now; the derived ones are kept for diagnosis only.

## Official 1.7.104 bin (2026-09-12)

meh321 published `versionlib-1-7-104-0.bin` (format 5, 565,759 slots, 435,162 assigned,
130,597 zero/unassigned, HighVID 565,758). It was imported directly into
`..\..\AddressLibraryDatabase\skyrimae.relib` using `relib.py`; no fndiff.py run was
needed because the official bin covers the full ID space. The database now holds 14 versions,
1.6.317.0 through 1.7.104.0, HighVID 565,758.

C# code in `Manager.cs` (`ReadAddressLibrary` / `WriteDenseAddressLibrary`) was verified
against the format-5 contract on 2026-09-12:
- Header layout matches `addrlib.py`'s `V5_HEADER` exactly: format int32, version uint32[4],
  name char[64], pointer\_size int32, data\_format int32 (reserved), count int32 (96 bytes total).
- Zero/unassigned slots are skipped with an explicit `if (offset != 0)` guard in the reader
  and rejected with an `InvalidOperationException` in the writer — no silent id→0 mapping.
- `AddressLibraryFormatFor` returns `FormatDense` for any version ≥ 1.7, covering 1.7.104.

## Reading the result

`fndiff.log` ends with the per-method counts, the unresolved reasons and the ground-truth
line. IDs the matcher could not place are simply absent from the bin (a plugin asking for one
fails at startup with the usual "failed to find id" message rather than silently using a wrong
address); `report.tsv` lists them with the reason. Methods in descending confidence: `hash`,
`inner`, `callgraph`, `ref`, `vtable`, `inner-delta`, `callgraph-strong`, `locality-1`,
`shift`, `callgraph-vote`, `locality-sim`, `inner-align`, `shift-code`, `vtable-1`.
When the official bin appears, diff it against ours with a few lines of `addrlib` and prefer
the official one; this tool exists so the update is not blocked on it. The Manager's new
Tools → "Import an Address Library .bin" (or `relib.py` from Python) then replaces the derived
column in the database with the official values — the 1.7.99 column in
`..\..\AddressLibraryDatabase\skyrimae.relib` is the official one, HighVID 565,072.

## Importing into the Manager

`Names → Create new version … cross-diff import from IDADiffCalculator results` asks for the
previous and the new version and then for `output.txt`; the other four files are picked up
from the same folder. The new version must already exist in the database and be empty; the
Manager refuses to overwrite. `fndiff.py --relib … --relib-out …` does the same insertion
without the GUI (values + hashes; it never replaces a version that already has values).

## Ground truth for a 1.5.97 → 1.7 diff (`gt_ng.py`)

`groundtruth.py` mines an SKSE "address update" commit, which only exists for the runtimes
SKSE itself moved between. For a 1.5.97 → 1.7.99 diff there is no such commit, so `gt_ng.py`
builds the equivalent from CommonLibSSE-NG instead: NG spells every dual-runtime address as
`RELOCATION_ID(se, ae)` (also `RelocationID` / `VariantID`), which is a hand-verified pair of
Address Library ids. Resolving both sides through the two published bins yields the same
`file, name, kind, old, new` TSV `fndiff.py --gt` expects.

    python gt_ng.py <CommonLibSSE-NG\include> version-1-5-97-0.bin versionlib-1-7-99-0.bin out.tsv

9,134 pairs exist in NG; 8,292 resolve in both libraries (423 ids are absent from the 1.5.97
bin, 419 from the 1.7.99 one). Scored against it, the 1.5.97 → 1.7.99 run resolves 258,903 of
778,674 ids and is **99.65 % correct** on the 8,266 checkable ones (8,237 correct, 29 wrong).
That is the same order of accuracy as the 1.6.1170 → 1.7.99 run, over a far larger version
gap, but note the coverage difference: 1.6.1170 → 1.7.99 resolved 82 %, 1.5.97 → 1.7.99 only
33 %, because AE recompiled most of the executable.
