"""Decrypt the code section of a SteamStub 3.1 (x64) protected executable, for static analysis.

Reference executables (SkyrimSE.exe 1.6.x from Steam) ship with SteamStub: the entry point sits
in a .bind section and .text is AES-256-CBC encrypted, so a disassembler sees noise (entropy
8.0). This writes a copy whose .text is the plaintext and whose entry point is the original one.
It never runs the stub. The output is for reading bytes (hooksite.py, hookport.py), not for
launching the game.

    python steamstub.py <in.exe> <out.exe>

Scheme (the one Steamless' Variant31 x64 unpacker implements):
  header = 0xF0 bytes just below the entry point, XOR-chained: key0 = first dword, then each
           dword is xored with the previous encrypted dword; signature 0xC0DEC0DF at +4
  +0x20 original entry point   +0x3C flags (0x04 = code not encrypted)
  +0x48 code section VA        +0x58 AES key (32)   +0x78 AES IV (16, itself ECB-encrypted)
  +0x88 the first 16 bytes of the code section's ciphertext ("stolen" out of the file)
  plaintext = AES-CBC(key, ECB-decrypt(IV))(stolen + section raw data); RVA va+k = plaintext[k]
Verification: the output must disassemble to the same instruction the Address Library points at
for a known function; check with hooksite.py before trusting it.
"""

import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER_SIZE = 0xF0
SIGNATURE = 0xC0DEC0DF
FLAG_NO_ENCRYPTION = 0x04


def steam_xor(data, key=0):
    out = bytearray(data)
    off = 0
    if key == 0:
        key = struct.unpack_from("<I", out, 0)[0]
        off = 4
    for x in range(off, len(out) - len(out) % 4, 4):
        val = struct.unpack_from("<I", out, x)[0]
        struct.pack_into("<I", out, x, val ^ key)
        key = val
    return bytes(out)


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    sec0 = pe + 24 + optsz
    out = []
    for i in range(nsec):
        o = sec0 + 40 * i
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, o + 8)
        out.append((name, va, vsize, raw, rsize))
    return pe, out


def rva_to_off(secs, rva):
    for name, va, vsize, raw, rsize in secs:
        if va <= rva < va + max(vsize, rsize):
            return raw + (rva - va)
    raise ValueError("RVA %#x in no section" % rva)


def unpack(src, dst):
    data = bytearray(open(src, "rb").read())
    pe, secs = sections(data)
    entry = struct.unpack_from("<I", data, pe + 24 + 16)[0]
    hoff = rva_to_off(secs, entry - HEADER_SIZE)
    hdr = steam_xor(bytes(data[hoff:hoff + HEADER_SIZE]))
    sig = struct.unpack_from("<I", hdr, 4)[0]
    if sig != SIGNATURE:
        raise SystemExit("not SteamStub 3.1 x64: header signature %#x != %#x" % (sig, SIGNATURE))
    oep = struct.unpack_from("<Q", hdr, 0x20)[0]
    flags = struct.unpack_from("<I", hdr, 0x3C)[0]
    code_va = struct.unpack_from("<Q", hdr, 0x48)[0]
    key = hdr[0x58:0x78]
    iv = hdr[0x78:0x88]
    stolen = hdr[0x88:0x98]
    print("SteamStub 3.1 x64: oep=%#x flags=%#x code_va=%#x" % (oep, flags, code_va))
    if flags & FLAG_NO_ENCRYPTION:
        print("code section is not encrypted; only the entry point is restored")
    else:
        sec = [s for s in secs if s[1] <= code_va < s[1] + max(s[2], s[4])][0]
        name, va, vsize, raw, rsize = sec
        ecb = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        real_iv = ecb.update(iv) + ecb.finalize()
        blob = stolen + bytes(data[raw:raw + rsize])
        blob = blob[:len(blob) - len(blob) % 16]
        cbc = Cipher(algorithms.AES(key), modes.CBC(real_iv)).decryptor()
        plain = cbc.update(blob) + cbc.finalize()
        data[raw:raw + rsize] = plain[:rsize]
        print("decrypted %s: %#x bytes at raw %#x" % (name, rsize, raw))
    struct.pack_into("<I", data, pe + 24 + 16, oep)
    open(dst, "wb").write(data)
    print("wrote", dst)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    unpack(sys.argv[1], sys.argv[2])
