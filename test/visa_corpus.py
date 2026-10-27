#!/usr/bin/env python3
"""Build the VISA consistency corpus from the ISA corpus (see visa_check.py).

    visa_corpus.py <isa-corpus.gh> <out-prefix>

<out>.isa : 6-byte words  w with the compute field (bits 22..0) cleared   (decoded as ISA)
<out>.v48 : 6-byte words  w unchanged                                     (decoded as VISA)
<out>.v32 : 6-byte slots  bits 47..16 of w with bits 22..16 = 0111111, then 2 filler bytes
<out>.v2b : 6-byte slots  type 2b (000 00001 1, compute in bits 38..16): every value of compute
            bits 22..12 with four random register tails, then 2 filler bytes
<out>.v2bisa : the same computes in ISA type 2a, IF TRUE (6-byte words)
"""
import random
import sys

data = open(sys.argv[1], "rb").read()
out = sys.argv[2]
n = len(data) // 6
with open(out + ".isa", "wb") as fi, open(out + ".v48", "wb") as f48, open(out + ".v32", "wb") as f32:
    for i in range(n):
        w = int.from_bytes(data[6 * i:6 * i + 6], "big")
        fi.write((w & ~0x7FFFFF).to_bytes(6, "big"))
        f48.write(w.to_bytes(6, "big"))
        v = ((w >> 16) & ~0x7F) | 0x3F
        f32.write(v.to_bytes(4, "big") + b"\xff\xff")
rng = random.Random(5)
with open(out + ".v2b", "wb") as fb, open(out + ".v2bisa", "wb") as fi:
    fb.write((0x03 << 23).to_bytes(4, "big") + b"\xff\xff")      # empty compute
    fi.write((0x013E00000000).to_bytes(6, "big"))
    for top in range(1 << 11):
        for _ in range(4):
            comp = (top << 12) | rng.getrandbits(12)
            fb.write((((0x03 << 23) | comp) << 0).to_bytes(4, "big") + b"\xff\xff")
            fi.write((0x013E00000000 | comp).to_bytes(6, "big"))
