#!/usr/bin/env python3
"""SHARC 48-bit (ISA) decode corpus.

    gen_corpus.py <out-prefix> [random-count] [seed]

Writes <out-prefix>.gh (6 bytes per word, big-endian: what the Ghidra module reads at a 48-bit
code address) and <out-prefix>.mame (8 bytes per word, little-endian: what MAME's unidasm
-arch sharc reads), same words in the same order:

  1. every value of bits 47..32 (the instruction type and opcode selectors) with two random
     tails, and for the branch types 8a, 9a and 11a every value of bits 47..32 with each of the
     eight J/E/CI (or J/E/LR) settings, and types 9a/9b with bits 31..24 in full (these first
     words, counted in <out-prefix>.nvisa, are what the VISA corpora are built from);
  2. the compute field (bits 22..0): every value of bits 22..12 (multifunction bit, unit,
     opcode) with random register fields, under the compute-only instruction (type 2, IF TRUE,
     eight tails) and, two tails each, type 1 (compute + dual move), type 9a (compute after
     the branch and ELSE compute) and type 11a (the same);
  3. every value of bits 47..32 with an empty compute field;
  4. random words.
"""
import random
import struct
import sys

out = sys.argv[1]
nrand = int(sys.argv[2]) if len(sys.argv) > 2 else 40000
rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
words = []
for hi in range(1 << 16):
    for _ in range(2):
        words.append((hi << 32) | rng.getrandbits(32))
# branch types 8a/9a/11a: every value of bits 47..32 with every J/E/CI (LR) combination (bits 26..24)
for top in range(0x06, 0x0C):
    for mid in range(256):
        for f in range(8):
            words.append((((top << 8) | mid) << 32) | (rng.getrandbits(5) << 27) | (f << 24) | rng.getrandbits(24))
# types 9a/9b: bits 31..24 (PMI/PMM or the 6-bit offset, J, E, CI) in full for every B/A,
# for conditions EQ and TRUE and both values of bit 32
for top in (0x08, 0x09):
    for b39 in range(2):
        for a38 in range(2):
            for cond in (0, 31):
                for b32 in range(2):
                    for low in range(256):
                        hi16 = (top << 8) | (b39 << 7) | (a38 << 6) | (cond << 1) | b32
                        words.append((hi16 << 32) | (low << 24) | rng.getrandbits(24))
n_visa = len(words)
# carriers of a full compute field: type 2 (IF TRUE), type 1 (dual move), type 9a indirect
# jump with E = 0 / 1 (compute after the branch / ELSE compute), type 11a RTS with E = 0 / 1,
# the return idiom JUMP (M14, I12) (DB)
carriers = [lambda: 0x013E00000000,
            lambda: (0b001 << 45) | (rng.getrandbits(22) << 23),
            lambda: (0x08 << 40) | (31 << 33) | (rng.getrandbits(6) << 27) | (rng.getrandbits(1) << 26),
            lambda: (0x08 << 40) | (31 << 33) | (rng.getrandbits(6) << 27) | (1 << 25),
            lambda: (0x0A << 40) | (31 << 33) | (rng.getrandbits(1) << 26),
            lambda: (0x0A << 40) | (31 << 33) | (1 << 25),
            # the C run time's return JUMP (M14, I12) (DB), conditional or not, E = 0 / 1
            lambda: ((0x08 << 40) | (rng.choice((0, 31)) << 33) | (1 << 32) | (6 << 27) | (1 << 26) |
                     (rng.getrandbits(1) << 25))]
for top in range(1 << 11):
    for k, carrier in enumerate(carriers):
        for _ in range(8 if k == 0 else 2):
            words.append(carrier() | (top << 12) | rng.getrandbits(12))
# every value of bits 47..32 with an empty compute field (bits 22..0 = 0)
for hi in range(1 << 16):
    words.append((hi << 32) | (rng.getrandbits(9) << 23))
for _ in range(nrand):
    words.append(rng.getrandbits(48))
with open(out + ".gh", "wb") as g, open(out + ".mame", "wb") as m:
    for w in words:
        g.write(w.to_bytes(6, "big"))
        m.write(struct.pack("<Q", w))
with open(out + ".nvisa", "w") as f:
    f.write(f"{n_visa}\n")
print(f"{len(words)} words, VISA corpus from the first {n_visa}")
