#!/usr/bin/env python3
"""VISA consistency check (no reference disassembler knows VISA).

    visa_check.py <isa-dump> <isa-nocompute-dump> <v48-dump> <v32-dump> <isa-corpus.gh> [<v2b-dump> <v2bisa-dump>]

The Programming Reference (ch. 9 preamble, ch. 10) defines VISA as the ISA opcodes placed in
short-word memory, plus sub-forms: a 32-bit form is the 48-bit form with the compute field
removed and bits 22..16 = 0111111.  So, for each ISA corpus word w (whose ISA decode is
checked against MAME separately):
  * VISA decode of w, when 48 bits long, must equal the ISA decode of w (PC-relative targets
    differ in units: 48-bit words in ISA, short words in VISA, so targets are masked);
  * VISA decode of the 32-bit form of w, when 32 bits long, must equal the ISA decode of w
    with its compute field cleared;
  * a type 2b word (compute in bits 38..16) must decode to the same compute as type 2a IF TRUE.
Every other outcome is counted by class; the run fails on a text mismatch.
"""
import re
import sys
from collections import Counter


def load(f):
    return [l.rstrip("\n").split(" ", 2) + [""] for l in open(f)]


def norm(t, rel):
    t = re.sub(r"[\s,]+", " ", t).strip()
    if rel:
        t = re.sub(r"\(0x[0-9a-f]+\)", "(T)", t)
    t = re.sub(r"\(PC, ?-?0x[0-9a-f]+\)", "(T)", t) if rel else t
    return t


def main():
    isa, isa0, v48, v32 = (load(f) for f in sys.argv[1:5])
    data = open(sys.argv[5], "rb").read()
    n = len(isa0)
    c = Counter()
    bad = []
    for i in range(n):
        w = int.from_bytes(data[6 * i:6 * i + 6], "big")
        rel = (w >> 40) in (0x07, 0x0C, 0x0D, 0x0E, 0x18) or (w >> 45) == 0b111 or (w >> 40) in (0x09, 0x0B)
        if v48[i][1] == "6":
            if isa[i][1] == "6":
                if norm(isa[i][2], rel) == norm(v48[i][2], rel):
                    c["v48 = isa"] += 1
                else:
                    bad.append(("v48", w, isa[i][2], v48[i][2]))
            else:
                c["v48 valid, isa invalid"] += 1
        else:
            c[f"v48 length {v48[i][1]} (isa {'valid' if isa[i][1] == '6' else 'invalid'})"] += 1
        if v32[i][1] == "4" and (w >> 39) == 0x03:
            c["v32 is a type 2b compute (bits 38..16)"] += 1
        elif v32[i][1] == "4" and ((w >> 44) == 0x9 or (w >> 40) == 0x0F):
            c["v32 is a type 16b/17b immediate (not a compute-removed form)"] += 1
        elif v32[i][1] == "4":
            if isa0[i][1] == "6" and norm(isa0[i][2], rel) == norm(v32[i][2], rel):
                c["v32 = isa without compute"] += 1
            else:
                bad.append(("v32", w, isa0[i][2] if isa0[i][1] == "6" else "BAD", v32[i][2]))
        else:
            c[f"v32 length {v32[i][1]}"] += 1
    if len(sys.argv) > 7:
        b2, b2i = load(sys.argv[6]), load(sys.argv[7])
        for i in range(len(b2)):
            ok2 = b2[i][1] == "4" and b2i[i][1] == "6" and norm(b2[i][2], False).split(" ", 1)[-1] == \
                norm(b2i[i][2], False).replace("IF TRUE ", "").split(" ", 1)[-1]
            both_bad = b2[i][1] == "0" and b2i[i][1] == "0"
            if ok2:
                c["type 2b = type 2a IF TRUE"] += 1
            elif both_bad:
                c["type 2b and 2a both invalid"] += 1
            else:
                bad.append(("v2b", i, b2i[i][2], b2[i][2]))
    for k, v in sorted(c.items()):
        print(f"  {k}: {v}")
    print(f"VISA consistency: {n} words, {len(bad)} mismatches")
    for kind, w, a, b in bad[:30]:
        print(f"  {kind} {w:012x}\n     isa:  {a}\n     visa: {b}")
    sys.exit(1 if bad else 0)


main()
