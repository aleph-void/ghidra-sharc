#!/usr/bin/env python3
"""Independent check of the single-function multiplier opcodes (PGR Tables 12-5..12-9).

    mult_check.py <ghidra-dump> <corpus.gh>

The corpus words whose bits 47..23 are type 2 "IF TRUE" (0x013E...) carry a full compute field;
for those with CU = 01 (bits 22..20 = 001) this script decodes the opcode from its own
transcription of the manual tables and compares the result with the module's text (MAME omits
most modifiers, so the decode differential cannot check them).  Exits non-zero on a mismatch.
"""
import re
import sys


def expect(op, n, x, y):
    def mod1():
        ys, xs, f, r = (op >> 5) & 1, (op >> 4) & 1, (op >> 3) & 1, op & 1
        if r and not f:
            return None                                  # Table 12-7 lists no (..IR)
        return "(" + "SU"[1 - xs] + "SU"[1 - ys] + "IF"[f] + ("R" if r else "") + ")"
    hi, d = op >> 6, (op >> 1) & 3
    if op == 0x30:
        return f"F{n} = F{x} * F{y}"
    if hi == 1:
        m = mod1()
        lhs = {0: f"R{n}", 2: "MRF", 3: "MRB"}.get(d)
        return m and lhs and f"{lhs} = R{x} * R{y} {m}"
    if hi in (2, 3):
        m = mod1()
        acc = "MRB" if d & 1 else "MRF"
        lhs = f"R{n}" if d < 2 else acc
        return m and f"{lhs} = {acc} {'+-'[hi - 2]} R{x} * R{y} {m}"
    if op >> 4 == 0:                                     # 0000 fddx: SAT, mod2
        src = "MRB" if d & 1 else "MRF"
        lhs = f"R{n}" if d < 2 else src
        return f"{lhs} = SAT {src} ({'US'[op & 1]}{'IF'[(op >> 3) & 1]})"
    if op >> 4 == 1:
        if op == 0x14:
            return "MRF = 0"
        if op == 0x16:
            return "MRB = 0"
        if op & 8:                                       # 0001 1ddx: RND, mod3 (F only)
            src = "MRB" if d & 1 else "MRF"
            lhs = f"R{n}" if d < 2 else src
            return f"{lhs} = RND {src} ({'US'[op & 1]}F)"
    return None


def main():
    lines = [l.rstrip("\n").split(" ", 2) for l in open(sys.argv[1])]
    data = open(sys.argv[2], "rb").read()
    checked = bad = 0
    for i, g in enumerate(lines):
        w = int.from_bytes(data[6 * i:6 * i + 6], "big")
        if w >> 23 != 0x013E00000000 >> 23 or (w >> 20) & 7 != 1:
            continue
        op, n, x, y = (w >> 12) & 0xFF, (w >> 8) & 15, (w >> 4) & 15, w & 15
        want = expect(op, n, x, y)
        got = None if g[1] == "0" else re.sub(r"^\w+ ", "", g[2]).strip()
        checked += 1
        if want != got:
            bad += 1
            if bad <= 20:
                print(f"  {w:012x} op {op:02x}: manual {want!r}, module {got!r}")
    print(f"multiplier opcode table check: {checked} words, {bad} mismatches")
    sys.exit(1 if bad or not checked else 0)


main()
