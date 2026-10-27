#!/usr/bin/env python3
"""VISA 16-bit forms, checked against their 48-bit ISA equivalents (PGR ch. 10 figures).

    visa16.py gen <out-prefix>
    visa16.py check <out-prefix> <visa-dump> <isa-dump>

gen writes <out>.v16 (every 16-bit parcel, padded to a 6-byte slot with 0xffffffff) and
<out>.isa (for each parcel, the 48-bit ISA instruction the manual says it abbreviates, or a
zero word).  The 16-bit forms, transcribed from the opcode figures:
  2c  1100 OP Rn Rx                  short compute (Table "Short Compute Opcodes", 12-12)
  3c  1001 DMI DMM D 1 DREG          Dreg <-> DM(Ia, Mb)  (= type 3a, G=0, U=1 post-modify, L=0, no compute)
  11c 000 0101x 1 J COND LR          RTS/RTI (= type 11a with E=0, no compute)
  21c 000 00000 0 0 .... 1           NOP
  22c 000 00000 IDL EMU .... 1       IDLE / EMUIDLE
  25c 0001 1001 0000 0001            RFRAME
check: a parcel that is one of these forms must decode (VISA) to 16 bits with the same text as
its ISA equivalent (class word ignored); any other parcel must not decode to 16 bits.
"""
import re
import sys

ALU, MUL = 0, 1
SHORT = [(ALU, 0x01, "nnx"), (ALU, 0x02, "nnx"), (ALU, 0x21, "nx-"), (ALU, 0x0A, "-nx"),
         (ALU, 0x43, "nx-"), (ALU, 0x29, "nx-"), (ALU, 0x2A, "nx-"), (MUL, 0x70, "nnx"),
         (ALU, 0x81, "nnx"), (ALU, 0x82, "nnx"), (ALU, 0xCA, "nx-"), (ALU, 0x8A, "-nx"),
         (ALU, 0x40, "nnx"), (ALU, 0x41, "nnx"), (ALU, 0x42, "nnx"), (MUL, 0x30, "nnx")]


def equiv(p):
    """The ISA word a 16-bit parcel abbreviates, or None if it is not a 16-bit form."""
    if p >> 12 == 0xC:                                   # 2c
        cu, op, roles = SHORT[(p >> 8) & 15]
        n, x = (p >> 4) & 15, p & 15
        val = {"n": n, "x": x, "-": 0}
        comp = (cu << 20) | (op << 12) | (val[roles[0]] << 8) | (val[roles[1]] << 4) | val[roles[2]]
        return 0x013E00000000 | comp
    if p >> 12 == 0x9 and (p >> 4) & 1:                   # 3c
        dmi, dmm, d, dreg = (p >> 9) & 7, (p >> 6) & 7, (p >> 5) & 1, p & 15
        # type 3a: 010 U I M COND G D L UREG(29..23) compute; COND = TRUE (31)
        return ((0b010 << 45) | (1 << 44) | (dmi << 41) | (dmm << 38) | (31 << 33) | (d << 31) | (dreg << 23))
    if p >> 9 in (0b0000101,) and (p >> 8) & 1 == 1 and (p >> 9) & 0x7F in (0b0000101,):
        pass
    top8 = p >> 8
    if top8 in (0x0A, 0x0B) and (p >> 7) & 1:            # 11c: bits 39 = 1, 38 = J, 37..33 COND, 32 LR
        j, cond, lr = (p >> 6) & 1, (p >> 1) & 31, p & 1
        if top8 == 0x0B:
            lr = 0      # the 11c figure shows an LR bit for RTI too, but 11a RTI has none: ignored
        return (top8 << 40) | (cond << 33) | (j << 26) | (lr << 24)
    if top8 == 0x00 and p & 1:                           # 21c / 22c
        if (p >> 7) & 1:
            return 0x008000000000                        # IDLE
        if (p >> 6) & 1:
            return 0x004000000000                        # EMUIDLE
        return 0x000000000000                            # NOP
    if p == 0x1901:
        return 0x190000000000                            # RFRAME
    return None


def main():
    if sys.argv[1] == "gen":
        out = sys.argv[2]
        with open(out + ".v16", "wb") as fv, open(out + ".isa", "wb") as fi:
            for p in range(65536):
                fv.write(p.to_bytes(2, "big") + b"\xff\xff\xff\xff")
                fi.write((equiv(p) or 0).to_bytes(6, "big"))
        return
    vis = [l.rstrip("\n").split(" ", 2) + [""] for l in open(sys.argv[3])]
    isa = [l.rstrip("\n").split(" ", 2) + [""] for l in open(sys.argv[4])]
    def strip(t):
        t = re.sub(r"[\s,]+", " ", t).strip()
        return re.sub(r"^(SCOMP|COMP|MOVE) ", "", t)
    ok = bad = forms = 0
    for p in range(65536):
        e = equiv(p)
        v = vis[p]
        if e is None:
            if v[1] == "2":
                bad += 1
                print(f"  {p:04x}: not a 16-bit form in the manual, module: {v[2]}")
            continue
        forms += 1
        if v[1] != "2" or isa[p][1] != "6" or strip(v[2]) != strip(isa[p][2]):
            bad += 1
            if bad <= 30:
                print(f"  {p:04x}: module {v[1]} {v[2]!r}, ISA equivalent {isa[p][1]} {isa[p][2]!r}")
        else:
            ok += 1
    print(f"VISA 16-bit forms: {forms} parcels are 16-bit forms, {ok} agree with their ISA equivalent, {bad} mismatches")
    sys.exit(1 if bad else 0)


main()
