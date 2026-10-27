#!/usr/bin/env python3
"""SHARC p-code tests: hand-encoded programs with hand-computed results.

    emu_tests.py <outdir>

Writes <outdir>/emu.bin (loaded at short word 0x100000), <outdir>/tests.txt (EmuCheck.java
format) and <outdir>/ctx.txt (the EmuCheck context arguments: the ISA programs need visa = 0).
The encoders below follow the opcode figures of the SHARC Processor Programming Reference
(rev 2.4, ch. 10 and 12); every expected value was worked out by hand from the instruction
descriptions in ch. 11, not taken from the module.  ISA instruction k of a program at short
word s has the 48-bit address (s + 0x80000) / 3 (block 0, PGR "Model" in README.md).
"""
import struct
import sys
from pathlib import Path

BASE = 0x100000
# ---------------------------------------------------------------- encoders (48-bit ISA)
TRUE = 31
UREG = {f"R{i}": i for i in range(16)}
UREG.update({f"I{i}": 0x10 + i for i in range(16)})
UREG.update({f"M{i}": 0x20 + i for i in range(16)})
UREG.update({f"L{i}": 0x30 + i for i in range(16)})
UREG.update({f"B{i}": 0x40 + i for i in range(16)})
UREG.update({"PCSTK": 0x64, "PCSTKP": 0x65, "LCNTR": 0x68, "CURLCNTR": 0x67, "MODE1": 0x72,
             "ASTATX": 0x76, "STKYX": 0x78})
UREG.update({f"S{i}": 0x50 + i for i in range(16)})
UREG.update({"PX": 0x6B, "PX1": 0x6C, "PX2": 0x6D, "USTAT1": 0x70, "USTAT2": 0x71, "ASTATY": 0x77, "STKYY": 0x79})


def alu(op, n, x, y=0):
    return (op << 12) | (n << 8) | (x << 4) | y


def mul(op, n, x, y=0):
    return (1 << 20) | (op << 12) | (n << 8) | (x << 4) | y


def shf(op, n, x, y=0):
    return (2 << 20) | (op << 12) | (n << 8) | (x << 4) | y


def mrmove(sel, n, to_mr):
    """MR data move (PGR 12-9): 100000 D OPCODE DREG."""
    return (0x20 << 17) | (to_mr << 16) | (sel << 12) | (n << 8)


def comp(c, cond=TRUE):
    """Type 2a: IF cond compute."""
    return (0x01 << 40) | (cond << 33) | c


def ureg_imm(r, v):
    """Type 17a: ureg = data32."""
    return (0x0F << 40) | (UREG[r] << 32) | (v & 0xFFFFFFFF)


def dag(r, i, m, d, u=1, g=0, lw=0, c=0, cond=TRUE):
    """Type 3a: ureg <-> DM/PM(Ia, Mb); u = 1 post-modify (Ia, Mb), d = 1 write to memory."""
    return ((0b010 << 45) | (u << 44) | ((i & 7) << 41) | ((m & 7) << 38) | (cond << 33) | (g << 32) |
            (d << 31) | (lw << 30) | (UREG[r] << 23) | c)


def umov(dst, src, cond=TRUE, c=0):
    """Type 5a: [IF cond] [compute,] ureg = ureg (PGR 10-9: 01110 SRC(4..2) COND SRC(1..0) DEST)."""
    s = UREG[src]
    return (0xE << 43) | ((s >> 2) << 38) | (cond << 33) | ((s & 3) << 31) | (UREG[dst] << 23) | c


def swap(rn, sn, cond=TRUE, c=0):
    """Type 5b: [IF cond] [compute,] Rn <-> Sn (01111 CDREG(41..38) COND ... DREG(26..23))."""
    return (0xF << 43) | (sn << 38) | (cond << 33) | (rn << 23) | c


def jrel6(off, cond=TRUE, c=0, e=0):
    """Type 9a: IF cond JUMP (PC, off) [, [ELSE] compute] (0001 00 1 0 0 COND RELADDR6 J E CI)."""
    return (0x04 << 41) | (1 << 40) | (cond << 33) | ((off & 0x3F) << 27) | (e << 25) | c


def absmem(r, addr, d, lw=0):
    """Type 14a: ureg <-> DM(addr32)."""
    return (0b000100 << 42) | (d << 40) | (lw << 39) | (UREG[r] << 32) | addr


def branch(target48, call=0, db=0, cond=TRUE):
    """Type 8a direct jump/call to a 48-bit address."""
    return (0x06 << 40) | (call << 39) | (cond << 33) | (db << 26) | target48


def rts(db=0):
    return (0x0A << 40) | (TRUE << 33) | (db << 26)


def bitop(op, sreg, data):
    """Type 18a BIT op sreg data32; op 0 SET, 1 CLR, 2 TGL, 4 TST, 5 XOR; sreg 0x70+n."""
    return (0x14 << 40) | (op << 37) | ((sreg - 0x70) << 32) | data


def lcntr_do(count, rel):
    """Type 12a: LCNTR = count, DO (PC, rel) UNTIL LCE."""
    return (0x0C << 40) | (count << 24) | (rel & 0xFFFFFF)


def do_until(term, rel):
    """Type 13a: DO (PC, rel) UNTIL term."""
    return (0x0E << 40) | (term << 33) | (rel & 0xFFFFFF)


def stack(v):
    """Type 20a: bits LPU LPO SPU SPO PPU PPO FC."""
    return (0x17 << 40) | (v << 33)


def shimm(op8, n, x, data8=0, bit6=None, len6=None):
    """Type 6a without data move (000 00010 COND ... SHIFTIM): shift by data8, or bit6:len6."""
    if bit6 is not None:
        data8 = ((len6 & 3) << 6) | bit6
        dataex = len6 >> 2
    else:
        dataex = 0
    return (0x02 << 40) | (TRUE << 33) | (dataex << 27) | ((op8 >> 2) << 16) | ((data8 & 0xFF) << 8) | (n << 4) | x


def modify(i, m, cond=TRUE):
    """Type 7a: MODIFY(Ia, Mb) (Id = Is)."""
    return (0x04 << 40) | ((i >> 3) << 38) | (cond << 33) | ((i & 7) << 30) | ((m & 7) << 27)


def f32(x):
    return struct.unpack(">I", struct.pack(">f", x))[0]


# ---------------------------------------------------------------- programs
# Each test: (name, [ISA words], init items, expect items).  Registers are 32-bit.
T = []


def t(name, words, init, expect):
    T.append((name, words, init, expect))


A = 0x76  # ASTATX ureg code (for reading flags into R registers)

# ALU, fixed point
t("add", [ureg_imm("R0", 5), ureg_imm("R1", 7), comp(alu(0x01, 2, 0, 1))], "",
  "R2=c,ASTATX=0")
t("add_overflow", [ureg_imm("R0", 0x7FFFFFFF), ureg_imm("R1", 1), comp(alu(0x01, 2, 0, 1))], "",
  "R2=80000000,ASTATX=6,STKYX=4")                      # AV (bit 1) + AN (bit 2); AOS sticky
t("add_saturate", [bitop(0, 0x72, 1 << 13), ureg_imm("R0", 0x7FFFFFFF), ureg_imm("R1", 1),
                   comp(alu(0x01, 2, 0, 1))], "", "R2=7fffffff,ASTATX=2")   # AV only
t("sub_borrow", [ureg_imm("R0", 5), ureg_imm("R1", 7), comp(alu(0x02, 2, 0, 1)), comp(alu(0x02, 3, 1, 0))],
  "", "R2=fffffffe,R3=2,ASTATX=8")                     # 7 - 5: AC (bit 3) set, last result positive
t("add_carry_in", [ureg_imm("R0", 0xFFFFFFFF), ureg_imm("R1", 1), comp(alu(0x01, 2, 0, 1)),
                   comp(alu(0x05, 3, 1, 1))], "", "R2=0,R3=3")   # 1 + 1 + carry(1)
t("compare_cacc", [ureg_imm("R0", 3), ureg_imm("R1", 9), comp(alu(0x0A, 0, 0, 1)), comp(alu(0x0A, 0, 1, 0))],
  "", "ASTATX=80000000")                               # CACC: 0 (3 < 9) then 1 (9 > 3) shifted in at bit 31
t("abs_min", [ureg_imm("R0", 0x80000000), comp(alu(0x30, 1, 0))], "", "R1=80000000,ASTATX=16,STKYX=4")
#   ABS of 0x80000000: AV (2) + AN (4) + AS (0x10)
t("min_max_clip", [ureg_imm("R0", 0xFFFFFFF0), ureg_imm("R1", 5), comp(alu(0x61, 2, 0, 1)),
                   comp(alu(0x62, 3, 0, 1)), comp(alu(0x63, 4, 0, 1))], "", "R2=fffffff0,R3=5,R4=fffffffb")
t("avg_round", [ureg_imm("R0", 4), ureg_imm("R1", 7), comp(alu(0x09, 2, 0, 1))], "", "R2=6")   # 11/2 = 5.5 -> 6 (even)
# ALU, floating point
t("fadd", [ureg_imm("R0", f32(1.5)), ureg_imm("R1", f32(2.25)), comp(alu(0x81, 2, 0, 1))], "",
  f"R2={f32(3.75):x},ASTATX=400")                      # AF (bit 10)
t("float_denormal", [ureg_imm("R0", 0x00400000), ureg_imm("R1", 0x00400000), comp(alu(0x81, 2, 0, 1)),
                     ureg_imm("R7", f32(2.0)), comp(mul(0x30, 6, 0, 7)),
                     ureg_imm("R4", f32(1.5e-38)), ureg_imm("R5", f32(1.4e-38)), comp(alu(0x82, 3, 4, 5))], "",
  "R2=0,R6=0,R3=0,ASTATX=401,STKYX=1")
#   denormal inputs are flushed to zero: 0x00400000 + 0x00400000 = 0 (not 0x00800000), and
#   F0 * 2.0 = 0; 1.5e-38 - 1.4e-38 = 1e-39 is a denormal result: +0, AZ + AF, AUS sticky
t("fix_round_even", [ureg_imm("R0", f32(2.5)), comp(alu(0xC9, 1, 0)), ureg_imm("R0", f32(3.5)),
                     comp(alu(0xC9, 2, 0)), ureg_imm("R0", f32(-2.5)), comp(alu(0xCD, 3, 0))], "",
  "R1=2,R2=4,R3=fffffffe")                              # FIX to nearest even; TRUNC toward zero
t("fix_trunc_mode", [bitop(0, 0x72, 1 << 15), ureg_imm("R0", f32(-2.5)), comp(alu(0xC9, 1, 0))], "",
  "R1=fffffffd")                                       # MODE1 TRUNC: FIX toward minus infinity
t("float_scalb", [ureg_imm("R0", 0xFFFFFFFD), comp(alu(0xCA, 1, 0)), ureg_imm("R2", 3),
                  comp(alu(0xBD, 3, 1, 2))], "", f"R1={f32(-3.0):x},R3={f32(-24.0):x}")
t("fix_overflow", [ureg_imm("R0", f32(3e9)), comp(alu(0xC9, 1, 0)), bitop(0, 0x72, 1 << 13),
                   comp(alu(0xC9, 2, 0))], "", "R1=ffffffff,R2=7fffffff")
t("mant_logb", [ureg_imm("R0", f32(-6.0)), comp(alu(0xAD, 1, 0)), comp(alu(0xC1, 2, 0))], "",
  "R1=c0000000,R2=2")                                  # 6 = 1.5 * 2^2: mantissa 1.1b left-justified
# multiplier
t("mul_ssi", [ureg_imm("R0", 0xFFFFFFFD), ureg_imm("R1", 7), comp(mul(0x70, 2, 0, 1))], "",
  "R2=ffffffeb,ASTATX=40")                             # -21; MN (bit 6)
t("mul_ssf", [ureg_imm("R0", 0x40000000), ureg_imm("R1", 0x40000000), comp(mul(0x78, 2, 0, 1))], "",
  "R2=20000000")                                       # 0.5 * 0.5 = 0.25
t("mac_mrf", [comp(mul(0x14, 0, 0)), ureg_imm("R0", 0x40000000), ureg_imm("R1", 0x40000000),
              comp(mul(0xBC, 0, 0, 1)), comp(mul(0xBC, 0, 0, 1)), comp(mrmove(1, 2, 0))], "",
  "R2=40000000,MRF=4000000000000000,MR2F=0")
t("mrf_sat", [ureg_imm("R3", 0x7FFFFFFF), comp(mrmove(1, 3, 1)), ureg_imm("R3", 0xFFFFFFFF), comp(mrmove(0, 3, 1)),
              ureg_imm("R0", 0x40000000), ureg_imm("R1", 0x40000000), comp(mul(0xBC, 0, 0, 1)),
              comp(mul(0x09, 2, 0))], "", "R2=7fffffff,MRF=9fffffffffffffff")
t("mul_round", [ureg_imm("R0", 0x00008000), ureg_imm("R1", 0x00008000), comp(mul(0x79, 2, 0, 1)),
                ureg_imm("R0", 0x00018000), comp(mul(0x79, 3, 0, 1))], "", "R2=0,R3=2")
#   (SSFR) 0x8000*0x8000*2 = 2^31: exactly half an LSB of the 1.31 result -> rounds to even 0;
#   0x18000*0x8000*2 = 3*2^31: 1.5 LSB -> 2
# shifter
t("lshift", [ureg_imm("R0", 0x80000001), ureg_imm("R1", 1), comp(shf(0x00, 2, 0, 1)),
             ureg_imm("R1", 0xFFFFFFFF), comp(shf(0x00, 3, 0, 1))], "", "R2=2,R3=40000000")
t("ashift_sv", [ureg_imm("R0", 0x80000000), shimm(0x04, 1, 0, data8=0xFC), shimm(0x04, 2, 0, data8=1)], "",
  "R1=f8000000,R2=0,ASTATX=1800")                      # last shift: SZ (bit 12) + SV (bit 11)
t("fext_fdep", [ureg_imm("R0", 0x12345678), shimm(0x40, 1, 0, bit6=4, len6=8),
                shimm(0x44, 2, 0, bit6=8, len6=8), shimm(0x48, 3, 0, bit6=0, len6=8)], "",
  "R1=67,R2=7800,R3=78")
t("fext_reg_se", [ureg_imm("R0", 0x0000F000), ureg_imm("R1", (8 << 6) | 8), comp(shf(0x48, 2, 0, 1))], "",
  "R2=fffffff0")                                       # field 0xF0 at bit 8, sign-extended
t("exp_leftz", [ureg_imm("R0", 0x00001000), comp(shf(0x80, 1, 0)), comp(shf(0x88, 2, 0)),
                ureg_imm("R3", 0xFFFF0000), comp(shf(0x8C, 4, 3))], "", "R1=ffffffee,R2=13,R4=10")
t("rot_btst", [ureg_imm("R0", 0x80000001), ureg_imm("R1", 4), comp(shf(0x08, 2, 0, 1)),
               ureg_imm("R1", 31), comp(shf(0xCC, 0, 0, 1))], "", "R2=18,ASTATX=0")   # bit 31 set: SZ = 0
t("fpack_funpack", [ureg_imm("R0", f32(1.0)), comp(shf(0x90, 1, 0)), comp(shf(0x94, 2, 1))], "",
  f"R1=3800,R2={f32(1.0):x}")
t("bit_fifo", [ureg_imm("R0", 0xAB), shimm(0x7C, 0, 0, data8=0), shimm(0x74, 0, 0, data8=8),
               shimm(0x50, 1, 0, data8=4), comp(shf(0x70, 2, 0))], "", "R1=a,R2=4")
# data address generators
t("dag_post_modify", [ureg_imm("I0", 0x1000), ureg_imm("M0", 1), ureg_imm("R0", 0x11), dag("R0", 0, 0, 1),
                      ureg_imm("R1", 0x22), dag("R1", 0, 0, 1), dag("R2", 0, 0, 0, u=0)], "",
  "d4:1000=11,d4:1001=22,I0=1002,R2=0")                 # pre-modify DM(M0, I0) reads 0x1003 (zero)
t("dag_circular", [bitop(0, 0x72, 1 << 24), ureg_imm("B0", 0x2000), ureg_imm("L0", 3), ureg_imm("M0", 1),
                   ureg_imm("R0", 7), dag("R0", 0, 0, 1), dag("R0", 0, 0, 1), dag("R0", 0, 0, 1)], "",
  "I0=2000,d4:2002=7")                                  # B0 load sets I0; third post-modify wraps
t("modify_wrap", [ureg_imm("B1", 0x40000), ureg_imm("L1", 0x10000), ureg_imm("I1", 0x4FFFF), ureg_imm("M1", 2),
                  modify(1, 1)], "", "I1=40001")         # PGR 6-12 example (wraps without CBUFEN)
t("lw_store", [ureg_imm("R2", 0xAA), ureg_imm("R3", 0xBB), absmem("R2", 0x3000, 1, lw=1),
               absmem("R15", 0x3001, 0, lw=1)], "", "d4:3000=aa,d4:3001=bb,R15=aa,R14=bb")
#   R15 = DM(0x3001) (LW): even word 0x3000 -> R15, odd word 0x3001 -> R14 (PGR Listing 6-1)
# flow
t("call_rts", ["CALL4", ureg_imm("R6", 2), "JUMP6", ureg_imm("R9", 9), ureg_imm("R5", 1), rts()], "",
  "R5=1,R6=2,R9=0,PCSTKP=0")
t("call_db", ["CALLDB5", ureg_imm("R1", 1), ureg_imm("R2", 2), "JUMP7", ureg_imm("R9", 9), ureg_imm("R5", 5),
              rts()], "", "R1=1,R2=2,R5=5,R9=0,PCSTKP=0")   # returns after the two delay slots
t("do_lce", [ureg_imm("R0", 0), ureg_imm("R1", 1), lcntr_do(4, 1), comp(alu(0x01, 0, 0, 1))], "",
  "R0=4,CURLCNTR=0,PCSTKP=0")
t("do_until_eq", [ureg_imm("R0", 3), ureg_imm("R1", 1), do_until(0, 1), comp(alu(0x02, 0, 0, 1))], "",
  "R0=0")                                              # loop until EQ (R0 reaches 0)
t("cond_skip", [ureg_imm("R0", 1), comp(alu(0x21, 0, 0)), ureg_imm("R1", 5), comp(alu(0x01, 1, 1, 1), cond=0),
                comp(alu(0x01, 1, 1, 1), cond=16)], "", "R1=a")   # IF EQ skipped, IF NE done
t("push_pop_sts", [ureg_imm("R0", 0), comp(alu(0x21, 0, 0)), stack(0x10), ureg_imm("R1", 5),
                   comp(alu(0x21, 1, 1)), stack(0x08)], "", "ASTATX=1")   # AZ from PASS 0 restored
t("XFAIL_wrong_add", [ureg_imm("R0", 5), ureg_imm("R1", 7), comp(alu(0x01, 2, 0, 1))], "", "R2=d")


# ---------------------------------------------------------------- SIMD programs (context simd = 1)
# PGR "SIMD Mode" (3-40), "Conditional Instruction Execution in SIMD Mode" (4-94, Tables 4-39..4-50)
# and the "SIMD Mode" paragraphs of ch. 9.  In SIMD an immediate load of a data register also
# loads its complement, so PEx/PEy data start out different through the init items.
ST = []


def st(name, words, init, expect):
    ST.append((name, words, init, expect))


EQ, NE = 0, 16
st("simd_alu_flags", [comp(alu(0x02, 2, 0, 1))], "R0=5,R1=5,S0=1,S1=2",
   "R2=0,S2=ffffffff,ASTATX=9,ASTATY=4")
#   R2 = R0 - R1 = 5 + ~5 + 1 = 0 with carry: ASTATx = AZ (1) + AC (8);
#   S2 = S0 - S1 = 1 + ~2 + 1 = 0xffffffff, no carry: ASTATy = AN (4)
st("simd_mac_msf", [comp(mul(0xBC, 0, 0, 1)), comp(mrmove(1, 2, 0))],
   "R0=40000000,R1=40000000,S0=20000000,S1=40000000",
   "MRF=2000000000000000,MSF=1000000000000000,R2=20000000,S2=10000000,MS2F=0")
#   MRF = MRF + R0 * R1 (SSF): 0.5 * 0.5 = 0.25 -> 2^60 << 1 = 0x2000000000000000;
#   MSF = MSF + S0 * S1: 0.25 * 0.5 = 0.125 -> 0x1000000000000000; R2 = MR1F, S2 = MS1F
st("simd_cond_compute", [comp(alu(0x29, 3, 3), cond=NE), comp(alu(0x29, 1, 1), cond=EQ)],
   "ASTATX=1,R1=a,S1=14,R3=0,S3=0", "R3=0,S3=1,R1=b,S1=14,ASTATX=0,ASTATY=0")
#   AZ is set in PEx only.  IF NE R3 = R3 + 1: false in PEx (R3 stays 0), true in PEy (S3 = 1,
#   AZy = 0); IF EQ R1 = R1 + 1: true in PEx (AZx untouched so far: R1 = 0xb, AZx = 0), false in
#   PEy (S1 stays 0x14) (PGR 9-10, Table 4-39)
st("simd_branch_and", [("JUMP", 2, EQ), comp(alu(0x29, 5, 5)), ("JUMP", 4, NE), comp(alu(0x29, 6, 6))],
   "ASTATX=1", "R5=1,S5=1,R6=0,S6=0")
#   IF EQ JUMP: true in PEx only -> not taken (Table 4-48), so R5 = S5 = 1, which clears AZx and
#   AZy; IF NE JUMP: now true in both PEs -> taken, over R6 = R6 + 1
st("simd_dreg_move", [dag("R2", 0, 0, 1), ureg_imm("I0", 0x90000), dag("R3", 0, 0, 0),
                      dag("R2", 1, 0, 1)],
   "I0=90000,M0=1,I1=120000,R2=11,S2=22",
   "d4:90000=11,d4:90001=22,I0=90001,R3=11,S3=22,d4:120000=11,d4:120001=0,d4:120002=22,I1=120001")
#   DM(I0,M0) = R2: R2 -> 0x90000, S2 -> 0x90001 (normal word, +1); I0 post-modified once;
#   R3 = DM(I0,M0): R3 <- 0x90000, S3 <- 0x90001;
#   DM(I1,M0) = R2 with I1 in short-word space: S2 goes to I1 + 2 (PGR Table 6-4)
st("simd_ureg_pairs", [umov("USTAT1", "R0"), umov("PX1", "USTAT1"), umov("R1", "PX1"), umov("R7", "I3"),
                       umov("I4", "S0")],
   "R0=5,S0=6,I3=77", "USTAT1=5,USTAT2=6,PX1=5,PX2=6,R1=5,S1=6,R7=77,S7=77,I4=6")
#   USTAT1 = R0 also USTAT2 = S0; PX1 = USTAT1 also PX2 = USTAT2; R1 = PX1 also S1 = PX2
#   (complementary pairs, Table 2-4); R7 = I3 also S7 = I3 (uncomplementary source, Table 4-43);
#   I4 = S0: explicit only (uncomplementary destination, Table 4-44)
st("simd_swap_cond", [swap(3, 4, cond=EQ), swap(5, 6, cond=NE)],
   "ASTATY=1,R3=33,S4=44,R5=55,S6=66", "R3=33,S4=33,R5=66,S6=66")
#   IF EQ R3 <-> S4: EQ false in PEx (R3 not loaded), true in PEy (S4 <- R3 = 0x33) (Table 4-40);
#   IF NE R5 <-> S6: true in PEx (R5 <- S6 = 0x66), false in PEy (S6 kept)
st("simd_else", [jrel6(2, cond=EQ, c=alu(0x29, 1, 1), e=1), jrel6(2, cond=EQ, c=alu(0x29, 2, 2))],
   "ASTATX=1,R1=a,S1=14,R2=0,S2=0", "R1=a,S1=15,R2=1,S2=0")
#   IF EQ JUMP (PC, 2), ELSE R1 = R1 + 1: EQ in PEx only -> no jump; ELSE runs in PEy only
#   (S1 = 21; AZy stays 0) (Table 4-50); IF EQ JUMP (PC, 2), R2 = R2 + 1: still no jump; the
#   compute runs where EQ holds: PEx (R2 = 1), not PEy
st("simd_modify_or", [modify(0, 0, cond=EQ), dag("R2", 1, 1, 1, cond=EQ)],
   "ASTATY=1,I0=100,M0=4,I1=90010,M1=2,R2=11,S2=22",
   "I0=104,I1=90012,d4:90010=0,d4:90011=22")
#   IF EQ MODIFY(I0, M0): EQ in PEy only, the modify happens on the OR (PGR 9-27);
#   IF EQ DM(I1,M1) = R2: the explicit store (PEx) does not happen, the implicit (PEy) does,
#   the post-modify happens on the OR (Table 4-39, 4-45)
st("simd_bit_tst", [bitop(4, 0x70, 0x80000000)], "USTAT1=1,USTAT2=80000000,ASTATX=40000",
   "ASTATX=0,ASTATY=40000")
#   BIT TST USTAT1 bit 31: false for USTAT1 (BTF, bit 18 of ASTATx, cleared), true for its
#   complement USTAT2 (BTF set in ASTATy) (PGR 9-66, "Bit Test Flag in SIMD Mode")


# ---------------------------------------------------------------- VISA programs
# Parcels: ("16", v), ("32", v), ("48", v) or ("call_db", k) / ("jump", k) to parcel k
# (48-bit, absolute short-word target).  ctx entries set dslot/dslot2 at a parcel.
def v_short(op, n, x):
    """Type 2c short compute (PGR 12-12): 1100 OP Rn Rx."""
    return ("16", 0xC000 | (op << 8) | (n << 4) | x)


def v_imm16(r, v):
    """Type 17b: ureg = data16 (sign-extended)."""
    return ("32", (((0x0F << 8) | 0x80 | UREG[r]) << 16) | (v & 0xFFFF))


def v_rts():
    """Type 11c RTS, condition TRUE: 000 01010 1 J COND LR."""
    return ("16", (0x0A << 8) | 0x80 | (TRUE << 1))


VT = []
VT.append(("visa_short_call_db",
           [v_imm16("R0", 3), v_imm16("R1", 4), v_short(0, 0, 1), ("call_db", 7), v_short(0, 2, 0),
            v_imm16("R3", 9), ("jump", 9), v_imm16("R5", 1), v_rts()],
           {3: "dslot2=1"}, "", "R0=7,R2=7,R3=9,R5=1,PCSTKP=0"))
VT.append(("visa_short_ops",
           [v_imm16("R0", 0xFFF0), v_imm16("R1", 5), v_short(1, 0, 1), v_short(4, 2, 1), v_short(7, 1, 1),
            v_short(10, 3, 1), v_short(12, 0, 1)],
           {}, "", "R0=9,R1=19,R2=fffffffa,R3=41c80000"))
#   R0 = -16 - 5 = -21 (0xffffffeb); R2 = NOT 5; R1 = 5*5 = 25; F3 = FLOAT R1 = 25.0;
#   R0 = 0xffffffeb AND 0x19 = 9


def assemble_visa(sw, data):
    lines, ctx = [], []
    for name, parcels, pctx, init, expect in VT:
        start = sw
        addr = []
        for kind, v in parcels:
            addr.append(sw)
            sw += {"16": 1, "32": 2, "48": 3, "call_db": 3, "jump": 3}[kind]
        end = sw
        for k, (kind, v) in enumerate(parcels):
            if kind in ("call_db", "jump"):
                tgt = addr[v] if v < len(addr) else end
                w = branch(tgt, call=int(kind == "call_db"), db=int(kind == "call_db"))
                data += w.to_bytes(6, "big")
            else:
                data += v.to_bytes({"16": 2, "32": 4, "48": 6}[kind], "big")
        for k, c in pctx.items():
            ctx.append(f"ctx:{c}@{addr[k]:x}-{addr[k]:x}")
        lines.append(f"{name} {start:x} {end:x} {init or '-'} {expect}")
        data += (0).to_bytes(6, "big")
        sw += 3
    return lines, ctx, sw


def assemble():
    """Place the ISA programs (T, then the SIMD ones, ST) at consecutive 48-bit addresses; return
    (bytes, tests, end, start of the SIMD programs)."""
    data = bytearray()
    lines = []
    sw = BASE
    simd = None
    for k, (name, words, init, expect) in enumerate(T + ST):
        if k == len(T):
            simd = sw
        start = sw
        a48 = (start + 0x80000) // 3
        out = []
        for w in words:
            if isinstance(w, tuple):            # ("JUMP", k, cond): conditional jump to instruction k
                w = branch(a48 + w[1], cond=w[2])
            if isinstance(w, str):              # CALL<k>, CALLDB<k>, JUMP<k>: to instruction k
                kind = w.rstrip("0123456789")
                k = int(w[len(kind):])
                w = branch(a48 + k, call=int(kind.startswith("CALL")), db=int(kind == "CALLDB"))
            out.append(w)
        for w in out:
            data += (w & 0xFFFFFFFFFFFF).to_bytes(6, "big")
            sw += 3
        lines.append(f"{name} {start:x} {sw:x} {init or '-'} {expect}")
        data += (0).to_bytes(6, "big")          # a NOP after each program (the stop address)
        sw += 3
    return bytes(data), lines, sw, simd


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    data, lines, end, simd = assemble()
    data = bytearray(data)
    vlines, vctx, _ = assemble_visa(end, data)
    (out / "emu.bin").write_bytes(bytes(data))
    (out / "tests.txt").write_text("\n".join(lines + vlines) + "\n")
    (out / "ctx.txt").write_text(" ".join([f"ctx:visa=0@{BASE:x}-{end - 1:x}", f"ctx:simd=1@{simd:x}-{end - 1:x}"]
                                          + vctx) + "\n")
    print(f"{len(lines) + len(VT)} emulator tests")


main()
