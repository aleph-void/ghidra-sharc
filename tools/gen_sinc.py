#!/usr/bin/env python3
# ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
"""Generate sharc214xx.sinc, the instruction tables of the ADSP-214xx SHARC (ISA + VISA).

    python3 tools/gen_sinc.py [data/languages/sharc214xx.sinc]

The encodings come from the opcode tables in sharc_isa.py.  The hand-written
sharc214xx.slaspec holds the address spaces, registers, context, macros, the DS, LoopTop
and ISA subtables and the root table; this file writes everything that is derived from the
tables: tokens and attach lists, the condition subtables, the compute subtables, the
branch-target subtables, and the `instr` subtable holding every instruction.

Tokens: i32 = instruction bits 47..16, i16 = bits 15..0, s16 = bits 47..32 (a 16-bit VISA
parcel).  A field "aH_L" is instruction bits H..L inside i32, "bH_L" inside i16 and "sH_L"
inside s16.  VISA 32-bit forms are the 48-bit forms with the compute field truncated and
bits 22..16 = 0x3f (PGR ch. 9 preamble), so both are generated from one description.

The output is deterministic.  DEBUG=1 prints a summary of the generated tables.
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sharc_isa as S                                   # noqa: E402

DEBUG = bool(os.environ.get("DEBUG"))
HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE.parent / "data" / "languages" / "sharc214xx.sinc"

UREG = list(S.UREG)
R = [f"R{i}" for i in range(16)]
F = [f"F{i}" for i in range(16)]
COND_NAMES = S.COND
TERM_NAMES = S.TERM


class Fields:
    """Allocate named bit fields on the three tokens, plus attach lists."""

    def __init__(self):
        self.defs = {"i32": {}, "i16": {}, "s16": {}}
        self.attach_vars = {}      # field -> list of register names
        self.attach_names = {}     # field -> list of display names
        self.signed = set()
        self.meta = {}             # name -> (hi, lo, tok, signed)
        self.nalias = 0

    def tok_of(self, name):
        return self.meta[name][2]

    def alias(self, name):
        """A new field over the same bits with the same attach (for repeated display)."""
        hi, lo, tok, sg = self.meta[name]
        self.nalias += 1
        n = self.f(hi, lo, tok=tok, kind=f"_d{self.nalias}", signed=sg)
        if name in self.attach_vars:
            self.attach_vars[n] = self.attach_vars[name]
        if name in self.attach_names:
            self.attach_names[n] = self.attach_names[name]
        return n

    def f(self, hi, lo, tok=None, kind="", signed=False):
        """Field for instruction bits hi..lo; tok forced for s16."""
        if tok is None:
            if lo >= 16:
                tok = "i32"
            elif hi <= 15:
                tok = "i16"
            else:
                raise ValueError(f"field {hi}..{lo} spans tokens")
        pre = {"i32": "a", "i16": "b", "s16": "s"}[tok]
        base = {"i32": 16, "i16": 0, "s16": 32}[tok]
        name = f"{pre}{hi}_{lo}{kind}" + ("s" if signed else "")
        self.defs[tok][name] = (hi - base, lo - base)
        self.meta[name] = (hi, lo, tok, signed)
        if signed:
            self.signed.add(name)
        return name

    def regs(self, hi, lo, regs, tok=None, kind=""):
        n = self.f(hi, lo, tok, kind=kind)
        if n in self.attach_vars and self.attach_vars[n] != regs:
            raise ValueError(f"field {n} attached to two register lists")
        self.attach_vars[n] = regs
        return n

    def names(self, hi, lo, names, tok=None, kind=""):
        n = self.f(hi, lo, tok, kind=kind + "N")
        self.attach_names[n] = names
        return n

    def render(self):
        out = []
        sizes = {"i32": 32, "i16": 16, "s16": 16}
        for tok, fs in self.defs.items():
            out.append(f"define token {tok} ({sizes[tok]})")
            for n, (h, l) in sorted(fs.items()):
                out.append(f"  {n} = ({l},{h}){' signed' if n in self.signed else ''}")
            out.append(";")
        # group attaches by identical lists
        for kind, table in (("variables", self.attach_vars), ("names", self.attach_names)):
            groups = {}
            for n, lst in table.items():
                groups.setdefault(tuple(lst), []).append(n)
            for lst, ns in groups.items():
                items = " ".join(f'"{x}"' if kind == "names" else x for x in lst)
                out.append(f"attach {kind} [ {' '.join(sorted(ns))} ] [ {items} ];")
        return "\n".join(out)


FL = Fields()


def disp(template, fieldmap):
    """Turn 'R{n} = R{x} + R{y}' into a SLEIGH display using fieldmap {('R','n'): field}.
    Returns (display, fields) -- repeated operands get alias fields (SLEIGH forbids repeats)."""
    parts = re.split(r"([RF])\{(\w+)\}", template)
    out, used = [], []
    i = 0
    while i < len(parts):
        lit = parts[i]
        if lit:
            out.append('"' + lit.replace('"', "") + '"')
        if i + 2 < len(parts):
            fld = fieldmap[(parts[i + 1], parts[i + 2])]
            if fld in used:
                fld = FL.alias(fld)
            used.append(fld)
            out.append(fld)
        i += 3
    return ("^".join(out) if out else ""), used


# ------------------------------------------------------------------ compute field layouts
class Layout:
    """Where compute bit k lives: '48' (i32 bits 22..16, i16 bits 15..0) or '2b' (i32 k+16)."""

    def __init__(self, name):
        self.name = name

    def fld(self, hi, lo, regs=None, names=None, kind=""):
        off = 16 if self.name == "2b" else 0
        h, l = hi + off, lo + off
        if regs is not None:
            return FL.regs(h, l, regs, kind=kind)
        if names is not None:
            return FL.names(h, l, names, kind=kind)
        return FL.f(h, l, kind=kind)

    def op8(self, value):
        """constraint text for compute bits 19..12 == value."""
        if self.name == "2b":
            return f"{self.fld(19, 12)}={value:#x}", None
        return f"{self.fld(19, 16)}={value >> 4:#x}", f"{self.fld(15, 12)}={value & 0xF:#x}"

    def pattern(self, i32c, i16c):
        """Join constraints into a pattern (i32 part ; i16 part for '48')."""
        i32c = [c for c in i32c if c]
        i16c = [c for c in i16c if c]
        if self.name == "2b":
            return " & ".join(i32c + i16c)
        left = " & ".join(i32c) if i32c else "epsilon"
        right = " & ".join(i16c) if i16c else "epsilon"
        return f"{left} ; {right}"


def reg_fields(L, tag):
    """Common compute register operands for layout L."""
    fm = {}
    for letter, regs in (("R", R), ("F", F)):
        for key, (h, l) in (("n", (11, 8)), ("x", (7, 4)), ("y", (3, 0)), ("s", (15, 12)),
                            ("m", (15, 12)), ("a", (11, 8)), ("s2", (19, 16))):
            if letter == "R":
                fm[(letter, key)] = L.fld(h, l, regs=R, kind=f"r{key}")
            else:
                fm[(letter, key)] = L.fld(h, l, names=F, kind=f"f{key}")
    # multifunction 2-bit operands
    for key, (h, l), regs in (("xm", (7, 6), R[0:4]), ("ym", (5, 4), R[4:8]),
                              ("xa", (3, 2), R[8:12]), ("ya", (1, 0), R[12:16])):
        fm[("R", key)] = L.fld(h, l, regs=regs, kind=f"r{key}")
        fm[("F", key)] = L.fld(h, l, names=[f"F{int(r[1:])}" for r in regs], kind=f"f{key}")
    return fm


def sem_vars(fm):
    """Map template placeholders to semantic register operand names (always R fields)."""
    return {k: fm[("R", k)] for k in ("n", "x", "y", "s", "m", "a", "s2", "xm", "ym", "xa", "ya")}


# p-code bodies for single-function ops, keyed by op8.  Placeholders {n} {x} {y}: the result
# and operand registers (R fields; floating-point operands are the same registers).  Every
# body computes into locals before it writes {n}, so {n} may name an operand register or a
# local (the multifunction forms write their results last).  Results and flags follow PGR
# ch. 11 (and Tables 3-2, 3-3, 3-8, 3-9); the slaspec macros hold the shared pieces.
def _fmin(cmp, zero_pick):
    return ("local t:4 = {y}; if (" + cmp + ") goto <a>; if (!(({x} f== {y}) && " + zero_pick +
            ")) goto <d>; <a> t = {x}; <d> local bad:1 = nan({x}) || nan({y}); t = t | (zext(bad) * 0xffffffff); "
            "fltinv(bad); fltres(t); {n} = t; AV = 0;")


ALU_SEM = {
    0x01: "aluadd({n}, {x}, {y}, 0:4);",
    0x02: "local ny:4 = ~{y}; aluadd({n}, {x}, ny, 1:4);",
    0x05: "local ci:4 = zext(AC); aluadd({n}, {x}, {y}, ci);",
    0x06: "local ny:4 = ~{y}; local ci:4 = zext(AC); aluadd({n}, {x}, ny, ci);",
    0x09: ("local s8:8 = sext({x}) + sext({y}); local q:8 = s8 s>> 1; "
           "q = q + zext((TRUNC == 0) && ((s8 & 1) == 1) && ((q & 1) == 1)); AC = carry({x}, {y}); "
           "local r:4 = q:4; {n} = r; fixres(r); AV = 0;"),
    0x0A: "AZ = ({x} == {y}); AN = ({x} s< {y}); AI = 0; compflags({x} s> {y}); AF = 0;",
    0x0B: "AZ = ({x} == {y}); AN = ({x} < {y}); AI = 0; compflags({x} > {y}); AF = 0;",
    0x25: "local ci:4 = zext(AC); aluadd({n}, {x}, 0:4, ci);",
    0x26: "local ci:4 = zext(AC); aluadd({n}, {x}, 0xffffffff:4, ci);",
    0x29: "aluadd({n}, {x}, 1:4, 0:4);",
    0x2A: "aluadd({n}, {x}, 0xffffffff:4, 0:4);",
    0x22: "local nx:4 = ~{x}; aluadd({n}, 0:4, nx, 1:4);",
    0x30: ("local sx:1 = {x} s< 0; local m:4 = {x} s>> 31; local r:4 = ({x} ^ m) - m; "
           "local ov:1 = ({x} == 0x80000000); r = r + zext(ov && ALUSAT) * (0x7fffffff - r); "
           "{n} = r; fixres(r); AV = ov; AC = 0; AS = sx; AOS = AOS || ov;"),
    0x21: "local r:4 = {x}; {n} = r; fixlogic(r);",
    0x40: "local r:4 = {x} & {y}; {n} = r; fixlogic(r);",
    0x41: "local r:4 = {x} | {y}; {n} = r; fixlogic(r);",
    0x42: "local r:4 = {x} ^ {y}; {n} = r; fixlogic(r);",
    0x43: "local r:4 = ~{x}; {n} = r; fixlogic(r);",
    0x61: "local t:4 = {x}; if ({x} s<= {y}) goto <d>; t = {y}; <d> {n} = t; fixlogic(t);",
    0x62: "local t:4 = {x}; if ({x} s>= {y}) goto <d>; t = {y}; <d> {n} = t; fixlogic(t);",
    0x63: ("local mx:4 = {x} s>> 31; local ax:4 = ({x} ^ mx) - mx; local my:4 = {y} s>> 31; "
           "local ay:4 = ({y} ^ my) - my; local t:4 = {x}; if (ax < ay) goto <d>; t = ay; "
           "if ({x} s>= 0) goto <d>; t = -ay; <d> {n} = t; fixlogic(t);"),
    # floating point
    0x81: "local r:4 = {x} f+ {y}; fltinv(nan({x}) || nan({y}) || nan(r)); fltnan(r); fltres(r); {n} = r; fltov(r);",
    0x82: "local r:4 = {x} f- {y}; fltinv(nan({x}) || nan({y}) || nan(r)); fltnan(r); fltres(r); {n} = r; fltov(r);",
    0x91: "local r:4 = abs({x} f+ {y}); fltinv(nan({x}) || nan({y}) || nan(r)); fltnan(r); fltres(r); {n} = r; fltov(r);",
    0x92: "local r:4 = abs({x} f- {y}); fltinv(nan({x}) || nan({y}) || nan(r)); fltnan(r); fltres(r); {n} = r; fltov(r);",
    0x89: ("local r:4 = ({x} f+ {y}) f* 0x3f000000:4; fltinv(nan({x}) || nan({y}) || nan(r)); fltnan(r); "
           "fltres(r); {n} = r; AV = 0;"),
    0x8A: ("AZ = ({x} f== {y}); AN = ({x} f< {y}); fltinv(nan({x}) || nan({y})); compflags({x} f> {y}); AF = 1;"),
    0xA2: "local r:4 = f- {x}; fltinv(nan({x})); fltnan(r); fltres(r); {n} = r; AV = 0;",
    0xB0: "local sx:1 = {x} s< 0; local r:4 = abs({x}); fltinv(nan({x})); fltnan(r); fltres(r); {n} = r; AV = 0; AS = sx;",
    0xA1: "local r:4 = {x}; fltinv(nan({x})); fltnan(r); fltres(r); {n} = r; AV = 0;",
    0xA5: "local r:4 = {x}; fltinv(nan({x})); fltnan(r); fltres(r); {n} = r; fltov(r);",
    0xBD: "local r:4 = 0; scalbf(r, {x}, {y}); fltinv(nan({x})); fltnan(r); fltres(r); {n} = r; fltov(r);",
    0xAD: ("local e:4 = ({x} >> 23) & 0xff; local sx:1 = {x} s< 0; "
           "local r:4 = ((({x} & 0x7fffff) | 0x800000) << 8) * zext(e != 0); r = r | (zext(e == 255) * 0xffffffff); "
           "fltinv(nan({x})); AV = (({x} & 0x7fffffff) == 0x7f800000); AVS = AVS || AV; {n} = r; "
           "AZ = (r == 0); AN = 0; AS = sx; AF = 1; AC = 0;"),
    0xC1: ("local e:4 = ({x} >> 23) & 0xff; local z:1 = (e == 0); local inf:1 = (({x} & 0x7fffffff) == 0x7f800000); "
           "local bad:1 = nan({x}); local r:4 = e - 127; "
           "r = r + zext(z) * ((0xff800000 + zext(ALUSAT) * 0x80800000) - r); "
           "r = r + zext(inf) * ((0x7f800000 + zext(ALUSAT) * 0x7fffff) - r); r = r | (zext(bad) * 0xffffffff); "
           "fltinv(bad); AV = z || inf; AVS = AVS || AV; {n} = r; AZ = (r == 0); AN = (r s< 0); AF = 1; AC = 0; AS = 0;"),
    0xD9: "local v:4 = 0; scalbf(v, {x}, {y}); fixconv({n}, v, 0:1);",
    0xC9: "fixconv({n}, {x}, 0:1);",
    0xDD: "local v:4 = 0; scalbf(v, {x}, {y}); fixconv({n}, v, 1:1);",
    0xCD: "fixconv({n}, {x}, 1:1);",
    0xDA: ("local fl:4 = int2float({x}); local r:4 = 0; scalbf(r, fl, {y}); fltres(r); {n} = r; fltov(r); "
           "AI = 0;"),
    0xCA: "local r:4 = int2float({x}); fltres(r); {n} = r; AV = 0; AI = 0;",
    # RECIPS / RSQRTS: the exact reciprocal (square root) instead of the 8-bit (4-bit) ROM seed,
    # whose table is not published; special values and flags as the manual gives them.
    0xC4: ("local r:4 = 0x3f800000:4 f/ {x}; local z:1 = (({x} & 0x7fffffff) == 0); fltinv(nan({x})); "
           "fltnan(r); fltres(r); {n} = r; AV = z; AVS = AVS || z;"),
    0xC5: ("local bad:1 = nan({x}) || (({x} s< 0) && (({x} & 0x7fffffff) != 0)); local z:1 = (({x} & 0x7fffffff) == 0); "
           "local mz:1 = ({x} == 0x80000000); local r:4 = 0x3f800000:4 f/ sqrt({x}); r = r | (zext(bad) * 0xffffffff); "
           "fltinv(bad); {n} = r; AZ = (r == 0); AN = mz; AV = z; AVS = AVS || z; AF = 1; AC = 0; AS = 0;"),
    0xE0: ("local bad:1 = nan({x}) || nan({y}); local r:4 = ({x} & 0x7fffffff) | ({y} & 0x80000000); "
           "r = r | (zext(bad) * 0xffffffff); fltinv(bad); fltres(r); {n} = r; AV = 0;"),
    0xE1: _fmin("{x} f< {y}", "({x} s< 0)"),
    0xE2: _fmin("{x} f> {y}", "({x} s>= 0)"),
    0xE3: ("local bad:1 = nan({x}) || nan({y}); local ax:4 = {x} & 0x7fffffff; local ay:4 = {y} & 0x7fffffff; "
           "local t:4 = {x}; if (ax f< ay) goto <d>; t = ay | ({x} & 0x80000000); <d> t = t | (zext(bad) * 0xffffffff); "
           "fltinv(bad); fltres(t); {n} = t; AV = 0;"),
}

# Denormal inputs of the floating-point operations are flushed to signed zero, and a
# denormal (post-rounded) result returns signed zero (PGR ch. 11, each floating-point ALU
# operation: "Denormal inputs are flushed to +-zero", "Post-rounded denormal returns +-zero";
# fltres flushes the result).  FLOAT/FIX/TRUNC/SCALB/LOGB/MANT read Ry as an integer.
_FLT_XY = (0x81, 0x82, 0x91, 0x92, 0x89, 0x8A, 0xE0, 0xE1, 0xE2, 0xE3)
_FLT_X = (0xA2, 0xB0, 0xA1, 0xA5, 0xBD, 0xAD, 0xC1, 0xD9, 0xC9, 0xDD, 0xCD, 0xC4, 0xC5)
for _k in _FLT_XY + _FLT_X:
    _b = ALU_SEM[_k].replace("{x}", "fx")
    _pre = "local fx:4 = {x}; ftz(fx); "
    if _k in _FLT_XY:
        _b = _b.replace("{y}", "fy")
        _pre += "local fy:4 = {y}; ftz(fy); "
    ALU_SEM[_k] = _pre + _b


# Bit-field extract/deposit (PGR ch. 11 "Shifter/Shift Immediate Computations"); {b} = bit6,
# {l} = len6, both 0..63.  Computed in 64 bits so that fields reaching past bit 31 need no
# special case; SV is set when bit6 + len6 > 32.
FIELD_SEM = {
    0x40: "local fv:8 = (zext({x}) >> {b}) & ((1 << {l}) - 1); local r:4 = fv:4;",
    0x48: ("local fv:8 = (zext({x}) >> {b}) & ((1 << {l}) - 1); local fs:8 = (fv << (64 - {l})) s>> (64 - {l}); "
           "local r:4 = fs:4;"),
    0x44: "local fv:8 = (zext({x}) & ((1 << {l}) - 1)) << {b}; local r:4 = fv:4;",
    0x4C: "local fs:8 = (sext({x}) << (64 - {l})) s>> (64 - {l}); local fv:8 = fs << {b}; local r:4 = fv:4;",
    0x64: "local fv:8 = (zext({x}) & ((1 << {l}) - 1)) << {b}; local r:4 = {n} | fv:4;",
    0x6C: "local fs:8 = (sext({x}) << (64 - {l})) s>> (64 - {l}); local fv:8 = fs << {b}; local r:4 = {n} | fv:4;",
}
for _k in list(FIELD_SEM):
    FIELD_SEM[_k] += " {n} = r; SZ = (r == 0); SV = (({b} + {l}) > 32); SS = 0;"


def shift_sem(op, n, x, cnt):
    """p-code of shifter op `op` (PGR Table 12-11) with result n, input x and count/position
    operand cnt (Ry, the immediate data8 or bitlen12/data7)."""
    if op in (0x00, 0x20, 0x04, 0x24):
        arith = op & 0x04
        right = f"{x} s>> -c" if arith else f"{x} >> -c"
        if arith:
            ov = (f"local t:4 = {x} s>> (31 - c); SV = (c s> 0) && ({x} != 0) && "
                  f"((c s>= 32) || ((t != 0) && (t != 0xffffffff)));")
        else:
            ov = f"SV = (c s> 0) && ({x} != 0) && ((c s>= 32) || (({x} >> (32 - c)) != 0));"
        res = f"{n} | sh" if op & 0x20 else "sh"
        return (f"local c:4 = {cnt}; local sh:4 = {x} << c; if (c s>= 0) goto <d>; sh = {right}; <d> {ov} "
                f"local r:4 = {res}; {n} = r; SZ = (r == 0); SS = 0;")
    if op == 0x08:
        return (f"local k:4 = {cnt} & 31; local r:4 = ({x} << k) | ({x} >> (32 - k)); {n} = r; "
                f"SZ = (r == 0); SV = 0; SS = 0;")
    if op in (0xC0, 0xC4, 0xC8):
        expr = {0xC0: f"{x} | m", 0xC4: f"{x} & ~m", 0xC8: f"{x} ^ m"}[op]
        return (f"local c:4 = {cnt}; local m:4 = 1 << c; local r:4 = {expr}; {n} = r; SZ = (r == 0); "
                f"SV = (c s> 31); SS = 0;")
    if op == 0xCC:
        return f"local c:4 = {cnt}; SZ = ((({x} >> c) & 1) == 0); SV = (c s> 31); SS = 0;"
    if op in FIELD_SEM:
        return (f"local b6:4 = {cnt} & 0x3f; local l6:4 = ({cnt} >> 6) & 0x3f; " +
                FIELD_SEM[op].format(n=n, x=x, b="b6", l="l6"))
    if op in (0x80, 0x84):
        ex = f" e = e + zext(AV) * (1 - e); SS = AV ^ ({x} s< 0);" if op == 0x84 else f" SS = ({x} s< 0);"
        return (f"local sg:4 = {x} s>> 31; local nlz:4 = lzcount({x} ^ sg); local e:4 = 1 - nlz;{ex} "
                f"{n} = e; SZ = (e == 0); SV = 0;")
    if op in (0x88, 0x8C):
        src = f"{x}" if op == 0x88 else f"~{x}"
        sz = f"({x} s< 0)" if op == 0x88 else f"({x} s>= 0)"
        return f"SZ = {sz}; local r:4 = lzcount({src}); {n} = r; SV = (r == 32); SS = 0;"
    if op == 0x90:
        return f"local r:4 = 0; fpack(r, {x}); {n} = r;"
    if op == 0x94:
        return f"local r:4 = 0; funpack(r, {x}); {n} = r; SZ = 0; SV = 0; SS = 0;"
    if op == 0x74:          # BITDEP Rx BY Ry|bitlen12
        return (f"local len:4 = {cnt} & 0x3f; local fv:8 = zext({x}) & ((1 << len) - 1); "
                f"local wp:4 = BFFWRP + len; BFF = BFF | (fv << (64 - wp)); BFFWRP = wp; SF = (wp >= 32); "
                f"SV = (len > 32) || (wp > 64); SZ = 0; SS = 0;")
    if op in (0x50, 0x58):  # Rn = BITEXT Rx|bitlen12 [(NU)]
        upd = "" if op == 0x58 else " BFF = BFF << len; BFFWRP = BFFWRP - len;"
        return (f"local len:4 = {cnt} & 0x3f; local fv:8 = BFF >> (64 - len); local r:4 = fv:4; "
                f"SV = (len > 32) || (len > BFFWRP);{upd} {n} = r; SZ = (r == 0); SF = (BFFWRP >= 32); SS = 0;")
    if op == 0x7C:          # BFFWRP = Rn|data7
        return (f"local v:4 = {cnt}; BFFWRP = v & 0x7f; SF = (BFFWRP >= 32); SV = (v > 64); SZ = 0; SS = 0;")
    if op == 0x70:          # Rn = BFFWRP
        return f"{n} = BFFWRP; SZ = 0; SV = 0; SS = 0;"
    raise ValueError(f"no shifter semantics for {op:#x}")


# ---------------------------------------------------------------- multiplier
def _mr(acc):
    return ("MRB", "MR2B") if acc == "MRB" else ("MRF", "MR2F")


def _mflags(sg, fr, h="h", l="l"):
    s1, s0 = (31, 32) if fr else (15, 16)
    neg = " || (up == 0xffffffffffffffff)" if sg else ""
    mu = (f"MU = ((({l} & 0xffffffff) != 0) && ((up == 0){neg}));" if fr else "MU = 0;")
    mv = (f"MV = (v1 != 0) && (v1 != 0xffffffffffffffff);" if sg else "MV = (v0 != 0);")
    return (f"local top:8 = (sext({h}) << 48) | ({l} >> 16); local v1:8 = top s>> {s1}; "
            f"local v0:8 = top >> {s0}; local up:8 = top s>> 16; MN = ({h} s< 0); {mv} {mu} MI = 0; MOS = MOS || MV;")


def mult_sem(op, v, out=None):
    """p-code for single-function multiplier opcode op (Table 12-5); v maps n, x, y to
    operands.  `out` names a local for an Rn result (multifunction), default {n}."""
    n, x, y = v["n"], v["x"], v["y"]
    dst_rn = out or n
    if op == 0x30:
        # denormal inputs are flushed to zero and a denormal product returns zero (PGR 11-61)
        return (f"local fx:4 = {x}; ftz(fx); local fy:4 = {y}; ftz(fy); "
                f"local r:4 = fx f* fy; local bad:1 = nan(fx) || nan(fy) || nan(r); "
                f"local un:1 = ((r & 0x7f800000) == 0) && ((fx & 0x7fffffff) != 0) && ((fy & 0x7fffffff) != 0); "
                f"ftz(r); r = r | (zext(bad) * 0xffffffff); "
                f"{dst_rn} = r; MN = (r s< 0); MV = ((r & 0x7fffffff) == 0x7f800000); "
                f"MU = un; MI = bad; "
                f"MVS = MVS || MV; MUS = MUS || MU; MIS = MIS || MI;")
    hi = op >> 6
    if hi == 0:
        if op in (0x14, 0x16):
            acc, acc2 = _mr("MRB" if op == 0x16 else "MRF")
            return f"{acc} = 0; {acc2} = 0; MN = 0; MV = 0; MU = 0; MI = 0;"
        d = (op >> 1) & 3
        src, src2 = _mr("MRB" if d & 1 else "MRF")
        sg, fr = op & 1, (op >> 3) & 1
        if op >> 4 == 0:                        # SAT (mod2)
            maxl = {(1, 0): 0x7FFFFFFF, (0, 0): 0xFFFFFFFF, (1, 1): 0x7FFFFFFFFFFFFFFF,
                    (0, 1): 0xFFFFFFFFFFFFFFFF}[(sg, fr)]
            s1, s0 = (31, 32) if fr else (15, 16)
            if sg:
                minl = 0x8000000000000000 if fr else 0xFFFFFFFF80000000
                body = (f"local h:2 = {src2}; local l:8 = {src}; local tq:8 = (sext(h) << 48) | (l >> 16); "
                        f"local w1:8 = tq s>> {s1}; local ph:1 = (w1 s> 0); local nh:1 = (w1 s< -1); "
                        f"l = l + zext(ph) * ({maxl:#x} - l) + zext(nh) * ({minl:#x} - l); "
                        f"h = h + zext(ph) * (0 - h) + zext(nh) * (0xffff - h);")
            else:
                body = (f"local h:2 = {src2}; local l:8 = {src}; local tq:8 = (sext(h) << 48) | (l >> 16); "
                        f"local w0:8 = tq >> {s0}; local ph:1 = (w0 != 0); "
                        f"l = l + zext(ph) * ({maxl:#x} - l); h = h * zext(ph == 0);")
            flags = _mflags(sg, fr) + " MV = 0;"
        elif op & 0x08:                         # RND (mod3, fractional)
            body = f"local h:2 = {src2}; local l:8 = {src}; mrround(h, l);"
            flags = _mflags(sg, 1)
        else:
            return None
        if d < 2:
            res = f"local r:4 = l(4); {dst_rn} = r;" if fr or not (op >> 4 == 0) else f"local r:4 = l:4; {dst_rn} = r;"
        else:
            res = f"{src} = l; {src2} = h;"
        return f"{body} {flags} {res}"
    ys, xs, fr, rnd = (op >> 5) & 1, (op >> 4) & 1, (op >> 3) & 1, op & 1
    d = (op >> 1) & 3
    sg = xs | ys
    ex = lambda r, s: f"sext({r})" if s else f"zext({r})"
    prod = (f"local p:8 = {ex(x, xs)} * {ex(y, ys)}; local ph:2 = " +
            ("0xffff * zext(p s< 0)" if sg else "0") + "; local pl:8 = p;")
    if xs and ys and fr:                        # signed fractional: drop the redundant sign bit
        prod += " pl = p << 1;"
    if hi == 1:
        acc = None
        calc = f"{prod} local h:2 = ph; local l:8 = pl;"
    else:
        acc, acc2 = _mr("MRB" if d & 1 else "MRF")
        if hi == 2:
            calc = (f"{prod} local l:8 = {acc} + pl; local h:2 = {acc2} + ph + zext(carry({acc}, pl));")
        else:
            calc = (f"{prod} local l:8 = {acc} - pl; local h:2 = {acc2} - ph - zext({acc} < pl);")
    if rnd:
        calc += " mrround(h, l);"
    flags = _mflags(sg, fr)
    if (hi == 1 and d == 0) or (hi > 1 and d < 2):
        res = f"local r:4 = l(4); {dst_rn} = r;" if fr else f"local r:4 = l:4; {dst_rn} = r;"
    elif hi == 1 and d == 1:
        return None
    else:
        tgt, tgt2 = _mr("MRB" if d & 1 else "MRF")
        res = f"{tgt} = l; {tgt2} = h;"
    return f"{calc} {flags} {res}"


def uniq(code, tag):
    """Rename a p-code fragment's locals and labels so that two fragments can share a
    constructor body."""
    for name in set(re.findall(r"local (\w+):", code)):
        code = re.sub(rf"\b{name}\b", f"{name}_{tag}", code)
    return re.sub(r"<(\w+)>", rf"<\1_{tag}>", code)


# Multifunction fixed-point multiplies (PGR 11-92): SSFR products into Rm, SSF accumulation
# into MRF; the equivalent single-function opcodes give their p-code.
MF_MUL = {0x04: 0x79, 0x0C: 0xB9, 0x14: 0xF9, 0x08: 0xBC, 0x10: 0xFC}


def mf_sem(op6, v):
    """p-code of multifunction op6 (Table 12-12): both units read their operands, compute
    into locals, then write; both units' flags are set."""
    m, a = v["m"], v["a"]
    xm, ym, xa, ya = v["xm"], v["ym"], v["xa"], v["ya"]
    if op6 < 0x18:
        mop = MF_MUL[op6 & 0x1C]
        msem = uniq(mult_sem(mop, {"n": m, "x": xm, "y": ym}, out="tm"), "m")
        alu = {0: 0x01, 1: 0x02, 2: 0x09}[op6 & 3]
        asem = uniq(ALU_SEM[alu].format(n="ta", x=xa, y=ya), "a")
        wr_m = f" {m} = tm;" if "tm" in msem else ""
        return f"local tm:4 = 0; local ta:4 = 0; {msem} {asem}{wr_m} {a} = ta;"
    fmul = uniq(mult_sem(0x30, {"n": m, "x": xm, "y": ym}, out="tm"), "m")
    alu = {0x18: 0x81, 0x19: 0x82, 0x1A: 0xDA, 0x1B: 0xD9, 0x1C: 0x89, 0x1D: 0xB0, 0x1E: 0xE2, 0x1F: 0xE1}[op6]
    asem = uniq(ALU_SEM[alu].format(n="ta", x=xa, y=ya), "a")
    return f"local tm:4 = 0; local ta:4 = 0; {fmul} {asem} {m} = tm; {a} = ta;"


def dual_sem(fl, v, mul=False):
    """Dual add/subtract (PGR 11-92), optionally with a multiply: the flags are those of the
    sum and the difference together (AZ, AN, AV, AC of either).  The manual does not state how
    the two results combine in ASTAT; see GHIDRA-RARE.md."""
    xa, ya, a, s = (v["xa"], v["ya"], v["a"], v["s2"]) if mul else (v["x"], v["y"], v["n"], v["s"])
    add, sub = (0x81, 0x82) if fl else (0x01, 0x02)
    p = (f"local ta:4 = 0; local ts:4 = 0; {uniq(ALU_SEM[add].format(n='ta', x=xa, y=ya), 'a')} "
         f"local z1:1 = AZ; local n1:1 = AN; local v1:1 = AV; local c1:1 = AC; "
         f"{uniq(ALU_SEM[sub].format(n='ts', x=xa, y=ya), 's')} AZ = AZ || z1; AN = AN || n1; AV = AV || v1; AC = AC || c1;")
    if mul:
        msem = uniq(mult_sem(0x30 if fl else 0x79, {"n": v["m"], "x": v["xm"], "y": v["ym"]}, out="tm"), "m")
        return f"local tm:4 = 0; {msem} {p} {v['m']} = tm; {a} = ta; {s} = ts;"
    return f"{p} {a} = ta; {s} = ts;"


class Compute:
    """Generate compute subtables for a layout, in variants of prefix/suffix text."""

    def __init__(self, layout, name):
        self.L = layout
        self.name = name
        self.fm = reg_fields(layout, name)
        self.v = sem_vars(self.fm)
        self.ops = []            # (pattern, display_template, pcode)
        self._build()

    def add(self, i32c, i16c, template, pcode):
        d, used = disp(template, self.fm)
        # semantic operands are the R-attached fields for the same keys
        keys = set(re.findall(r"[RF]\{(\w+)\}", template))
        need = set(used) | {self.fm[("R", k)] for k in keys}
        need |= {fld for fld in self.v.values() if pcode and re.search(rf"\b{fld}\b", pcode)}
        i32c, i16c = list(i32c), list(i16c)
        for n in sorted(need):
            (i32c if FL.tok_of(n) == "i32" else i16c).append(n)
        self.ops.append((self.L.pattern(i32c, i16c), d, pcode or ""))

    def _sem(self, body):
        return body.format(**self.v) if body else None

    def _build(self):
        L, v = self.L, self.v
        mf, cu = L.fld(22, 22), L.fld(21, 20)
        # single function ALU
        for op, tmpl in S.ALU.items():
            a, b = L.op8(op)
            t = tmpl.replace("{n}", "{n}").replace("{x}", "{x}").replace("{y}", "{y}")
            self.add([f"{mf}=0", f"{cu}=0", a], [b], t, self._sem(ALU_SEM.get(op)))
        for hi4, fl in ((0x7, False), (0xF, True)):     # dual add/sub
            if L.name == "2b":
                c = [f"{mf}=0", f"{cu}=0", f"{L.fld(19, 16)}={hi4:#x}"]
                c2 = []
            else:
                c = [f"{mf}=0", f"{cu}=0", f"{L.fld(19, 16)}={hi4:#x}"]
                c2 = []
            p = "F" if fl else "R"
            tmpl = f"{p}{{n}} = {p}{{x}} + {p}{{y}}, {p}{{s}} = {p}{{x}} - {p}{{y}}"
            self.add(c, c2, tmpl, dual_sem(fl, v))
        # multiplier
        for op in range(256):
            t = S.mult_text(op, 0, 0, 0)
            if not t:
                continue
            t = S.mult_text(op, "{n}", "{x}", "{y}")
            a, b = L.op8(op)
            self.add([f"{mf}=0", f"{cu}=1", a], [b], t, self._sem(mult_sem(op, {k: "{" + k + "}" for k in v})))
        # shifter
        for op, tmpl in S.SHIFT.items():
            a, b = L.op8(op)
            t = tmpl.format(n="{n}", x="{x}", y="R{y}", f="R{y}", b="R{y}", w="R{x}")
            sem = shift_sem(op, "{n}", "{x}", "{x}" if op == 0x7C else "{y}")
            self.add([f"{mf}=0", f"{cu}=2", a], [b], t, self._sem(sem))
        # multifunction
        op6 = L.fld(21, 16)
        for code, tmpl in S.MULALU.items():
            t = tmpl.replace("{m}", "{m}")
            sem = mf_sem(code, {k: "{" + k + "}" for k in v})
            self.add([f"{mf}=1", f"{op6}={code:#x}"], [], t, self._sem(sem))
        fx = L.fld(21, 20, kind="mfd")
        for fl in (0, 1):
            p = "F" if fl else "R"
            if fl:
                t = "F{m} = F{xm} * F{ym}, F{a} = F{xa} + F{ya}, F{s2} = F{xa} - F{ya}"
            else:
                t = "R{m} = R{xm} * R{ym} (SSFR), R{a} = R{xa} + R{ya}, R{s2} = R{xa} - R{ya}"
            self.add([f"{mf}=1", f"{fx}={2 | fl}"], [], t, dual_sem(fl, self.v, mul=True))
        mrd = L.fld(21, 17, kind="mr")
        dbit = L.fld(16, 16)
        for code, mr in S.MRREG.items():
            sel = L.fld(15, 12, kind="mrsel")
            n = self.v["n"]
            # PGR 3-15: MR2 reads are sign-extended, writing MR1 sign-extends into MR2, writing
            # MR0 does not; the multiplier flags are cleared (PGR 11-56).
            rd = f"{n} = sext({mr});" if mr.startswith("MR2") else f"{n} = {mr};"
            wr = {"MR2": f"{mr} = {n}:2;", "MR1": f"{mr} = {n}; MR2{mr[3]} = 0xffff * zext({n} s< 0);",
                  "MR0": f"{mr} = {n};"}[mr[:3]]
            clr = " MN = 0; MV = 0; MU = 0; MI = 0;"
            self.add([f"{mf}=1", f"{mrd}=0", f"{dbit}=0"], [f"{sel}={code}"], f"R{{n}} = {mr}", rd + clr)
            self.add([f"{mf}=1", f"{mrd}=0", f"{dbit}=1"], [f"{sel}={code}"], f"{mr} = R{{n}}", wr + clr)

    def render(self, sub, prefix="", suffix="", zero_display=""):
        """One subtable `sub`: each op displayed as prefix+op+suffix; compute==0 -> zero_display."""
        out = []
        # null compute
        if self.L.name == "2b":
            zpat = f"{FL.f(38, 16)}=0"
        else:
            zpat = f"{FL.f(22, 16)}=0 ; {FL.f(15, 0)}=0"
        zd = f'"{zero_display}"' if zero_display else ""
        out.append(f"{sub}: {zd} is {zpat} {{ }}")
        pre = f'"{prefix}"^' if prefix else ""
        suf = f'^"{suffix}"' if suffix else ""
        for pat, d, pcode in self.ops:
            out.append(f"{sub}: {pre}{d}{suf} is {pat} {{ {pcode} }}")
        return "\n".join(out)




# ------------------------------------------------------------------ conditions
# Condition codes (PGR Table 10-4; meanings in Table 4-37).  15 is NOT LCE: the loop counter expires on the
# iteration in which CURLCNTR is 1.  31 is TRUE (no IF displayed).
# LT and LE follow the footnotes of Table 4-37: in fixed-point (AF = 0) the sign is corrected
# by an overflow when saturation is off; in floating point a zero is never negative.
# 14 is the shifter bit FIFO flag SF on the ADSP-2147x/2148x (bus master, an input the module
# cannot know, on the ADSP-2146x; the mnemonic stays BM).
COND_EXPR = {0: "AZ", 1: "((AF == 0) && (AN ^^ (AV && (ALUSAT == 0)))) || (AF && AN && !AZ)",
             2: "((AF == 0) && (AN ^^ (AV && (ALUSAT == 0)))) || (AF && AN) || AZ", 3: "AC", 4: "AV", 5: "MV",
             6: "MN", 7: "SV",
             8: "SZ", 9: "FLAG0", 10: "FLAG1", 11: "FLAG2", 12: "FLAG3", 13: "BTF", 14: "SF",
             15: "CURLCNTR != 1", 31: "1"}
for _k in range(16, 31):
    COND_EXPR[_k] = f"!({COND_EXPR[_k - 16]})"


def cond_tables():
    """CC (all 32 codes, for the ISA-only type 10), CCN/CCN16 (0..30, for conditional
    instructions, whose TRUE form is a separate constructor), and LTERM (the
    DO UNTIL termination condition, read from the loop-end context)."""
    cc = []
    for tab, fld in (("CC", FL.f(37, 33)),):
        for k, nm in enumerate(COND_NAMES):
            if k == 31:
                cc.append(f"{tab}: is {fld}=31 {{ local t:1 = 1; export t; }}")
            else:
                cc.append(f'{tab}: "IF {nm} " is {fld}={k} {{ local t:1 = {COND_EXPR[k]}; export t; }}')
    for tab, fld in (("CCN", FL.f(37, 33)), ("CCN16", FL.f(37, 33, tok="s16"))):
        for k, nm in enumerate(COND_NAMES[:31]):
            cc.append(f'{tab}: "IF {nm} " is {fld}={k} {{ local t:1 = {COND_EXPR[k]}; export t; }}')
    for k in range(31):
        if k != 15:
            cc.append(f"LTERM: is lterm={k} {{ local t:1 = {COND_EXPR[k]}; export t; }}")
    return "\n".join(cc)


def gen():
    C48 = Compute(Layout("48"), "c48")
    C2B = Compute(Layout("2b"), "c2b")
    parts = [cond_tables()]
    parts.append(C48.render("CMP48"))                          # bare
    parts.append(C48.render("CMP48s", suffix=", "))            # followed by a move
    parts.append(C48.render("CMP48p", prefix=", "))            # after a branch
    parts.append(C48.render("CMP48e", prefix=", ELSE "))       # else-compute
    parts.append(C2B.render("CMP2B"))
    parts += instr_types()
    return parts


# ------------------------------------------------------------------ branch targets
def map48(t):
    """SLEIGH pattern expression mapping a PM address `t` to the code-space address.

    Short-word (SW) addresses 0x100000..0x1fffff are used as they are.  A 48-bit address
    in 0x80000..0xfffff (blocks 0-3) is replaced by its physical SW alias, where the
    instruction's three parcels are stored: SW = 3*A - (A & 0xe0000) (block 0 0x8c000 ->
    0x124000, block 1 0xac000 -> 0x164000, block 2 0xc0000 -> 0x180000, block 3 0xe0000 ->
    0x1c0000).  There are no conditionals in pattern expressions, so the choice is made
    arithmetically: s48 = bit 19 set and bits 31..20 clear (nz is 1 when any of bits
    31..20 is set).  Testing bit 20 alone mapped external addresses such as 0x280000."""
    nz = f"((((({t}) >> 20) & 0xfff) + 0xfff) >> 12)"
    s48 = f"((({t}) >> 19) & 1 & ({nz} ^ 1))"
    return f"({t}) + {s48} * (2 * ({t}) - (({t}) & 0xe0000))"


def targets():
    f = FL.f
    lo16 = f(15, 0)
    a24hi = f(23, 16)
    rel24hi = f(23, 16, signed=True)
    r6 = f(32, 27, signed=True)
    t_abs = f"(({a24hi} << 16) | {lo16})"
    t_rel = f"(inst_start + (({rel24hi} << 16) | {lo16}))"
    return "\n".join([
        # absolute (types 8, 25): a 24-bit PM address
        f"ABS24: tgt is {a24hi} ; {lo16} [ tgt = {map48(t_abs)}; ] {{ export *:4 tgt; }}",
        # PC-relative, 24-bit: VISA offsets are in short words and may cross into 48-bit
        # code (the linker emits them for jumps to ISA stubs); ISA offsets are in 48-bit
        # words, i.e. three code units in the alias
        f"REL24: tgt is visa=1 & {rel24hi} ; {lo16} [ tgt = {map48(t_rel)}; ] {{ export *:4 tgt; }}",
        f"REL24: tgt is visa=0 & {rel24hi} ; {lo16} [ tgt = inst_start + (({rel24hi} << 16) | {lo16}) * 3; ] {{ export *:4 tgt; }}",
        f"REL6: tgt is visa=1 & {r6} [ tgt = inst_start + {r6}; ] {{ export *:4 tgt; }}",
        f"REL6: tgt is visa=0 & {r6} [ tgt = inst_start + {r6} * 3; ] {{ export *:4 tgt; }}",
    ])


def flow(kind, tgt, cond, db, la=False):
    """p-code for the control transfer of a branch whose condition (if any) is in local `c`.

    The delay slots (DS) run whether or not the branch is taken, so they come first; the
    not-taken path then falls through to the instruction after the slots.  `goto inst_next`
    is never used: for a delayed branch it would re-enter the first delay slot."""
    pre = "build DS; " if db else ""
    popl = "popLoop(); " if la else ""
    if kind == "jump" and cond and not la:
        return pre + f"if (c) goto {tgt};"
    # CALL pushes the return address (the hardware address: 48-bit in ISA code, after the
    # delay slots for (DB)) with bit 24 set (PGR Table A-3); RTS/RTI pop it.  The caller adds
    # call_pattern(db) / " & ISA" to the constructor's pattern.
    push = f"local ra:4 = {'RA1' if db else 'RA0'}; pushPC(ra | 0x1000000); "
    body = {"jump": f"{popl}goto {tgt};", "call": f"{push}call {tgt};", "ijump": f"{popl}goto [{tgt}];",
            "icall": f"{push}call [{tgt}];", "ret": f"return [{tgt}];",
            "rts": "local rt:4 = PCSTK & 0xffffff; popPC(); pmcode(rt, ISA); return [rt];"}[kind]
    if cond:
        return pre + f"if (!c) goto <end>; {body} <end>"
    return pre + body


def call_pattern(db, have_isa=False):
    """Pattern operands the CALL p-code of flow() uses."""
    return " & RA1" if db else " & RA0"


def mods(j=0, la=0, ci=0, lr=0):
    """Display pieces for the branch modifiers."""
    return [f'" {txt}"' for flag, txt in ((j, "(DB)"), (la, "(LA)"), (ci, "(CI)"), (lr, "(LR)")) if flag]


def dj(*pieces):
    """Join display pieces (strings or lists of strings) with ^, dropping empty ones."""
    flat = []
    for p in pieces:
        flat += p if isinstance(p, list) else [p]
    flat = [x for x in flat if x]
    if flat and flat[0].startswith('" '):     # the mnemonic's own space separates it
        flat[0] = '"' + flat[0][2:]
    return "^".join(flat)


def instr_types():
    """`instr` constructors for every instruction type (48-bit shared, 32/16-bit VISA-only)."""
    f, regs, names = FL.f, FL.regs, FL.names
    out = [targets()]
    I1 = [f"I{i}" for i in range(8)]
    I2 = [f"I{i}" for i in range(8, 16)]
    M1 = [f"M{i}" for i in range(8)]
    M2 = [f"M{i}" for i in range(8, 16)]
    lo16 = f(15, 0)
    ureg29 = FL.regs(29, 23, UREG)                  # type 3 ureg
    ureg38 = FL.regs(38, 32, UREG)                  # types 14,15a,17
    dest5 = FL.regs(29, 23, UREG, kind="d")         # type 5 dest (same bits as ureg29)
    # Loading Bn also loads In (PGR "Circular Buffering Mode": "When the B register is
    # loaded, the corresponding I register is simultaneously loaded with the same value").
    # A companion field over the same ureg bits names In for the B codes and the scratch
    # register BIX (never read) for every other code; each ureg load writes both.
    bi_regs = [f"I{k - 64}" if 64 <= k < 80 else "BIX" for k in range(128)]
    bi29 = FL.regs(29, 23, bi_regs, kind="bi")
    bi38 = FL.regs(38, 32, bi_regs, kind="bi")
    # (LW) neighbours (PGR Table 6-1: code ^ 1 within a register group; PX moves as itself)
    # and the I register a neighbouring B load also loads.
    nb_regs = [UREG[k ^ 1] if UREG[k] != "PX" else "PX" for k in range(128)]
    nbi_regs = [f"I{(k ^ 1) - 64}" if 64 <= (k ^ 1) < 80 else "BIX" for k in range(128)]
    nb29, nbi29 = FL.regs(29, 23, nb_regs, kind="nb"), FL.regs(29, 23, nbi_regs, kind="nbi")
    nb38, nbi38 = FL.regs(38, 32, nb_regs, kind="nb"), FL.regs(38, 32, nbi_regs, kind="nbi")
    # Stored universal registers: PC reads as the address of the instruction (PCVAL).
    out.append(f"UR29: {ureg29} is {ureg29} {{ export {ureg29}; }}\n"
               f'UR29: "PC" is {FL.f(29, 23)}=0x63 & PCVAL {{ export PCVAL; }}\n'
               f"UR38: {ureg38} is {ureg38} {{ export {ureg38}; }}\n"
               f'UR38: "PC" is {FL.f(38, 32)}=0x63 & PCVAL {{ export PCVAL; }}\n'
               "BR0V: is brm0=0 { export 0:1; }\nBR0V: is brm0=1 { export 1:1; }\n"
               "BR8V: is brm8=0 { export 0:1; }\nBR8V: is brm8=1 { export 1:1; }")
    nocomp = f"{f(22, 16)}=0x3f"                    # VISA 32-bit form: compute field absent
    cnt = [0]

    B1, B2 = [f"B{i}" for i in range(8)], [f"B{i}" for i in range(8, 16)]
    L1, L2 = [f"L{i}" for i in range(8)], [f"L{i}" for i in range(8, 16)]

    def dag(ir):
        """Companion operands of an I-register field: the B and L registers of the same
        number, and the field's plain value (for the bit-reverse test of I0/I8)."""
        hi, lo, tok, _ = FL.meta[ir]
        hi2 = FL.attach_vars[ir][0] == "I8"
        bf = FL.regs(hi, lo, B2 if hi2 else B1, tok=tok, kind=f"cb{int(hi2)}")
        lf = FL.regs(hi, lo, L2 if hi2 else L1, tok=tok, kind=f"cl{int(hi2)}")
        iv = FL.f(hi, lo, tok=tok, kind="iv")
        return bf, lf, iv, ("BR8V" if hi2 else "BR0V")

    def mem(space_g, d, ir, mr, reg, post=True, lw=False, bi=None, nb=None, nbi=None):
        """Display and p-code for a DAG access; ir/mr are operand fields (mr may be an
        immediate).  Returns (display, pre, post, pattern): `pre` captures a stored register
        before any compute in the same instruction writes it (all sources are read before any
        destination is written), `post` performs the access and the post-modify, `pattern`
        lists the companion operands the p-code uses (append it to the constructor's pattern).
        Post-modify honours circular buffering (postmod) and, where the brm0/brm8 context
        says bit-reverse mode is on, outputs I0/I8 bit-reversed.  (LW) moves the explicit
        register to/from the even word of the 64-bit pair and its neighbour to/from the odd
        word (PGR "Forced Long Word (LW) Memory Access")."""
        sp = "PM" if space_g else "DM"
        ea = f'{ir}^", "^{mr}' if post else f'{mr}^", "^{ir}'
        if d:
            dsp = f'"{sp}("^{ea}^") = "^{reg}'
        else:
            dsp = f'{reg}^" = {sp}("^{ea}^")"'
        if lw:
            dsp += '^" (LW)"'
        cnt[0] += 1
        n = cnt[0] % 2
        pat = ""
        if post:
            bf, lf, iv, brv = dag(ir)
            pat = f" & {bf} & {lf} & {iv} & {brv}"
            addr = f"ea{n}"
            calc = (f"local ea{n}:4 = {ir}; if (!(({iv} == 0:4) && {brv})) goto <nbr{n}>; bitrev32(ea{n}); <nbr{n}> ")
            upd = f" postmod({ir}, {mr}, {bf}, {lf});"
        else:
            addr = f"ea{n}"
            calc = f"local ea{n}:4 = {ir} + {mr}; "
            upd = ""
        if lw:
            calc += f"ea{n} = ea{n} & 0xfffffffe; "
            pat += f" & {nb}" + (f" & {nbi}" if nbi and not d else "")
        if d:
            pre = f"local sv{n}:4 = {reg};" + (f" local sw{n}:4 = {nb};" if lw else "")
            st = f"*[dm]:4 {addr} = sv{n};" + (f" *[dm]:4 ({addr} + 1) = sw{n};" if lw else "")
            return dsp, pre, f"{calc}{st}{upd}", pat
        also = f" {bi} = lv{n};" if bi else ""
        ld = f"local lv{n}:4 = *[dm]:4 {addr};" + (f" local lw{n}:4 = *[dm]:4 ({addr} + 1);" if lw else "")
        wr = f" {reg} = lv{n};{also}" + (f" {nb} = lw{n}; {nbi} = lw{n};" if lw else "")
        return dsp, "", f"{calc}{ld}{upd}{wr}", pat

    def cond_body(cc, *stmts):
        """A conditional non-branch instruction: everything is skipped when `cc` is false."""
        return f"build {cc}; if (!{cc}) goto <skip>; " + " ".join(s for s in stmts if s) + " <skip>"

    # ---------------- Type 1 (compute + dual move)
    dmd, pmd = f(44, 44), f(37, 37)
    dmi, dmm = regs(43, 41, I1), regs(40, 38, M1)
    pmi, pmm = regs(32, 30, I2), regs(29, 27, M2)
    dmr, pmr = regs(36, 33, R), regs(26, 23, R)
    for dd in (0, 1):
        for pd in (0, 1):
            a_d, a_pre, a_p, a_pat = mem(0, dd, dmi, dmm, dmr)
            b_d, b_pre, b_p, b_pat = mem(1, pd, pmi, pmm, pmr)
            base = (f"{f(47, 45)}=1 & {dmd}={dd} & {pmd}={pd} & {dmi} & {dmm} & {dmr} & {pmi} & {pmm} & {pmr}"
                    + a_pat + b_pat)
            out.append(f'instr: PAR CMP48s^{a_d}^", "^{b_d} is ({base}) ... & CMP48s '
                       f'{{ {a_pre} {b_pre} build CMP48s; {a_p} {b_p} }}')
            out.append(f'instr: PAR {a_d}^", "^{b_d} is visa=1 & {base} & {nocomp} '
                       f'{{ {a_pre} {b_pre} {a_p} {b_p} }}')
    # ---------------- Type 2
    out.append(f"instr: COMP CC^CMP48 is ({f(47, 40)}=0x01 & {f(39, 39)}=0 & CC) ... & CMP48 "
               f"{{ {cond_body('CC', 'build CMP48;')} }}")
    out.append(f"instr: COMP CMP2B is visa=1 & {f(47, 40)}=0x01 & {f(39, 39)}=1 & CMP2B {{ build CMP2B; }}")
    # 2c short compute (16-bit)
    sop = f(43, 40, tok="s16")
    sn = regs(39, 36, R, tok="s16")
    sn2 = regs(39, 36, R, tok="s16", kind="b")
    sx = regs(35, 32, R, tok="s16")
    fn_ = names(39, 36, F, tok="s16")
    fn2 = names(39, 36, F, tok="s16", kind="b")
    fx_ = names(35, 32, F, tok="s16")
    # The short compute ops are ALU/multiplier opcodes with Rx = Rn (PGR 12-12).
    short_ops = [("A", 0x01, "nnx"), ("A", 0x02, "nnx"), ("A", 0x21, "nx-"), ("A", 0x0A, "-nx"),
                 ("A", 0x43, "nx-"), ("A", 0x29, "nx-"), ("A", 0x2A, "nx-"), ("M", 0x70, "nnx"),
                 ("A", 0x81, "nnx"), ("A", 0x82, "nnx"), ("A", 0xCA, "nx-"), ("A", 0x8A, "-nx"),
                 ("A", 0x40, "nnx"), ("A", 0x41, "nnx"), ("A", 0x42, "nnx"), ("M", 0x30, "nnx")]

    def short_sem(op, n, x):
        unit, code, roles = short_ops[op]
        val = {"n": n, "x": x, "-": n}
        vv = {"n": val[roles[0]], "x": val[roles[1]], "y": val[roles[2]]}
        return ALU_SEM[code].format(**vv) if unit == "A" else mult_sem(code, vv)
    for op, tmpl in enumerate(S.SHORT):
        fm = {("R", "n"): sn, ("R", "x"): sx, ("F", "n"): fn_, ("F", "x"): fx_}
        first = {"R": True, "F": True}

        def sub(m):
            p, k = m.group(1), m.group(2)
            if k == "n":
                if first[p]:
                    first[p] = False
                    return f"{p}{{n}}"
                return f"{p}{{n2}}"
            return m.group(0)
        t2 = re.sub(r"([RF])\{(\w+)\}", sub, tmpl)
        fm[("R", "n2")] = sn2
        fm[("F", "n2")] = fn2
        d, used = disp(t2, fm)
        sem = short_sem(op, sn, sx)
        flds = " & ".join(sorted(set(used) | {sn, sx}))
        out.append(f"instr: SCOMP {d} is visa=1 & {f(47, 44, tok='s16')}=0xc & {sop}={op} & {flds} {{ {sem} }}")
    # ---------------- Type 3 (ureg <-> DM/PM, I/M register)
    u, g, d_, lw = f(44, 44), f(32, 32), f(31, 31), f(30, 30)
    for gg in (0, 1):
        ir = regs(43, 41, I2 if gg else I1, kind=f"g{gg}")
        mr = regs(40, 38, M2 if gg else M1, kind=f"g{gg}")
        for uu in (0, 1):
            for dd in (0, 1):
                for ll in (0, 1):
                    src = "UR29" if dd else ureg29
                    dsp, pre, pc, mpat = mem(gg, dd, ir, mr, src, post=bool(uu), lw=bool(ll),
                                             bi=None if dd else bi29, nb=nb29, nbi=nbi29)
                    base = (f"{f(47, 45)}=2 & {u}={uu} & {g}={gg} & {d_}={dd} & {lw}={ll} & "
                            f"{ir} & {mr} & {src}" + ("" if dd else f" & {bi29}") + mpat)
                    out.append(f"instr: MOVE CC^CMP48s^{dsp} is ({base} & CC) ... & CMP48s "
                               f"{{ {cond_body('CC', pre, 'build CMP48s;', pc)} }}")
                    out.append(f"instr: MOVE CC^{dsp} is visa=1 & {base} & CC & {nocomp} "
                               f"{{ {cond_body('CC', pre, pc)} }}")
    # 3c (16-bit): 1001 DMI DMM D 1 DREG
    s_dmi, s_dmm = regs(43, 41, I1, tok="s16"), regs(40, 38, M1, tok="s16")
    s_d, s_r = f(37, 37, tok="s16"), regs(35, 32, R, tok="s16", kind="c")
    for dd in (0, 1):
        dsp, pre, pc, mpat = mem(0, dd, s_dmi, s_dmm, s_r)
        out.append(f"instr: MOVE {dsp} is visa=1 & {f(47, 44, tok='s16')}=0x9 & {f(36, 36, tok='s16')}=1 & "
                   f"{s_d}={dd} & {s_dmi} & {s_dmm} & {s_r}{mpat} {{ {pre} {pc} }}")
    # ---------------- Type 4 (6-bit immediate modifier, dreg)
    d6 = f(32, 27, signed=True)
    dreg4 = regs(26, 23, R, kind="t4")
    gb, db, ub = f(40, 40), f(39, 39), f(38, 38)
    for gg in (0, 1):
        ir = regs(43, 41, I2 if gg else I1, kind=f"g{gg}")
        for uu in (0, 1):
            for dd in (0, 1):
                dsp, pre, pc, mpat = mem(gg, dd, ir, d6, dreg4, post=bool(uu))
                base = f"{f(47, 44)}=0x6 & {gb}={gg} & {db}={dd} & {ub}={uu} & {ir} & {d6} & {dreg4}" + mpat
                out.append(f"instr: MOVE CC^CMP48s^{dsp} is ({base} & CC) ... & CMP48s "
                           f"{{ {cond_body('CC', pre, 'build CMP48s;', pc)} }}")
                out.append(f"instr: MOVE CC^{dsp} is visa=1 & {base} & CC & {nocomp} "
                           f"{{ {cond_body('CC', pre, pc)} }}")
    # ---------------- Type 5 (ureg = ureg ; dreg <-> cdreg)
    srch, srcl = f(42, 38), f(32, 31)
    srcsub = []
    for code, nm in enumerate(UREG):
        if nm == "PC":      # the PC reads as the address of the instruction
            srcsub.append(f'SRCU: "PC" is {srch}={code >> 2} & {srcl}={code & 3} & PCVAL {{ export PCVAL; }}')
        else:
            srcsub.append(f'SRCU: "{nm}" is {srch}={code >> 2} & {srcl}={code & 3} {{ export {nm}; }}')
    out.append("\n".join(srcsub))
    base5 = f"{f(47, 43)}=0xE & {dest5} & {bi29} & SRCU"
    mv5 = f"{dest5} = t5; {bi29} = t5;"
    out.append(f'instr: MOVE CC^CMP48s^{dest5}^" = "^SRCU is ({base5} & CC) ... & CMP48s '
               f'{{ {cond_body("CC", "local t5:4 = SRCU;", "build CMP48s;", mv5)} }}')
    out.append(f'instr: MOVE CC^{dest5}^" = "^SRCU is visa=1 & {base5} & CC & {nocomp} '
               f'{{ {cond_body("CC", "local t5:4 = SRCU;", mv5)} }}')
    cdr = regs(41, 38, [f"S{i}" for i in range(16)])
    swr = regs(26, 23, R, kind="sw")
    base5s = f"{f(47, 43)}=0xF & {cdr} & {swr}"
    swp_pre = f"local ts:4 = {swr}; local tc:4 = {cdr};"
    swp = f"{swr} = tc; {cdr} = ts;"
    out.append(f'instr: SWAP CC^CMP48s^{swr}^" <-> "^{cdr} is ({base5s} & CC) ... & CMP48s '
               f'{{ {cond_body("CC", swp_pre, "build CMP48s;", swp)} }}')
    out.append(f'instr: SWAP CC^{swr}^" <-> "^{cdr} is visa=1 & {base5s} & CC & {nocomp} '
               f'{{ {cond_body("CC", swp_pre, swp)} }}')
    # ---------------- Type 6 (shift immediate [+ move]); SHIFTIM: 6-bit op at 21..16,
    # data8 at 15..8, Rn 7..4, Rx 3..0; DATAEX (30..27) extends data to 12 bits (bit6:len6).
    sh_rn, sh_rx = regs(7, 4, R, kind="sh"), regs(3, 0, R, kind="sh")
    sh_d8 = f(15, 8, signed=True)
    sh_bit = f(13, 8, kind="bit")
    sh_lenlo = f(15, 14, kind="lenlo")
    dataex = f(30, 27)
    shsub = []
    for op, tmpl in S.SHIFT.items():
        op6 = op >> 2
        t = (tmpl.replace("R{n}", "\x01").replace("R{x}", "\x02")
             .replace("F{n}", "\x06").replace("F{x}", "\x07")
             .replace("{y}", "\x03").replace("{f}", "\x04").replace("{b}", "\x05").replace("{w}", "\x05"))
        used = []

        def opnd(tag):
            if tag in "\x06\x07":            # FPACK / FUNPACK name the register as F
                n = FL.names(7, 4, F, kind="shf") if tag == "\x06" else FL.names(3, 0, F, kind="shf")
                used.append(n)
                return n
            base = {"\x01": sh_rn, "\x02": sh_rx, "\x03": sh_d8}.get(tag)
            if base is None:
                return {"\x04": f'{sh_bit}^":"^len6', "\x05": "imm12"}[tag]
            n = FL.alias(base) if base in used else base
            used.append(n)
            return n
        parts = re.split("([\x01-\x07])", t)
        dd = "^".join(opnd(p) if p and p in "\x01\x02\x03\x04\x05\x06\x07" else f'"{p}"' for p in parts if p)
        pat_i16 = set(used) | {sh_rn, sh_rx, sh_d8}
        acts = ""
        variants = [("", None)]
        if "\x04" in t:
            pat_i16 |= {sh_bit, sh_lenlo}
            acts = f"[ len6 = ({dataex} << 2) | {sh_lenlo}; ]"
            sem = f"local b6:4 = {sh_bit}; local l6:4 = len6; " + FIELD_SEM[op].format(n=sh_rn, x=sh_rx, b="b6", l="l6")
        elif "\x05" in t:
            pat_i16 |= {FL.f(15, 8, kind="u")}
            acts = f"[ imm12 = ({dataex} << 8) | {FL.f(15, 8, kind='u')}; ]"
            sem = f"local kk:4 = imm12; " + shift_sem(op, sh_rn, sh_rx, "kk")
        else:
            sem = f"local kk:4 = {sh_d8}; " + shift_sem(op, sh_rn, sh_rx, "kk")
        pat_i16 = sorted(pat_i16)
        for extra, vsem in variants:
            shsub.append(f"SHIMM: {dd} is {f(22, 22)}=0 & {f(21, 16)}={op6:#x} & {dataex} ; "
                         f"{' & '.join(pat_i16)}{extra} {acts} {{ {vsem or sem} }}")
    out.append("\n".join(shsub))
    for gg in (0, 1):
        ir = regs(43, 41, I2 if gg else I1, kind=f"g{gg}")
        mr = regs(40, 38, M2 if gg else M1, kind=f"g{gg}")
        for dd in (0, 1):
            dsp, pre, pc, mpat = mem(gg, dd, ir, mr, dreg4)
            base = f"{f(47, 44)}=0x8 & {g}={gg} & {d_}={dd} & {ir} & {mr} & {dreg4}" + mpat
            out.append(f'instr: SHIFT CC^SHIMM^", "^{dsp} is ({base} & CC) ... & SHIMM '
                       f'{{ {cond_body("CC", pre, "build SHIMM;", pc)} }}')
    out.append(f"instr: SHIFT CC^SHIMM is ({f(47, 40)}=0x02 & CC) ... & SHIMM "
               f"{{ {cond_body('CC', 'build SHIMM;')} }}")
    # ---------------- Type 7 (index modify)
    for gg in (0, 1):
        isr = regs(32, 30, I2 if gg else I1, kind=f"s{gg}")
        mm = regs(29, 27, M2 if gg else M1, kind=f"s{gg}")
        idx = f(26, 24)
        dst_sub = []
        base_nm = f"IDST{gg}"
        for s in range(8):
            for x in range(8):
                src = (8 if gg else 0) + s
                dst = (8 if gg else 0) + (s ^ x)
                if x == 0:
                    dst_sub.append(f'{base_nm}: is {f(32, 30)}={s} & {idx}=0 {{ export I{src}; }}')
                else:
                    dst_sub.append(f'{base_nm}: "I{dst} = " is {f(32, 30)}={s} & {idx}={x} {{ export I{dst}; }}')
        out.append("\n".join(dst_sub))
        base = f"{f(47, 40)}=0x04 & {f(38, 38)}={gg} & {isr} & {mm} & {base_nm}"
        cbf, clf, _, _ = dag(isr)
        base += f" & {cbf} & {clf}"
        mod = f"build {base_nm}; local t7:4 = 0; modwrap(t7, {isr}, {mm}, {cbf}, {clf}); {base_nm} = t7;"
        out.append(f'instr: MODIFY CC^CMP48s^{base_nm}^"MODIFY("^{isr}^", "^{mm}^")" is ({base} & CC) ... & CMP48s '
                   f'{{ {cond_body("CC", "build CMP48s;", mod)} }}')
        out.append(f'instr: MODIFY CC^{base_nm}^"MODIFY("^{isr}^", "^{mm}^")" is visa=1 & {base} & CC & {nocomp} '
                   f'{{ {cond_body("CC", mod)} }}')

    # ---------------- branches
    b39, la38, j26, e25, ci24 = f(39, 39), f(38, 38), f(26, 26), f(25, 25), f(24, 24)
    ccf = f(37, 33)

    def cc_forms(cc="CCN", field=ccf):
        """(conditional?, pattern fragment, display, p-code prologue): a branch exists
        once per condition code 0..30 and once for TRUE, whose flow is unconditional."""
        return [(True, cc, cc, f"build {cc}; local c:1 = {cc};"),
                (False, f"{field}=31", "", "")]

    # Type 8: direct / PC-relative jump or call
    for rel in (0, 1):
        tg = "REL24" if rel else "ABS24"
        for b in (0, 1):
            for j in (0, 1):
                for la in (0, 1):
                    for ci in (0, 1):
                        for cond, cpat, cdsp, cpro in cc_forms():
                            mn = "CALL" if b else "JUMP"
                            base = (f"{f(47, 41)}=3 & {f(40, 40)}={rel} & {b39}={b} & {la38}={la} & "
                                    f"{j26}={j} & {ci24}={ci} & {cpat}" + (" & DS" if j else "") +
                                    (call_pattern(j) if b else ""))
                            body = flow("call" if b else "jump", tg, cond, j, la=la and not b)
                            dsp = dj(cdsp, ['"("', tg, '")"'], mods(j, la, ci))
                            out.append(f'instr: {mn} {dsp} is ({base}) ... & {tg} '
                                       f'{{ {cpro} {body} }}')
    # Type 9: indirect (Md, Ic) or PC-relative 6-bit, with compute (48-bit) or without (9b).
    # The VisualDSP++ function return, JUMP (M14, I12) (DB) (I12 = the saved PC, M14 = 1),
    # gets its own, more specific constructor.  Its calls through JUMP (DB), which store the
    # return address in a delay slot, are recognised by the SHARC Call Idiom analyzer.
    ipmi, ipmm = regs(32, 30, I2, kind="ind"), regs(29, 27, M2, kind="ind")
    for rel in (0, 1):
        for b in (0, 1):
            for j in (0, 1):
                for la in (0, 1):
                    for ci in (0, 1):
                        variants = [("", "call" if b else "jump")]
                        if not rel and not b and j and not la and not ci:
                            variants.append((f" & {ipmi}=4 & {ipmm}=6", "ret"))
                        for extra, kind in variants:
                            if rel:
                                dst, pre, tgt = ['"("', "REL6", '")"'], "", "REL6"
                                ops = " & REL6"
                            else:
                                dst = ['"("', ipmm, '", "', ipmi, '")"']
                                pre, tgt = f"local tg:4 = {ipmi} + {ipmm}; pmcode(tg, ISA);", "tg"
                                ops = f" & {ipmi} & {ipmm} & ISA"
                                kind = {"jump": "ijump", "call": "icall"}.get(kind, kind)
                            mn = "CALL" if b else "JUMP"
                            for cond, cpat, cdsp, cpro in cc_forms():
                                base = (f"{f(47, 41)}=4 & {f(40, 40)}={rel} & {b39}={b} & {la38}={la} & "
                                        f"{j26}={j} & {ci24}={ci} & {cpat}{ops}{extra}" + (" & DS" if j else "") +
                                        (call_pattern(j, have_isa=not rel) if b else ""))
                                body = flow(kind, tgt, cond, j, la=la and not b)
                                for e in (0, 1):
                                    cmp = "CMP48e" if e else "CMP48p"
                                    if cond:
                                        gate = "if (c) goto <nc>;" if e else "if (!c) goto <nc>;"
                                        cpart = f"{gate} build {cmp}; <nc>"
                                    else:
                                        cpart = "" if e else f"build {cmp};"
                                    out.append(
                                        f'instr: {mn} {dj(cdsp, dst, mods(j, la, ci), cmp)} is ({base} & {e25}={e}) ... & {cmp} '
                                        f'{{ {cpro} {pre} {cpart} {body} }}')
                                out.append(
                                    f'instr: {mn} {dj(cdsp, dst, mods(j, la, ci))} is visa=1 & {base} & {e25}=0 & {nocomp} '
                                    f'{{ {cpro} {pre} {body} }}')
    # Type 10 (ISA only): IF cond JUMP (Md, Ic) / (PC, rel6), ELSE compute, DM move
    t10d, t10i, t10m, t10r = f(44, 44), regs(43, 41, I1, kind="t10"), regs(40, 38, M1, kind="t10"), regs(26, 23, R, kind="t10")
    for rel in (0, 1):
        for dd in (0, 1):
            dsp, mpre, pc, mpat = mem(0, 1 - dd, t10i, t10m, t10r)
            if rel:
                dst, pre, go, extra = '"("^REL6^")"', "", "goto REL6;", " & REL6"
            else:
                dst, pre, go, extra = (f'"("^{ipmm}^", "^{ipmi}^")"', f"local tg:4 = {ipmi} + {ipmm}; pmcode(tg, ISA);",
                                       "goto [tg];", f" & {ipmi} & {ipmm} & ISA")
            out.append(f'instr: JUMP CC^{dst}^", ELSE "^CMP48s^{dsp} is (visa=0 & {f(47, 45)}={6 + rel} & {t10d}={dd} & {t10i} & {t10m} & {t10r} & CC{extra}{mpat}) ... & CMP48s '
                       f'{{ build CC; local c:1 = CC; {pre} if (!c) goto <nt>; {go} <nt> {mpre} build CMP48s; {pc} }}')
    # Type 11: RTS / RTI with compute (48-bit) and 11c (16-bit)
    lr24 = f(24, 24, kind="lr")
    ccf16 = f(37, 33, tok="s16")
    for rti in (0, 1):
        mn = "RTI" if rti else "RTS"
        for j in (0, 1):
            for lr in (0, 1):
                for cond, cpat, cdsp, cpro in cc_forms():
                    body = flow("rts", "PCSTK", cond, j)
                    for e in (0, 1):
                        cmp = "CMP48e" if e else "CMP48p"
                        if cond:
                            cpart = ("if (c) goto <nc>;" if e else "if (!c) goto <nc>;") + f" build {cmp}; <nc>"
                        else:
                            cpart = "" if e else f"build {cmp};"
                        base = (f"{f(47, 40)}={0x0A + rti} & {b39}=0 & {j26}={j} & {e25}={e} & {lr24}={lr} & {cpat}"
                                + (" & DS" if j else "") + " & ISA")
                        out.append(f'instr: {mn} {dj(cdsp, mods(j, lr=lr and not rti), cmp)} is ({base}) ... & {cmp} '
                                   f'{{ {cpro} {cpart} {body} }}')
                for cond, cpat, cdsp, cpro in cc_forms("CCN16", ccf16):
                    body = flow("rts", "PCSTK", cond, j)
                    base = (f"visa=1 & {f(47, 40, tok='s16')}={0x0A + rti} & {f(39, 39, tok='s16')}=1 & "
                            f"{f(38, 38, tok='s16')}={j} & {f(32, 32, tok='s16')}={lr} & {cpat}" + (" & DS" if j else "") + " & ISA")
                    out.append(f"instr: {mn} {dj(cdsp, mods(j, lr=lr and not rti))} is {base} {{ {cpro} {body} }}")
    # Types 12/13: DO loops.  The DO marks its loop-end instruction with context (lend,
    # lterm, ltop); the root table in sharc214xx.slaspec adds the loop-back there.  All forms
    # push the loop-counter stack and load CURLCNTR from LCNTR.
    lcd = FL.f(39, 32, kind="lch")
    lcl = FL.f(31, 24, kind="lcl")
    mark = "lend=1; ltop=inst_start+3; globalset(REL24, lend); globalset(REL24, lterm); globalset(REL24, ltop);"
    # The loop's hardware addresses for the stacks (PGR Table A-4): the loop top goes on the PC
    # stack, the loop end with its termination code into LADDR; 48-bit addresses in ISA code.
    rel_hi, rel_lo = f(23, 16, signed=True), lo16
    out.append(f"LEND: le is visa=0 & {rel_hi} ; {rel_lo} [ le = ((inst_start + (((((inst_start - 0x100000) >> 18) & 3) + 4) << 17)) / 3) + (({rel_hi} << 16) | {rel_lo}); ] {{ export *[const]:4 le; }}\n"
               f"LEND: le is visa=1 & {rel_hi} ; {rel_lo} [ le = inst_start + (({rel_hi} << 16) | {rel_lo}); ] {{ export *[const]:4 le; }}")
    push = "local top:4 = PCVAL + 3 - 2 * ISA; pushLoop(top, la);"
    out.append(f'instr: DO "LCNTR = "^lcv^", DO ("^REL24^") UNTIL LCE" is ({f(47, 40)}=0x0C & {lcd} & {lcl}) ... & REL24 & LEND & PCVAL & ISA '
               f'[ lcv = ({lcd} << 8) | {lcl}; lterm=15; {mark} ] {{ LCNTR = lcv; local la:4 = (LEND & 0xffffff) | (15 << 24); {push} CURLCNTR = LCNTR; }}')
    out.append(f':DO "LCNTR = "^{ureg38}^", DO ("^REL24^") UNTIL LCE" is ({f(47, 40)}=0x0D & {f(39, 39)}=0 & {ureg38}) ... & REL24 & LEND & PCVAL & ISA '
               f'[ lterm=15; {mark} ] {{ LCNTR = {ureg38}; local la:4 = (LEND & 0xffffff) | (15 << 24); {push} CURLCNTR = LCNTR; }}'.replace(":DO", "instr: DO", 1))
    term = names(37, 33, TERM_NAMES, kind="term")
    termv = f(37, 33, kind="tv")
    out.append(f'instr: DO "DO ("^REL24^") UNTIL "^{term} is ({f(47, 40)}=0x0E & {term} & {termv}) ... & REL24 & LEND & PCVAL & ISA '
               f'[ lterm={term}; {mark} ] {{ local la:4 = (LEND & 0xffffff) | ({termv} << 24); {push} }}')
    def umove(dd, addr, ureg, src, bi, nb, nbi, ll):
        """p-code of a ureg <-> memory move at address expression addr, with (LW)."""
        if ll:
            a0 = f"local ea:4 = ({addr}) & 0xfffffffe; "
        else:
            a0 = f"local ea:4 = {addr}; "
        if dd:
            return (a0 + f"local sv:4 = {src}; *[dm]:4 ea = sv;" +
                    (f" local sv2:4 = {nb}; *[dm]:4 (ea + 1) = sv2;" if ll else ""))
        return (a0 + f"local lv:4 = *[dm]:4 ea; {ureg} = lv; {bi} = lv;" +
                (f" local lw:4 = *[dm]:4 (ea + 1); {nb} = lw; {nbi} = lw;" if ll else ""))

    def upat(dd, ureg, src, bi, nb, nbi, ll):
        return (f"{src}" + ("" if dd else f" & {bi}") + (f" & {nb}" if ll else "") +
                (f" & {nbi}" if ll and not dd else ""))

    # ---------------- Type 14 DM(addr32) <-> ureg
    a32hi = f(31, 16)
    for gg in (0, 1):
        for dd in (0, 1):
            for ll in (0, 1):
                sp = "PM" if gg else "DM"
                lws = '^" (LW)"' if ll else ""
                src = "UR38" if dd else ureg38
                if dd:
                    dsp = f'"{sp}("^a32^") = "^{src}{lws}'
                else:
                    dsp = f'{ureg38}^" = {sp}("^a32^")"{lws}'
                pc = umove(dd, "a32", ureg38, src, bi38, nb38, nbi38, ll)
                out.append(f"instr: MOVE {dsp} is {f(47, 42)}=0x04 & {f(41, 41)}={gg} & {f(40, 40)}={dd} & {f(39, 39)}={ll} & "
                           f"{upat(dd, ureg38, src, bi38, nb38, nbi38, ll)} & {a32hi} ; {lo16} "
                           f"[ a32 = ({a32hi} << 16) | {lo16}; ] {{ {pc} }}")
    # Type 15a DM(data32, Ia) <-> ureg ; 15b DM(data7, Ia)
    for gg in (0, 1):
        ir = regs(43, 41, I2 if gg else I1, kind=f"g{gg}")
        for dd in (0, 1):
            for ll in (0, 1):
                sp = "PM" if gg else "DM"
                lws = '^" (LW)"' if ll else ""
                src = "UR38" if dd else ureg38
                if dd:
                    dsp = f'"{sp}("^d32^", "^{ir}^") = "^{src}{lws}'
                else:
                    dsp = f'{ureg38}^" = {sp}("^d32^", "^{ir}^")"{lws}'
                pc = umove(dd, f"{ir} + d32", ureg38, src, bi38, nb38, nbi38, ll)
                out.append(f"instr: MOVE {dsp} is {f(47, 45)}=5 & {f(44, 44)}={gg} & {ir} & {f(40, 40)}={dd} & {f(39, 39)}={ll} & "
                           f"{upat(dd, ureg38, src, bi38, nb38, nbi38, ll)} & {a32hi} ; {lo16} "
                           f"[ d32 = ({a32hi} << 16) | {lo16}; ] {{ {pc} }}")
                d7 = f(22, 16, signed=True)
                src = "UR29" if dd else ureg29
                if dd:
                    dsp = f'"{sp}("^{d7}^", "^{ir}^") = "^{src}{lws}'
                else:
                    dsp = f'{ureg29}^" = {sp}("^{d7}^", "^{ir}^")"{lws}'
                pc = umove(dd, f"{ir} + {d7}", ureg29, src, bi29, nb29, nbi29, ll)
                out.append(f"instr: MOVE {dsp} is visa=1 & {f(47, 44)}=0x9 & {f(36, 34)}=2 & {f(37, 37)}={gg} & {ir} & {f(40, 40)}={dd} & {f(39, 39)}={ll} & "
                           f"{upat(dd, ureg29, src, bi29, nb29, nbi29, ll)} & {d7} "
                           f"{{ {pc} }}")
    # Type 16a DM(Ia, Mb) = data32 ; 16b data16 (post-modify)
    for gg in (0, 1):
        ir = regs(43, 41, I2 if gg else I1, kind=f"g{gg}")
        mr = regs(40, 38, M2 if gg else M1, kind=f"g{gg}")
        sp = "PM" if gg else "DM"
        bf, lf, iv, brv = dag(ir)
        dp = f" & {bf} & {lf} & {iv} & {brv}"
        st = (f"local ea:4 = {ir}; if (!(({iv} == 0:4) && {brv})) goto <nbr>; bitrev32(ea); <nbr> "
              f"*[dm]:4 ea = v; postmod({ir}, {mr}, {bf}, {lf});")
        out.append(f'instr: MOVE "{sp}("^{ir}^", "^{mr}^") = "^d32 is visa=0 & {f(47, 44)}=0x9 & {f(37, 37)}={gg} & {ir} & {mr}{dp} & {a32hi} ; {lo16} '
                   f'[ d32 = ({a32hi} << 16) | {lo16}; ] {{ local v:4 = d32; {st} }}')
        out.append(f'instr: MOVE "{sp}("^{ir}^", "^{mr}^") = "^d32 is visa=1 & {f(47, 44)}=0x9 & {f(36, 34)}=0 & {f(37, 37)}={gg} & {ir} & {mr}{dp} & {a32hi} ; {lo16} '
                   f'[ d32 = ({a32hi} << 16) | {lo16}; ] {{ local v:4 = d32; {st} }}')
        d16s = f(31, 16, signed=True)
        out.append(f'instr: MOVE "{sp}("^{ir}^", "^{mr}^") = "^{d16s} is visa=1 & {f(47, 44)}=0x9 & {f(36, 34)}=1 & {f(37, 37)}={gg} & {ir} & {mr}{dp} & {d16s} '
                   f'{{ local v:4 = {d16s}; {st} }}')
    # Type 17 ureg = data32 / data16
    out.append(f'instr: MOVE {ureg38}^" = "^d32 is {f(47, 40)}=0x0F & {f(39, 39)}=0 & {ureg38} & {bi38} & {a32hi} ; {lo16} '
               f'[ d32 = ({a32hi} << 16) | {lo16}; ] {{ {ureg38} = d32; {bi38} = d32; }}')
    d16s = f(31, 16, signed=True)
    out.append(f'instr: MOVE {ureg38}^" = "^{d16s} is visa=1 & {f(47, 40)}=0x0F & {f(39, 39)}=1 & {ureg38} & {bi38} & {d16s} '
               f'{{ {ureg38} = {d16s}; {bi38} = {d16s}; }}')
    # Type 18 BIT op sreg data32
    sreg = regs(35, 32, [n for n in UREG[112:128]])
    bops = {0: ("SET", "{r} = {r} | d32;"), 1: ("CLR", "{r} = {r} & ~d32;"), 2: ("TGL", "{r} = {r} ^ d32;"),
            4: ("TST", "BTF = ({r} & d32) == d32;"), 5: ("XOR", "BTF = ({r} == d32);")}
    for code, (nm, sem) in bops.items():
        out.append(f'instr: BIT "{nm} "^{sreg}^" "^d32 is {f(47, 40)}=0x14 & {f(39, 37)}={code} & {sreg} & {a32hi} ; {lo16} '
                   f'[ d32 = ({a32hi} << 16) | {lo16}; ] {{ {sem.format(r=sreg)} }}')
    # Type 19 MODIFY/BITREV with data32 (Id = ...)
    for gg in (0, 1):
        isr = regs(34, 32, I2 if gg else I1, kind=f"m{gg}")
        dsub = []
        nm = f"IDST19_{gg}"
        for s in range(8):
            for x in range(8):
                src = (8 if gg else 0) + s
                dst = (8 if gg else 0) + (s ^ x)
                if x == 0:
                    dsub.append(f'{nm}: is {f(34, 32)}={s} & {f(37, 35)}=0 {{ export I{src}; }}')
                else:
                    dsub.append(f'{nm}: "I{dst} = " is {f(34, 32)}={s} & {f(37, 35)}={x} {{ export I{dst}; }}')
        out.append("\n".join(dsub))
        cbf, clf, _, _ = dag(isr)
        out.append(f'instr: MODIFY {nm}^"MODIFY("^{isr}^", "^d32s^")" is ({f(47, 40)}=0x16 & {f(39, 39)}=0 & {f(38, 38)}={gg} & {isr} & {nm} & {cbf} & {clf} & {a32hi} ; {lo16}) '
                   f'[ d32s = ({a32hi} << 16) | {lo16}; ] {{ build {nm}; local t19:4 = 0; modwrap(t19, {isr}, d32s, {cbf}, {clf}); {nm} = t19; }}')
        out.append(f'instr: BITREV {nm}^"BITREV("^{isr}^", "^d32s^")" is ({f(47, 40)}=0x16 & {f(39, 39)}=1 & {f(38, 38)}={gg} & {isr} & {nm} & {a32hi} ; {lo16}) '
                   f'[ d32s = ({a32hi} << 16) | {lo16}; ] {{ build {nm}; local t19:4 = {isr} + d32s; bitrev32(t19); {nm} = t19; }}')
    # Type 20 push/pop of the loop, status and PC stacks (modelled as registers, PGR Table
    # 4-4); the cache flush is a user operation.
    names20 = ["PUSH LOOP", "POP LOOP", "PUSH STS", "POP STS", "PUSH PCSTK", "POP PCSTK", "FLUSH CACHE"]
    for v in range(128):
        txt = ", ".join(nm for k, nm in enumerate(names20) if v & (1 << (6 - k))) or "?20"
        mn, rest = (txt.split(" ", 1) + [""])[:2]
        sem = ""
        if v & 0x40:
            sem += "pushLoopCA(LADDR); CURLCNTR = LCNTR; "
        if v & 0x20:
            sem += "popLoopCA(); "
        if v & 0x10:
            sem += "pushSTS(); "
        if v & 0x08:
            sem += "popSTS(); "
        if v & 0x04:
            sem += "pushPC(PCSTK); "
        if v & 0x02:
            sem += "popPC(); "
        if v & 0x01:
            sem += "flushcache(); "
        out.append(f'instr: {mn} "{rest}" is {f(47, 40)}=0x17 & {f(39, 33)}={v} ; {lo16} {{ {sem} }}')
    # Types 21/22 NOP/IDLE and 16-bit forms
    for vm, extra in ((0, f" ; {lo16}"), (1, f" & {f(32, 32)}=0 ; {lo16}")):
        out.append(f'instr: NOP is visa={vm} & {f(47, 40)}=0x00 & {f(39, 38)}=0{extra} {{ }}')
        out.append(f'instr: IDLE is visa={vm} & {f(47, 40)}=0x00 & {f(39, 39)}=1{extra} {{ idle(); }}')
        out.append(f'instr: EMUIDLE is visa={vm} & {f(47, 40)}=0x00 & {f(39, 39)}=0 & {f(38, 38)}=1{extra} {{ emuidle(); }}')
    out.append(f'instr: NOP is visa=1 & {f(47, 40, tok="s16")}=0x00 & {f(39, 38, tok="s16")}=0 & {f(32, 32, tok="s16")}=1 {{ }}')
    out.append(f'instr: IDLE is visa=1 & {f(47, 40, tok="s16")}=0x00 & {f(39, 39, tok="s16")}=1 & {f(32, 32, tok="s16")}=1 {{ idle(); }}')
    out.append(f'instr: EMUIDLE is visa=1 & {f(47, 40, tok="s16")}=0x00 & {f(39, 39, tok="s16")}=0 & {f(38, 38, tok="s16")}=1 & {f(32, 32, tok="s16")}=1 {{ emuidle(); }}')
    # Type 25 CJUMP (C call: I6 = I7, R2 = old I6; the frame is stored in the delay slots)
    out.append(f'instr: CJUMP "("^ABS24^") (DB)" is ({f(47, 40)}=0x18 & {f(39, 32)}=0x04 & DS) ... & ABS24 '
               f'{{ R2 = I6; I6 = I7; build DS; call ABS24; }}')
    out.append(f'instr: CJUMP "("^REL24^") (DB)" is ({f(47, 40)}=0x18 & {f(39, 32)}=0x44 & DS) ... & REL24 '
               f'{{ R2 = I6; I6 = I7; build DS; call REL24; }}')
    out.append(f'instr: RFRAME is {f(47, 32)}=0x1900 ; {lo16} {{ I7 = I6; I6 = *[dm]:4 I6; }}')
    out.append(f'instr: RFRAME is visa=1 & {f(47, 32, tok="s16")}=0x1901 {{ I7 = I6; I6 = *[dm]:4 I6; }}')
    return [split_cond(o) for o in out if o]


def split_cond(block):
    """A conditional non-branch instruction exists once per condition code 0..30 (CCN, the
    body skipped when the condition is false) and once for TRUE with no test at all.  A
    single constructor testing a constant TRUE would leave a CBRANCH in every instruction,
    which the decompiler only folds late -- too late for jump-table recovery, whose guard
    search stops after two CBRANCHes."""
    out = []
    for ln in block.split("\n"):
        if "build CC; if (!CC) goto <skip>;" not in ln:
            out.append(ln)
            continue
        head, rest = ln.split(" is ", 1)
        pat, body = rest.split(" {", 1)
        out.append(head.replace("CC^", "CCN^", 1) + " is " + re.sub(r"\bCC\b", "CCN", pat) + " {" +
                   body.replace("build CC; if (!CC) goto <skip>;", "build CCN; if (!CCN) goto <skip>;"))
        body = body.replace("build CC; if (!CC) goto <skip>; ", "").replace(" <skip> }", " }")
        out.append(head.replace("CC^", "", 1) + " is " + re.sub(r"\bCC\b", f"{FL.f(37, 33)}=31", pat) +
                   " {" + body)
    return "\n".join(out)


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    parts = gen()
    # in a subtable a bare word in the display is an operand name: quote the mnemonics
    body = re.sub(r"^instr: ([A-Z0-9?]+) ", r'instr: "\1" ', "\n\n".join(parts), flags=re.M)
    text = ("# ADSP-214xx SHARC (ISA + VISA) instruction tables -- GENERATED by tools/gen_sinc.py\n"
            "# from tools/sharc_isa.py; do not edit.  See sharc214xx.slaspec for the model.\n\n"
            + FL.render() + "\n\n" + body + "\n")
    out.write_text(text)
    if DEBUG:
        n = sum(1 for ln in text.splitlines() if ln.startswith("instr:"))
        print(f"[gen_sinc] {out}: {text.count(chr(10))} lines, {n} instr constructors", file=sys.stderr)


if __name__ == "__main__":
    main()
