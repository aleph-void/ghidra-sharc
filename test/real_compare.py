#!/usr/bin/env python3
"""Compare the module's disassembly of a real executable with selache's seldump (black box).

    real_compare.py <seldump -all output> <RealCheck listing> [--show N]

seldump (https://github.com/js216/selache, GPL-3.0, run as a tool only) disassembles the code
sections of a .dxe: short-word sections at their short-word addresses, 48-bit sections at the
section's 48-bit address plus the offset in short words.  Every instruction seldump lists is
looked up at the same short-word address in the module's listing and classed as
  agree      the same text after normalisation (case, spacing, hex spelling, symbols replaced by
             their addresses, PC-relative targets made absolute);
  explained  a documented spelling difference (REWRITES);
  missing    the module has no instruction there (code no analysis reached);
  DIFF       anything else.
"""
import re
import sys
from collections import Counter

sys.path.insert(0, __import__("os").path.dirname(__file__))
from compare import norm_gh, norm_common, loose, DROP  # noqa: E402

DROP.add("SCOMP")


def sw48(a):
    return 3 * a - (a & 0xe0000)


def parse(dump):
    secs, syms, insns = {}, {}, []
    cur = None
    for line in open(dump, errors="replace"):
        m = re.match(r"(\w{4})\s+progbits\s+\w+\s+(\w{8})\s+\w+\s+\w+:B.*'(\S+)'", line.strip())
        if m:
            secs[m.group(3)] = int(m.group(2), 16)
            continue
        m = re.match(r"---- Section: (\S*) \[\d+\]", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"[0-9a-f]{4}\s+(\w+)\s+([0-9a-f]{8})\s+[0-9a-f]{8}\s+\w+\s+\w+\s+\w+\s+'(\S+)'", line.strip())
        if m and cur == ".symtab":
            syms.setdefault(m.group(3).upper(), set()).add(int(m.group(2), 16))
            continue
        m = re.match(r"\s+([0-9a-f]{8})\s+([0-9a-f]{4,12})\s+(.*)$", line)
        if m and cur in secs and cur.startswith("dxe_") and "code" in cur:
            a = int(m.group(1), 16)
            base = secs[cur]
            sw = a if base >= 0x100000 else sw48(base) + (a - base)
            insns.append((sw, m.group(2), m.group(3).strip(), base < 0x100000))
    return syms, insns


def word48(word):
    return int(word, 16) << (48 - 4 * len(word))


def norm_sel(t, sw, isa, syms, word, g):
    """seldump's text in the module's terms.  g (the module's normalised text) only picks the
    value of a local symbol name that several files define."""
    t = t.upper()
    w = word48(word)
    unit = 3 if isa else 1

    def target(v):
        return sw48(v) if 0x80000 <= v < 0x100000 else v

    def pick(name, mapped):
        vals = syms.get(name)
        if not vals:
            return None
        cands = [target(v) if mapped else v for v in sorted(vals)]
        for c in cands:
            if f"0X{c:X}" in g:
                return c
        return cands[0]

    # PC-relative operands: the offset is in the word (types 8a/12a/13a: bits 23..0, signed;
    # 9a/10a/11a: bits 32..27, signed), in 48-bit words in ISA code
    def pcrel(m):
        if (w >> 40) & 0xFF in (0x07, 0x0C, 0x0D, 0x0E) or (w >> 40) & 0xFE == 0x06:
            o = w & 0xFFFFFF
            o -= (o & 0x800000) << 1
        else:
            o = (w >> 27) & 0x3F
            o -= (o & 0x20) << 1
        return "(0X%X)" % (sw + o * unit)

    t = re.sub(r"\(PC, ?([-\w.]+)\)", pcrel, t)
    # DO <offset> UNTIL: the loop end relative to the DO
    # CJUMP (PC-relative, type 25a): seldump prints the 24-bit offset as if it were the target
    t = re.sub(r"^CJUMP (0X[0-9A-F]+)", lambda m: "CJUMP (0X%X)" % (sw + int(m.group(1), 16) * unit), t)
    t = re.sub(r"\bDO (-?0X[0-9A-F]+) UNTIL", lambda m: "DO (0X%X) UNTIL" % (sw + int(m.group(1), 16) * unit), t)

    def sym(m):
        kw, name = m.group(1), m.group(2)
        v = pick(name, bool(kw))
        if v is None:
            return m.group(0)
        return f"{kw}(0X{v:X})" if kw else f"0X{v:X}"

    t = re.sub(r"(?<![\w.])(JUMP |CALL |CJUMP )?([._A-Z][\w.]*)", sym, t)
    t = re.sub(r"\b(JUMP|CALL|CJUMP) (0X[0-9A-F]+)", r"\1 (\2)", t)
    t = norm_common(t)
    t = re.sub(r"^IF ([A-Z0-9_ ]+?) (JUMP|CALL|CJUMP|RTS|RTI)", r"IF \1, \2", t)
    return t


SREGS = ["USTAT1", "USTAT2", "MODE1", "MMASK", "MODE2", "FLAGS", "ASTATX", "ASTATY", "STKYX", "STKYY",
         "IRPTL", "IMASK", "IMASKP", "LRPTL", "USTAT3", "USTAT4"]


SEL_ONLY = {"MODE1STK"}


def sreg_swap(g, s):
    a, b = re.findall(r"\w+|[^\w\s]", g), re.findall(r"\w+|[^\w\s]", s)
    if len(a) != len(b):
        return g, s
    return g, " ".join(x if x != y and x in SREGS and (y in SREGS or y in SEL_ONLY) else y for x, y in zip(a, b))


# Rewrites: documented spelling differences and seldump/PGR differences (each with its reason).
REWRITES = [
    ("Id = Is shown short", lambda g, s: (g, re.sub(r"(I\d+) ?= ?(MODIFY|BITREV) ?\(\1,", r"\2(\1,", s)),
     "type 7/19 with Id = Is: the module prints MODIFY(Ia, Mb), seldump Ia = MODIFY(Ia, Mb)"),
    ("signed immediates", lambda g, s: (re.sub(r"0X([89A-F][0-9A-F]{7})\b",
                                               lambda m: "-0X%X" % (0x100000000 - int(m.group(1), 16)), g), s),
     "the module prints 32-bit immediates of MODIFY/DM(imm, I) unsigned, seldump signed"),
    ("seldump: system register codes", sreg_swap,
     "seldump names universal-register codes 0x70-0x7f differently from PGR Table 10-2 (e.g. 0x76 STKYY for "
     "ASTATx, type 18 SREG 5 MODE1 for FLAGS); the module follows Table 10-2"),
    ("seldump: no name for PX", lambda g, s: (g, s.replace("UREG(0X6B)", "PX")),
     "seldump prints universal register 0x6B as ureg(0x6b); Table 10-2 names it PX"),
    ("seldump drops OR of the shifter OR forms", lambda g, s: (re.sub(r"(R\d+) = \1 OR ", r"\1 = ", g), s),
     "Rn = Rn OR LSHIFT/ASHIFT/FDEP (PGR Table 12-11 opcodes 0x20/0x24/0x64...; MAME agrees with the module); "
     "seldump prints the plain shift"),
]


def whole_class(gt, st, word, glen):
    """Whole-instruction difference classes: (name, reason) or None."""
    w = word48(word)
    if (re.match(r"^(MUL|SHORTCOMPUTE|ALU|SHIFTER|MULTI\w*|STACK OP) ", st) or "???" in st or
            "SHIFT(0X" in st):
        return ("seldump undecoded", "seldump prints raw fields or ??? for this compute")
    if 2 * glen != len(word) // 2 * 2 and glen != len(word) // 4:
        return ("instruction length", "seldump and the module split the VISA stream differently; the module's "
                "lengths agree with the branch targets and loop ends around it (VISA types 7a/16a with "
                "bits 36-34 = 000 are 48-bit, PGR 10-22)")
    if len(word) == 4 and (w >> 44) == 0xC and ((w >> 40) & 0xF) == 7:
        return ("seldump short compute op 7", "type 2c OP 0111 is Rn = Rn * Rx (SSI) (PGR 12-12); "
                "seldump prints Rn = Rn + Rx + CI")
    toks = lambda x: sorted(re.findall(r"\w+", re.sub(r"\b[IM]\d+\b|\bDM\b|\bPM\b", "", x)))
    if (w >> 45) in (0b010, 0b011) or (w >> 44) == 0x9:
        if toks(gt) == toks(st):
            return ("seldump DAG fields of types 3, 4, 15, 16", "PGR 10-7..10-8, 10-21, 10-22: U (1 = post-modify), "
                    "D (1 = write), I, M and G; seldump disagrees on U, D, M or G (real code confirms the module: "
                    "DM(I7,M7) pushes, M3 computed just before DM(M3,I4), a pointer loaded by IF GT R15 = "
                    "DM(-2,I6) used by I4 = R15 next)")
    if (w >> 44) == 0x7 and toks(gt) == toks(st.replace("PX1", "PX2").replace("PX2", "PX2")):
        return ("seldump type 5 source register", "type 5a (PGR 10-9): source ureg in bits 42-38 and 32-31; "
                "seldump reads another register")
    if (w >> 40) == 0x02 and re.sub(r"^IF [A-Z ]+? (?=R\d)", "", gt) != gt:
        return ("seldump drops the type 6a condition", "type 6a (PGR 10-11) carries COND in bits 37-33; "
                "seldump prints the shift unconditionally")
    if (w >> 40) in (0x02,) or (w >> 45) == 0b100:
        if loose(re.sub(r"[AL]SHIFT|OR |\(SE\)", "", gt)) == loose(re.sub(r"[AL]SHIFT|OR |\(SE\)", "", st)) or \
                re.search(r"FEXT|FDEP", gt):
            return ("seldump shift-immediate fields", "shift-immediate opcode (Table 12-11: LSHIFT 0x00, ASHIFT "
                    "0x04, FEXT (SE) 0x48...) and bit6:len6 (Table 12-2, with DATAEX); MAME agrees with the "
                    "module, seldump prints other opcodes or a bit6 above 63")
    if (w >> 40) == 0x16:
        return ("seldump type 19a", "type 19a (PGR 10-24): bit 39 selects MODIFY/BITREV, bit 38 G, Is in "
                "34-32; seldump decodes the other operation and DAG")
    return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show = int(sys.argv[sys.argv.index("--show") + 1]) if "--show" in sys.argv else 0
    if show:
        args = [a for a in args if a != str(show)]
    syms, insns = parse(args[0])
    gh, glen, inside = {}, {}, set()
    for line in open(args[1]):
        a, n, t = line.rstrip("\n").split(" ", 2)
        a = int(a, 16) // 2
        gh[a] = t.lstrip("_")
        glen[a] = int(n) // 2
        inside.update(range(a + 1, a + int(n) // 2))
    cnt, ex, diffs = Counter(), Counter(), Counter()
    samples = {}
    for sw, word, t, isa in insns:
        if sw not in gh:
            cnt["inside" if sw in inside else "missing"] += 1
            continue
        g = norm_gh(gh[sw])
        s = norm_sel(t, sw, isa, syms, word, g)
        if loose(g) == loose(s):
            cnt["agree"] += 1
            continue
        g2, s2 = g, s
        used = []
        for name, fn, _ in REWRITES:
            ng, ns = fn(g2, s2)
            if (ng, ns) != (g2, s2):
                used.append(name)
                g2, s2 = ng, ns
            if loose(g2) == loose(s2):
                break
        wc = None if loose(g2) == loose(s2) else whole_class(g2, s2, word, glen[sw])
        if wc:
            used = [wc[0]]
        if loose(g2) == loose(s2) or wc:
            cnt["explained"] += 1
            ex[" + ".join(used)] += 1
            continue
        cnt["DIFF"] += 1
        key = re.sub(r"0X[0-9A-F]+|\d+", "#", g.split(" ")[0] + " | " + s.split(" ")[0])
        diffs[key] += 1
        samples.setdefault(key, []).append(f"{sw:x} {word}\n      G: {gh[sw]}\n      S: {t}")
    total = sum(cnt.values())
    print(f"seldump instructions {total}: agree {cnt['agree']}, explained {cnt['explained']}, "
          f"not disassembled by the module {cnt['missing']}, inside a module instruction {cnt['inside']}, "
          f"unexplained {cnt['DIFF']}")
    for k, v in ex.most_common():
        print(f"  {v:7d}  {k}")
    for k, v in diffs.most_common():
        print(f"  DIFF {v:5d} {k}")
        for smp in samples[k][:show]:
            print("     ", smp)
    return 1 if cnt["DIFF"] else 0


if __name__ == "__main__":
    sys.exit(main())
