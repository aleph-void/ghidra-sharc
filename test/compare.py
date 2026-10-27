#!/usr/bin/env python3
"""Compare the module's 48-bit (ISA) decode with MAME's unidasm -arch sharc.

    compare.py <ghidra-dump> <mame-listing> <corpus.gh> <base48> [--show N]

The ghidra dump is DumpSlots.java output for the 6-byte slots of <corpus.gh> imported at the
short-word alias of 48-bit address <base48>; the MAME listing is unidasm -basepc <base48>.
Each slot is classed as
  agree      same instruction after normalisation (spacing, commas, hex spelling, branch targets
             converted from the module's short-word alias back to the 48-bit address);
  invalid    both reject it (module: no decode, MAME: ??? or an empty line);
  explained  a difference class listed in EXPLAIN below, each with its reason;
  DIFF       anything else (the run fails).
"""
import re
import sys
from collections import Counter, defaultdict


DROP = {"MOVE", "PAR", "SWAP", "SHIFT", "COMP", "DO", "MODIFY", "BITREV"}
FLOW = {"JUMP", "CALL", "RTS", "RTI", "CJUMP"}
REL_TYPES = {0x07, 0x0C, 0x0D, 0x0E}          # type 8a PC-relative, types 12a/13a DO
HEX = re.compile(r"-?0[xX][0-9a-fA-F]+")


def num(m):
    s = m.group(0)
    neg = s.startswith("-")
    return ("-" if neg else "") + "0X" + format(int(s.lstrip("-"), 16), "X")


def norm_common(t):
    t = t.upper()
    t = HEX.sub(num, t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def norm_gh(t):
    mn, _, rest = t.partition(" ")
    if mn in DROP:
        t = rest
    elif mn in FLOW:
        m = re.match(r"IF ((?:NOT )?\S+)\s*(.*)", rest)
        t = f"IF {m.group(1)}, {mn} {m.group(2)}" if m else t
    t = norm_common(t)
    return t


def expected_target(a, w, base48, index):
    """MAME's 48-bit target `a` as the module shows it (short-word alias)."""
    if (w >> 40) in REL_TYPES:
        # ISA PC-relative targets are three short words per 48-bit word from the instruction
        return (3 * a - (base48 & 0xe0000)) & 0xffffffff
    if a >> 19 == 1:
        return 3 * a - (a & 0xe0000)
    return a


def norm_mame(t, w, base48, index):
    t = norm_common(t)
    t = re.sub(r"^IF ([A-Z0-9_ ]+?),", r"IF \1", t)
    t = re.sub(r"^IF ([A-Z0-9_ ]+?) (JUMP|CALL|RTS|RTI)", r"IF \1, \2", t)
    t = re.sub(r"(JUMP|CALL|DO) \((0X[0-9A-F]+)\)",
               lambda m: "%s (0X%X)" % (m.group(1), expected_target(int(m.group(2), 16), w, base48, index)), t)
    return t


def shape(toks):
    return " ".join(re.sub(r"(?<=[A-Z])\d+", "n", re.sub(r"\b\d+\b", "#", re.sub(r"-?0X[0-9A-F]+", "#", t))) for t in toks)


def signature(g, m):
    """The tokens that differ, with register numbers and constants generalised."""
    import difflib
    a, b = re.findall(r"[\w#?.]+|[^\w\s]", g), re.findall(r"[\w#?.]+|[^\w\s]", m)
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op != "equal":
            out.append(f"[{shape(a[i1:i2])}|{shape(b[j1:j2])}]")
    return " ".join(out)[:120]


def loose(t):
    return re.sub(r"[\s,]", "", t)


UREGS = set(f"{c}{i}" for c in "RIMLBS" for i in range(16)) | {f"MR{i}{x}" for i in range(3) for x in "FB"} | {
    "FADDR", "DADDR", "UREG_62", "PC", "PCSTK", "PCSTKP", "LADDR", "CURLCNTR", "LCNTR", "EMUCLK",
    "EMUCLK2", "PX", "PX1", "PX2", "TPERIOD", "TCOUNT", "USTAT1", "USTAT2", "MODE1", "MMASK", "MODE2",
    "FLAGS", "ASTATX", "ASTATY", "STKYX", "STKYY", "IRPTL", "IMASK", "IMASKP", "LRPTL", "USTAT3", "USTAT4"}
M2106X = UREGS | {"ASTAT", "STKY", "???"}
MOD = r"\((?:[SU]{2}[IF]R?|[SU][IF])\)"

# Rewrites that make the two texts comparable.  Each is a documented difference class: the
# module follows the Programming Reference (rev 2.4); MAME's sharc disassembler follows the
# ADSP-2106x and has the bugs listed.  (name, side, function(text, word) -> text, reason)
REWRITES = [
    ("spelling: NBM", "m", lambda t, w: t.replace("NBM", "NOT BM"),
     "MAME spells condition 30 NBM; the manual (Table 10-4) writes NOT BM"),
    ("spelling: decimal shift data", "m",
     lambda t, w: re.sub(r"(BY|:) ?(-?)(\d+)\b", lambda k: "%s %s0X%X" % (k.group(1), k.group(2), int(k.group(3))), t),
     "MAME prints shift-immediate data in decimal"),
    ("spelling: BIT CLEAR/TOGGLE/TEST", "m",
     lambda t, w: t.replace("BIT CLEAR", "BIT CLR").replace("BIT TOGGLE", "BIT TGL").replace("BIT TEST", "BIT TST"),
     "MAME spells BIT CLR/TGL/TST as BIT CLEAR/TOGGLE/TEST (type 18a)"),
    ("MAME prints (LR) for RTI", "m", lambda t, w: re.sub(r"(RTI.*?)\s*\(LR\)", r"\1", t),
     "type 11a: only RTS has the LR bit (bit 24); MAME prints it for RTI too"),
    ("MAME does not print (LA)", "g", lambda t, w: re.sub(r"\s*\(LA\)", "", t),
     "the loop-abort bit A of types 8a/9a (Table 10-1); MAME never prints it"),
    ("MAME omits multiplier modifiers", "both",
     lambda t, w: re.sub(r" ?" + MOD, "", re.sub(r"([+-])\((R\d+ \* R\d+)\)", r"\1 \2", t)),
     "MAME prints mod1/mod2/mod3 only for some forms; the module prints the modifier the opcode encodes (Tables 12-7..12-9)"),
    ("UNTIL LCE implied", "g", lambda t, w: t.replace(" UNTIL LCE", "") if "LCNTR =" in t else t,
     "LCNTR = ..., DO addr UNTIL LCE: MAME leaves out the implied termination"),
    ("MAME lacks the Id field", "g", lambda t, w: re.sub(r"I\d+ = (MODIFY|BITREV)\(", r"\1 (", t)
     if (w >> 40) in (0x16,) or (w >> 41) == 0b0000010 else t,
     "types 7a/19a carry Id XOR Is in bits 26-24 / 39-37 (destination I register, ADSP-214xx); MAME shows only Is"),
    ("MAME R/F letter bugs", "both", lambda t, w: re.sub(r"\bF(\d+)", r"R\1", t),
     "MAME writes FLOAT Fx BY Fy, Fn = FIX Fx BY Fy, RND Rx; the manual has Fn = FLOAT Rx BY Ry, Rn = FIX Fx BY Ry, Fn = RND Fx"),
    ("MAME ignores the LW bit", "g", lambda t, w: t.replace(" (LW)", ""),
     "long-word access bit L (Table 10-1, ADSP-214xx); MAME does not decode it"),
    ("ADSP-214xx register codes", "m", None,
     "MAME decodes universal-register codes with the ADSP-2106x table (ASTAT/STKY, no S registers, ??? for codes it lacks); the module follows Table 10-2"),
    ("MAME MR register numbering", "both", lambda t, w: re.sub(r"MR\d([FB])", r"MR?\1", t),
     "MR data move (PGR 12-9, Table 12-10): opcode 0100 is MR0B, 0101 MR1B, 0110 MR2B; MAME is off by one for the B registers"),
]


def reg_rewrite(g, m):
    """Replace MAME's register tokens by the module's where both are register names (2106x
    table versus Table 10-2): only token-for-token differences qualify."""
    a, b = re.findall(r"[\w?]+|[^\w\s?]", g), re.findall(r"[\w?]+|[^\w\s?]", m)
    if len(a) != len(b):
        return m
    out = []
    for x, y in zip(a, b):
        out.append(x if x != y and x in UREGS and y in M2106X else y)
    return " ".join(out)


def try_rewrites(g, m, w):
    """Apply rewrites cumulatively; return the list of classes needed for agreement, or None."""
    used = []
    for name, side, fn, _ in REWRITES:
        if fn is None:
            m2 = reg_rewrite(g, m)
            g2 = g
        else:
            g2 = fn(g, w) if side in ("g", "both") else g
            m2 = fn(m, w) if side in ("m", "both") else m
        if (g2, m2) != (g, m):
            used.append(name)
            g, m = g2, m2
            if loose(g) == loose(m):
                return used
    return None


# Whole-instruction classes: (name, predicate(gtext, mtext, word, gbad, mbad), reason)
def bits(w, h, l):
    return (w >> l) & ((1 << (h - l + 1)) - 1)


ONLY214 = re.compile(r"\b(COMPU|BITDEP|BITEXT|BFFWRP|EMUIDLE|CJUMP|RFRAME|S\d+)\b|\(LW\)|<->|\(NW\)|\(SW\)")


CLASSES = [
    ("type 2a with an empty compute", lambda g, m, w, gb, mb: not gb and m == "" and bits(w, 47, 40) == 0x01
     and bits(w, 22, 0) == 0,
     "IF cond with compute field 0 is a conditional no-operation (type 2a); MAME prints an empty line"),
    ("VISA-only selector bit 39 in a 48-bit word", lambda g, m, w, gb, mb: gb and not mb and
     bits(w, 47, 40) in (0x01, 0x0A, 0x0B, 0x0D, 0x0F) and bits(w, 39, 39) == 1,
     "bit 39 = 1 selects the 32-bit VISA forms 2b, 11c, 17b (PGR 10-6, 10-18, 10-23) and must be 0 in type 12a's ureg form; "
     "the module rejects such 48-bit words in ISA code, MAME (ADSP-2106x, no VISA) ignores the bit"),
    ("MR transfer opcode not in Table 12-10", lambda g, m, w, gb, mb: gb and not mb and bits(w, 22, 17) == 0x20
     and bits(w, 15, 12) in (3, 7, 8, 9, 10, 11, 12, 13, 14, 15),
     "MR data move opcodes 0011 and 0111-1111 are not listed (PGR 12-9); MAME prints ??? or, off by one, MRxB"),
    ("ADSP-214xx instruction MAME lacks", lambda g, m, w, gb, mb: not gb and (mb or "???" in m) and ONLY214.search(g),
     "COMPU, BITDEP/BITEXT/BFFWRP, EMUIDLE, CJUMP/RFRAME, S registers, Dreg<->CDreg swaps and LW moves are ADSP-214xx additions"),
    ("type 20a with no stack operation", lambda g, m, w, gb, mb: g == "?20" and m == "",
     "type 20a with all of LPU/LPO/SPU/SPO/PPU/PPO/FC clear does nothing; MAME prints an empty line"),
    ("MAME: type 5 field positions", lambda g, m, w, gb, mb: bits(w, 47, 44) == 0b0111,
     "type 5a/5b (PGR 10-9): COND is bits 37-33, source ureg 42-38/32-31, CDreg 41-38, Dreg 26-23; MAME takes the condition from bits 35-31 and misreads the registers"),
    ("MAME: type 7 G bit", lambda g, m, w, gb, mb: bits(w, 47, 40) == 0x04 and bits(w, 39, 39) != bits(w, 38, 38),
     "type 7a (PGR 10-12): G is bit 38 and bit 39 is unused; MAME selects the DAG from bit 39"),
    ("EMUIDLE", lambda g, m, w, gb, mb: g == "EMUIDLE" and m == "NOP",
     "type 22a bit 38 (EMU): ADSP-214xx EMUIDLE, which MAME does not know"),
    ("MAME accepts shift-immediate bit 22", lambda g, m, w, gb, mb: gb and not mb and
     (bits(w, 47, 45) == 0b100 or bits(w, 47, 40) == 0x02) and bits(w, 22, 22) == 1,
     "Table 12-2: bit 22 of a type 6 shift-immediate compute field is 0; MAME ignores it"),
    ("MAME accepts reserved multiplier opcodes", lambda g, m, w, gb, mb: gb and not mb and
     bits(w, 22, 20) == 0b001 and not re.search(MOD, m),
     "Table 12-5: opcodes not listed (01yx f01r destinations, 0001 0xx0, 0010 xxxx...); MAME prints them with no or a partial operand list"),
    ("MAME prints a partial instruction", lambda g, m, w, gb, mb: gb and not mb and re.search(r"= ,|=$|= \Z", m),
     "MAME leaves the operands of an undefined compute opcode empty ('R14 =') instead of rejecting it"),
]


def classify(g, m, w, gb, mb):
    for name, pred, _ in CLASSES:
        if pred(g, m, w, gb, mb):
            return name
    if not gb and not mb:
        used = try_rewrites(g, m, w)
        if used:
            return " + ".join(used)
    return None


def summary(files):
    tot = Counter()
    ex = Counter()
    for f in files:
        for l in open(f):
            m = re.match(r"slots (\d+): exact (\d+), semantic (\d+), both invalid (\d+), explained (\d+), unexplained (\d+)", l)
            if m:
                for k, v in zip(("slots", "exact", "semantic", "invalid", "explained", "unexplained"), m.groups()):
                    tot[k] += int(v)
            m = re.match(r"  explained (.*): (\d+)$", l)
            if m:
                for part in m.group(1).split(" + "):
                    ex[part] += int(m.group(2))
    print(f"   total {tot['slots']} words: exact {tot['exact']}, semantic {tot['semantic']}, both invalid "
          f"{tot['invalid']}, explained {tot['explained']}, unexplained {tot['unexplained']}")
    reasons = {n: r for n, _, _, r in REWRITES} | {n: r for n, _, r in CLASSES}
    for k, v in ex.most_common():
        print(f"   {v:7d}  {k}: {reasons.get(k, '')}")


def main():
    if sys.argv[1] == "--summary":
        summary(sys.argv[2:])
        return
    gfile, mfile, corpus, base = sys.argv[1:5]
    show = int(sys.argv[sys.argv.index("--show") + 1]) if "--show" in sys.argv else 5
    base48 = int(base, 16)
    data = open(corpus, "rb").read()
    gl = [l.rstrip("\n").split(" ", 2) for l in open(gfile)]
    ml = [l.rstrip("\n") for l in open(mfile)]
    assert len(gl) == len(ml) == len(data) // 6, (len(gl), len(ml), len(data) // 6)
    cnt = Counter()
    ex = Counter()
    diffs = defaultdict(list)
    for i, (g, m) in enumerate(zip(gl, ml)):
        w = int.from_bytes(data[6 * i:6 * i + 6], "big")
        mt = m.split(None, 2)[2] if len(m.split(None, 2)) > 2 else ""
        gt = g[2] if len(g) > 2 else ""
        gbad = g[1] == "0"
        # "???" in a register position only (a register code MAME lacks) is not a reject
        mbad = mt in ("", "?") or mt.strip() == "???" or "??? (" in mt or mt.startswith("BIT ???")
        if gbad and mbad:
            cnt["invalid"] += 1
            continue
        gn = "" if gbad else norm_gh(gt)
        mn = "" if mbad else norm_mame(mt, w, base48, i)
        if not gbad and not mbad and gn == mn:
            cnt["exact"] += 1
            continue
        if not gbad and not mbad and loose(gn) == loose(mn):
            cnt["semantic"] += 1
            continue
        c = classify(gn, mn, w, gbad, mbad)
        if c:
            ex[c] += 1
            continue
        key = ("G-only" if mbad else "M-only" if gbad else "diff") + " %02x " % (w >> 40) + signature(gn, mn)
        diffs[key].append((w, gt if not gbad else "BAD", mt if not mbad else mt or "(empty)"))
    total = len(gl)
    print(f"slots {total}: exact {cnt['exact']}, semantic {cnt['semantic']}, both invalid {cnt['invalid']}, "
          f"explained {sum(ex.values())}, unexplained {sum(len(v) for v in diffs.values())}")
    for k, v in sorted(ex.items()):
        print(f"  explained {k}: {v}")
    for k, v in sorted(diffs.items(), key=lambda kv: -len(kv[1])):
        print(f"  DIFF {k}: {len(v)}")
        for w, a, b in v[:show]:
            print(f"     {w:012x}  G: {a}\n                   M: {b}")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
