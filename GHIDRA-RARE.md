# Ghidra-Rare notes: Analog Devices ADSP-214xx SHARC

Fork of [roblg/ghidra-sharc](https://github.com/roblg/ghidra-sharc) (Apache-2.0, see `CREDITS.md`),
verified and extended by Ghidra-Rare. Extension name `SHARC`, language ID `SHARC:BE:32:214xx`
(ADSP-21467/21469, 21477-21479, 21483-21489: the 48-bit ISA and the 16/32/48-bit VISA). SHARC+
(ADSP-2156x/SC5xx) is not covered.

## What it covers

Every instruction type of the *SHARC Processor Programming Reference* (rev 2.4, chapters 9-12) in
ISA and VISA encodings, with the upstream model (short-word code space with 48-bit code at its
alias, hardware loops as context, delay slots per the Delay Slot analyzer). Ghidra-Rare rewrote
the semantics from the manual (status and sticky flags, saturation, float special values and
denormal flush, FIX/TRUNC rounding modes, the 80-bit MR accumulators, the bit FIFO, circular
buffering, bit-reverse addressing, long-word moves, the PC/loop/status stacks), added SIMD mode
(`simd` context: the PEy half of every instruction), a loader for CrossCore/VisualDSP++
executables (.dxe) and the SHARC SIMD Mode analyzer. Run-time mode bits that change decoding or
data flow are context assumptions: `simd` (MODE1 PEYEN), `brm0`/`brm8` (MODE1 BR0/BR8); the
compiler spec tracks MODE1 at its C run-time value so compiled code decompiles cleanly, while
code that changes MODE1 locally (e.g. TRUNC around a FIX) is followed.

## How to test

    GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x or 12.2 with this module in Ghidra/Processors/SHARC> \
      PROJ_DIR=<dir without a dot component> test/run-tests.sh [workdir] [--real]

Needs MAME's `unidasm` and Python 3; `--real` downloads the test executable (pinned commit and
SHA-256, never committed) and, if `SELDUMP` points to selache's `seldump` (built with cargo from
https://github.com/js216/selache), compares the disassembly with it.

## Results

| Area | Result |
|---|---|
| Builds | Specs compile on Ghidra 12.1.3, 12.1.4 and 12.2 (`tools/build-module.sh --standard --name SHARC`); `.sla` 1.1 MB |
| Decode vs MAME `unidasm -arch sharc` (ADSP-2106x) | 298,048 48-bit words (every value of bits 47..32 twice, every branch type with every J/E/CI setting, types 9a/9b bits 31..24 in full, every compute field under six carriers including the C return idiom, every bits 47..32 with an empty compute, 40,000 random): 17,429 identical, 108,452 same after spelling rules, 81,693 invalid in both, 90,474 in 21 explained classes, 0 unexplained |
| Decode vs the manual's tables | 2,048 multiplier opcodes against Tables 12-5..12-9: 0 mismatches; VISA: 151,552 words as 48-bit VISA = ISA and 32-bit forms = ISA without the compute (0 mismatches), 6,529 16-bit parcels against their ISA equivalents (0 mismatches) |
| Every constructor reached | 3,862/3,862 (with the loop-end, delay-slot, bit-reverse and SIMD contexts swept) |
| Semantics | 51 hand-computed emulator programs pass (fixed and float ALU flags, saturation, carries, CACC, AVG, FIX/TRUNC modes, SCALB/MANT/LOGB, denormal flush, multiplier integer/fraction/MAC/SAT/rounding, shifts and field ops, FPACK/FUNPACK, bit FIFO, DAG post-modify, circular buffers, MODIFY wrap, LW store, CALL/RTS and CALL (DB) in ISA and VISA, DO UNTIL LCE / condition, conditional skip, PUSH/POP STS, VISA short computes, and ten SIMD programs: both-PE ALU flags, MAC into MSF, per-PE conditional compute, branch on the AND of both PEs, implicit +1/+2 memory transfers, complementary ureg pairs, conditional swap, ELSE per PE, MODIFY on the OR, BIT TST); a deliberately wrong expectation is reported |
| Real code | `image_segmentation.dxe` (CrossCore for the ADSP-21489, MIT): DXE loader + full analysis, 9,060 instructions, 210 functions, 0 bad-instruction/error bookmarks, 209/209 functions decompile. Against selache's `seldump` at the same addresses: 9,225 instructions, 7,720 identical, 1,043 in 13 explained classes, 0 unexplained; 261 lie inside a module instruction (after one of the 58 length disagreements, all seldump errors) and 201 are not disassembled by the module (43 unreachable IVT padding words, 158 in two run-time stub tables entered through computed jumps, below) |

## Doesn't work (and why)

- **Run-time modes are context, not dynamic**: SIMD (`simd`) and bit-reverse (`brm0`/`brm8`)
  follow the context, not MODE1 at run time, because the instruction decoding and the decompiler
  need them statically. The SIMD Mode analyzer sets `simd` between `BIT SET/CLR MODE1 PEYEN` in
  address order within a function; other mode changes need the context set by hand. Broadcast
  load mode (MODE1 BDCST1/BDCST9) is not modelled.
- **40-bit extended precision** (MODE1 RND32 clear): registers are 32 bits. P-code has no float
  type for the 40-bit SHARC format (8-bit exponent, 31-bit fraction), so every float operation
  would need a software implementation; the C run time always runs with RND32 set.
- **IDLE, EMUIDLE, FLUSH CACHE** are user operations (core halt and cache state).
- **RTI does not pop the status stack**: the push happens on interrupt entry, which is not an
  instruction; interrupt and SIMD exception behaviour is not modelled.
- **RECIPS/RSQRTS** give the exact reciprocal (square root), not the hardware seed: the seed
  table is not published.
- **Delay slots** in VISA code are right only after the SHARC Delay Slot analyzer (Ghidra collects
  delay slots by byte count and VISA instructions are 2, 4 or 6 bytes).
- **A loop whose end lies before its DO** (the boot kernel's FINAL_INIT sequence): the DO's
  context mark conflicts with the existing decoding (one context value per address).
- **Code pointers held as 48-bit addresses in data** are not mapped to the code space by
  Ghidra's pointer analysis; computed calls are mapped in p-code.
- **Computed jumps into stub tables** (`I13 = base + 5*n; JUMP (M13, I13)` into a table of
  `BIT SET IMASK n; JUMP (M14, I12)` stubs in the CrossCore run time): the decompiler's
  jump-table recovery cannot follow a table of code with two possible bases, so those stubs are
  not disassembled automatically.
- **Loaders**: MULTI_PROC boot streams are not supported (no freely licensed sample to test
  with); relocatable objects (.doj) are refused (executables have no relocations); DWARF in .dxe
  files is not imported (ADI's DWARF register numbering and address units are unpublished).
- **Decompiler readability**: float operations show the NaN canonicalisation and denormal flush
  explicitly; that is the hardware behaviour.

## Unverified

No ADSP-214xx hardware or simulator was available. The semantics follow the manual and were
checked by hand-computed emulator programs only; where the manual is ambiguous the choice is
documented in `tools/gen_sinc.py` and the slaspec (dual add/subtract flags, SIMD details such as
the PEy bit FIFO, (LW) moves under a SIMD condition, bit-reverse plus SIMD implicit address).
MAME's SHARC disassembler is the ADSP-2106x and does not know VISA or the 214xx additions; VISA
is checked only for consistency with the ISA decode. The internal memory map and IVT are those of
the 5-Mbit parts; the 3-Mbit parts' maps were not checked. The real-code check uses one
executable.

## Confirmed reference-tool bugs

MAME `unidasm -arch sharc` (ADSP-2106x): type 5a/5b condition and register fields (it reads COND
from bits 35-31), type 7a selects the DAG from bit 39 instead of 38, R/F letters of FLOAT/FIX/RND
(`FLOAT Fx BY Fy`, `FIX Fx BY Fy`, `RND Rx`), prints (LR) for RTI, accepts reserved multiplier
opcodes and shift-immediate bit 22, MR data move opcodes off by one for the B registers.

selache `seldump` (SHARC+ tool) on ADSP-214xx code: type 3/4/15/16 DAG fields (U inverted in
some forms, M read from the wrong bits, G ignored, D inverted in type 4), types 7a and 16a in VISA
code decoded with the wrong length, type 6a condition dropped, shift-immediate opcodes (ASHIFT
shown as LSHIFT, OR forms dropped, FEXT bit6 above 63), short compute OP 0111 shown as
`Rn = Rn + Rx + CI` (the manual: `Rn = Rn * Rx (SSI)`), system register codes 0x70-0x7f named
from another table (0x76 STKYY for ASTATx, SREG 5 MODE1 for FLAGS), type 5 source register,
type 19a operation and DAG, CJUMP's PC-relative offset printed as an absolute address. Real code
confirms the module in each case examined (`_status_led` sets FLAGS bits for its LEDs, `M3`
computed just before `DM(M3,I4)`, `DM(I7,M7) = PCSTK` pushes, branch targets land on the
module's instruction boundaries).
