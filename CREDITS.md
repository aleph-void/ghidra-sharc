# Credits

## Upstream

- Repository: https://github.com/roblg/ghidra-sharc
- Commit: `f4ebdfa7865241249dc8c918291ee55ea4af5a13` ("CI: keep the Ghidra release out of the
  extension zip", 2026-10-07), the GitHub HEAD when this fork was made
- License: Apache License 2.0 (`LICENSE`, unchanged); upstream's `NOTICE.md` lists its sources
- Author: Robert Gay (GitHub @roblg), the only author in the upstream history

Upstream wrote the SLEIGH generator (`tools/gen_sinc.py`, `tools/sharc_isa.py`), the hand-written
`sharc214xx.slaspec`, the boot-stream (.ldr) loader, the Delay Slot, Loop End, Call Idiom and
Function Pointer Arguments analyzers, and the smoke tests in `tests/`.

Not merged here: upstream's open pull request #1 (SHARC+ / ADSP-2156x support, by @rjmendez),
which is unmerged upstream and outside this module's ADSP-214xx scope.

## Ghidra-Rare changes (branch `ghidra-rare`)

Every change is a separate commit on top of the upstream commit above.

Decode (found by the MAME differential and the manual's opcode figures):
- Branch targets: only 48-bit addresses 0x80000-0xfffff map to their short-word alias.
- Type 6: FPACK/FUNPACK show the F register.
- Multiplier: SAT MRF (UI) is opcode 0x00; reserved mod1 forms are invalid.
- VISA: the 16-bit EMUIDLE (type 22c).
- Shifter: BITEXT takes only the bit count (`Rn = BITEXT Ry`).

Semantics (written from the SHARC Processor Programming Reference rev 2.4):
- Status flags as bit ranges of ASTATx/STKYx/MODE1/FLAGS; every ALU, multiplier and shifter flag
  and sticky bit; ALUSAT saturation, carries, CACC; floating-point NaN, denormal flush, FIX/TRUNC
  modes and saturation, SCALB/MANT/LOGB/COPYSIGN/RECIPS/RSQRTS/FPACK/FUNPACK as p-code; the
  80-bit MR accumulators with rounding and SAT; all shifter forms and the bit FIFO.
- DAG circular buffering and bit-reverse addressing, long-word moves; the PC, loop-address,
  loop-counter and status stacks; CALL (DB) return addresses in VISA code (`dslot2`, set by the
  Delay Slot analyzer).
- SIMD mode: the `simd` context bit and the PEy half of every instruction (registers S0-S15,
  MSF/MSB, ASTATy/STKYy, complementary memory transfers, per-PE conditions).
- Compiler spec: L registers and MODE1 tracked at their C run-time values; hardware registers
  (FLAGS, IMASK, IMASKP, IRPTL, LRPTL, MMASK, MODE2) are globals.

New components:
- `SharcDxeLoader`: VisualDSP++ / CrossCore executables (.dxe, ELF e_machine 0x85).
- `SharcSimdModeAnalyzer`: sets `simd` between `BIT SET/CLR MODE1 PEYEN`.

Build and tests:
- `build.gradle`: `copyDependencies` disabled (it copied other modules' jars into `lib/`),
  `test/` excluded from the zip.
- `test/`: the Ghidra-Rare test suite (`run-tests.sh`), see GHIDRA-RARE.md.
- `README.md`: limitation list and stale claims updated; pointer to GHIDRA-RARE.md.
- `GHIDRA-RARE.md`, `CREDITS.md`: added.

## Sources used by the Ghidra-Rare work

- Analog Devices, *SHARC Processor Programming Reference* (ADSP-2136x/2137x/214xx), rev 2.4:
  encodings (ch. 10, 12), semantics (ch. 3, 4, 6, 7, 9, 11), register tables (appendix A).
  Not redistributed.
- MAME `unidasm -arch sharc` (ADSP-2106x disassembler), run as a black box for the decode
  differential.
- selache (https://github.com/js216/selache, GPL-3.0, Jakob Kastelic): its `seldump` was run as
  a black box on a real executable; its source was not read.
- The real executable for testing (fetched, not included): `image_segmentation.dxe` from
  https://github.com/alexBeslic/image_segmentation (MIT, Aleksandar Beslic).
- The C run-time MODE1 value tracked by the compiler spec was read from that executable's
  start-up code (`___lib_setup_c`).
