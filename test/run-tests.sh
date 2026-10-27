#!/usr/bin/env bash
# SHARC module test suite (Ghidra-Rare): everything that needs no downloaded inputs.
#
#   GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x> test/run-tests.sh [workdir] [--real]
#
# 1. the generator reproduces the checked-in SLEIGH (tools/gen_sinc.py)
# 2. the spec compiles (.sla well under 16 MB)
# 3. decode:
#    a. 48-bit ISA words against MAME unidasm -arch sharc (ADSP-2106x): every value of bits 47..32,
#       the branch types with every J/E/CI setting, every compute opcode under six carriers, empty
#       computes and random words; compare.py classes every difference and fails on an unexplained one
#    b. the multiplier opcodes against a transcription of PGR Tables 12-5..12-9 (mult_check.py)
#    c. VISA (no reference tool knows it): 48-bit VISA = ISA, 32-bit forms = ISA without the compute,
#       type 2b = type 2a IF TRUE (visa_check.py), every 16-bit parcel against its ISA equivalent (visa16.py)
# 4. every SLEIGH constructor is reached by those corpora (with the loop-end and delay-slot contexts swept)
# 5. p-code: hand-computed emulator tests (EmuCheck.java), including a deliberately wrong expectation
# --real adds step 6 (test/real-binaries.sh).
#
# Environment: GHIDRA_INSTALL_DIR (a scratch Ghidra 12.1.x or 12.2; the module is symlinked into its
# Ghidra/Processors/SHARC), JAVA_HOME (optional), UNIDASM (MAME's unidasm), PROJ_DIR (where the
# throw-away Ghidra projects go; its path must not contain a component starting with '.').
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a scratch Ghidra 12.1.x}"
REAL=0
ARGS=()
for a in "$@"; do if [[ $a == --real ]]; then REAL=1; else ARGS+=("$a"); fi; done
W=$(readlink -m "${ARGS[0]:-${TMPDIR:-/tmp}/sharc-tests}")
mkdir -p "$W"
UNIDASM=${UNIDASM:-$(command -v unidasm || true)}
export GHIDRA_INSTALL_DIR
fail=0
LANGID=SHARC:BE:32:214xx
GS() { BASE_ADDR=0x100000 "$HERE/ghidra-script.sh" raw $LANGID "$@"; }

echo "== 1. generator reproduces the checked-in spec"
python3 "$MOD/tools/gen_sinc.py" "$W/gen.sinc" >/dev/null
cmp "$W/gen.sinc" "$MOD/data/languages/sharc214xx.sinc"

echo "== 2. SLEIGH compiles"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/sharc214xx.slaspec" 2>&1 | grep -E "^ERROR|^Error" && exit 1 || true
sz=$(stat -c %s "$MOD/data/languages/sharc214xx.sla")
echo "   sharc214xx.sla: $sz bytes"
((sz < 16 * 1024 * 1024))
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/SHARC"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi

echo "== 3. decode"
python3 "$HERE/gen_corpus.py" "$W/c" 40000 1
rm -f "$W"/gh.0? "$W"/mame.0?
split -b $((100000 * 6)) -d "$W/c.gh" "$W/gh."
split -b $((100000 * 8)) -d "$W/c.mame" "$W/mame."
chunks=$(cd "$W" && ls gh.0? | sed 's/gh\.//')
for c in $chunks; do GS "$W/gh.$c" DumpSlots.java "$W/gh.$c.txt" 6 ctx:visa=0 & done
wait
cat $(for c in $chunks; do echo "$W/gh.$c.txt"; done) > "$W/isa.txt"
if [[ -n $UNIDASM ]]; then
	echo "-- 3a. ISA against MAME unidasm -arch sharc"
	for c in $chunks; do
		"$UNIDASM" "$W/mame.$c" -arch sharc -basepc 0x80000 > "$W/mame.$c.txt"
		python3 "$HERE/compare.py" "$W/gh.$c.txt" "$W/mame.$c.txt" "$W/gh.$c" 0x80000 --show 4 > "$W/compare.$c.txt" || fail=1
		head -1 "$W/compare.$c.txt"
	done
	python3 "$HERE/compare.py" --summary "$W"/compare.0?.txt
else
	echo "-- 3a. skipped (no unidasm)"
fi
echo "-- 3b. multiplier opcodes against the manual's tables"
python3 "$HERE/mult_check.py" "$W/isa.txt" "$W/c.gh" || fail=1
echo "-- 3c. VISA"
NV=$(cat "$W/c.nvisa")
head -c $((NV * 6)) "$W/c.gh" > "$W/isa1.gh"
head -n "$NV" "$W/isa.txt" > "$W/isa1.txt"
python3 "$HERE/visa_corpus.py" "$W/isa1.gh" "$W/vc"
python3 "$HERE/visa16.py" gen "$W/v16"
GS "$W/vc.isa" DumpSlots.java "$W/vc.isa.txt" 6 ctx:visa=0 &
GS "$W/vc.v48" DumpSlots.java "$W/vc.v48.txt" 6 ctx:visa=1 &
GS "$W/vc.v32" DumpSlots.java "$W/vc.v32.txt" 6 ctx:visa=1 &
GS "$W/vc.v2b" DumpSlots.java "$W/vc.v2b.txt" 6 ctx:visa=1 &
GS "$W/vc.v2bisa" DumpSlots.java "$W/vc.v2bisa.txt" 6 ctx:visa=0 &
GS "$W/v16.v16" DumpSlots.java "$W/v16.txt" 6 ctx:visa=1 &
GS "$W/v16.isa" DumpSlots.java "$W/v16.isa.txt" 6 ctx:visa=0 &
wait
python3 "$HERE/visa_check.py" "$W/isa1.txt" "$W/vc.isa.txt" "$W/vc.v48.txt" "$W/vc.v32.txt" "$W/isa1.gh" \
	"$W/vc.v2b.txt" "$W/vc.v2bisa.txt" | tee "$W/visa.txt" | tail -1
grep -q " 0 mismatches" "$W/visa.txt" || { cat "$W/visa.txt"; fail=1; }
python3 "$HERE/visa16.py" check "$W/v16" "$W/v16.txt" "$W/v16.isa.txt" || fail=1

echo "== 4. every constructor is reached"
head -c $((4096 * 6)) "$W/c.gh" > "$W/small.gh"
GS "$W/c.gh" Reach.java "$W/r1.txt" 6 ctx:visa=0 &
GS "$W/vc.v48" Reach.java "$W/r2.txt" 6 ctx:visa=1 sweep:dslot:0:3 &
GS "$W/vc.v32" Reach.java "$W/r3.txt" 6 ctx:visa=1 sweep:dslot:0:3 &
GS "$W/v16.v16" Reach.java "$W/r4.txt" 6 ctx:visa=1 &
GS "$W/small.gh" Reach.java "$W/r5.txt" 6 ctx:visa=0 ctx:lend=1 sweep:lterm:0:31 &
GS "$W/vc.v2b" Reach.java "$W/r6.txt" 6 ctx:visa=1 &
GS "$W/c.gh" Reach.java "$W/r7.txt" 6 ctx:visa=0 ctx:brm0=1 ctx:brm8=1 &
wait
cat "$W"/r?.txt | sort -u > "$W/reach.txt"
python3 "$HERE/reach.py" "$MOD/data/languages" "$W/reach.txt" || fail=1

echo "== 5. p-code: emulator tests"
mkdir -p "$W/emu"
python3 "$HERE/emu_tests.py" "$W/emu"
GS "$W/emu/emu.bin" EmuCheck.java "$W/emu/tests.txt" "$W/emu/out.txt" $(cat "$W/emu/ctx.txt")
echo "   $(tail -1 "$W/emu/out.txt")"
grep -q ", 0 failed" "$W/emu/out.txt" || { grep -v "^PASS" "$W/emu/out.txt" | head -20; fail=1; }

if ((REAL)); then
	echo "== 6. real code"
	"$HERE/real-binaries.sh" "$W/real" || fail=1
fi

if ((fail)); then echo "FAILED"; exit 1; fi
echo "all tests passed"
