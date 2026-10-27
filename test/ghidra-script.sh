#!/usr/bin/env bash
# Import a file into a throw-away headless Ghidra project and run one postScript from test/.
#   BASE_ADDR=0x1000 test/ghidra-script.sh raw <language-id> <file> <Script.java> [script args...]
#   test/ghidra-script.sh auto -            <file> <Script.java> [script args...]   (loader picks the language, analysis on)
#   test/ghidra-script.sh auto-noanalysis - <file> <Script.java> [script args...]
set -euo pipefail
MODE=$1 LANG_ID=$2
BIN=$(readlink -f "$3")
SCRIPT=$4
shift 4
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/sharc-gs.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
case $MODE in
raw) IMP=(-loader BinaryLoader -loader-baseAddr "${BASE_ADDR:-0}" -processor "$LANG_ID" -noanalysis) ;;
auto-noanalysis) IMP=(-noanalysis) ;;
*) IMP=() ;;
esac
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" "${IMP[@]}" \
	-scriptPath "$HERE" -postScript "$SCRIPT" "$@" -deleteProject >"$PROJ/log.txt" 2>&1 ||
	{ tail -40 "$PROJ/log.txt" >&2; exit 1; }
# (emulator traps log UnimplementedCallOtherException lines by design: they are not script errors)
if grep -qE "SCRIPT ERROR|Exception in thread" "$PROJ/log.txt"; then
	grep -E -A5 "SCRIPT ERROR|Exception in thread" "$PROJ/log.txt" | head -40 >&2
	exit 1
fi
