#!/usr/bin/env bash
# Real-code run: a CrossCore Embedded Studio executable for the ADSP-21489, imported with the
# module's DXE loader and full auto-analysis; counts of instructions, functions, bookmarks and
# decompile failures; every instruction seldump lists compared with the module at the same address.
#   test/real-binaries.sh <workdir>
# Download (pinned URL + SHA-256, never committed): image_segmentation.dxe from
# github.com/alexBeslic/image_segmentation (MIT; built by its author with CCES 2.10 / linker 6.3.6.4).
# Oracle (optional, black box): seldump from selache (github.com/js216/selache, GPL-3.0), built with
# cargo; set SELDUMP or put it on PATH.  Without it only the counts are checked.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "${1:?workdir}")
mkdir -p "$W/dl"
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
SELDUMP=${SELDUMP:-$(command -v seldump || true)}
REPO=alexBeslic/image_segmentation
COMMIT=557d20fc7fa6d5b1b0a3ae8928f7a11a695125ae
SHA=5ae66ab4a1d26a434b7bce6d9bf0c90b608b9539b4d004dd4770bf6d4c378d85
F=$W/dl/image_segmentation.dxe
[[ -f $F ]] || curl -sSL -o "$F" "https://raw.githubusercontent.com/$REPO/$COMMIT/Debug/image_segmentation.dxe"
echo "$SHA  $F" | sha256sum -c - >/dev/null

fail=0
"$HERE/ghidra-script.sh" auto - "$F" RealCheck.java "$W/seg.sum" "$W/seg.lst" 100000
grep -E "^(executable format|instructions|functions|bookmark|decompiled)" "$W/seg.sum" | sed 's/^/   /'
grep -q "^executable format ADI SHARC Executable (DXE)" "$W/seg.sum" || { echo "DXE loader not used"; fail=1; }
if grep -qE "^(Error|Warning)/" "$W/seg.sum"; then grep -E "^(Error|Warning)/" "$W/seg.sum" | head; fail=1; fi
grep -q "failed 0 " "$W/seg.sum" || fail=1
n=$(sed -n 's/^functions //p' "$W/seg.sum")
((n >= 200)) || { echo "only $n functions"; fail=1; }
if [[ -n $SELDUMP ]]; then
	"$SELDUMP" -all "$F" >"$W/seg.seldump" 2>&1
	python3 "$HERE/real_compare.py" "$W/seg.seldump" "$W/seg.lst" --show 3 >"$W/seg.compare" || fail=1
	sed 's/^/   /' "$W/seg.compare" | head -20
else
	echo "   (no seldump: disassembly comparison skipped)"
fi
exit $fail
