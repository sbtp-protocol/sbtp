"""Checks the core WASM budget of ADR 0048 ("Budgets": under 200,000 bytes gzip) on the output of
`cargo build -p sbtp-wasm --target wasm32-unknown-unknown --release`, without the wasm-bindgen CLI
or binaryen.

  python3 -I web/wasm-budget.py <module.wasm> [budget-bytes]

The module is copied without its custom sections (section id 0: `name`, `producers`,
`target_features` and the wasm-bindgen descriptors' metadata), which `web/build.sh` drops too, then
gzip-compressed at level 9 as `web/build.sh` reports it. What remains still holds the wasm-bindgen
descriptor functions and has not been through `wasm-opt -Os`, both of which only make the shipped
`web/pkg/sbtp_wasm_bg.wasm` smaller: this figure is an upper bound of the shipped size, so a pass
here is a pass of the budget. The script reads the file only; it runs nothing.
"""

import gzip
import sys


def leb128(data: bytes, pos: int) -> tuple[int, int]:
    value, shift = 0, 0
    while True:
        if pos >= len(data) or shift > 35:
            raise ValueError("bad LEB128")
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if b < 0x80:
            return value, pos


def strip_custom(data: bytes) -> bytes:
    if data[:8] != b"\0asm\x01\0\0\0":
        raise ValueError("not a WebAssembly 1.0 module")
    out, pos = bytearray(data[:8]), 8
    while pos < len(data):
        start = pos
        section_id = data[pos]
        size, body = leb128(data, pos + 1)
        end = body + size
        if end > len(data):
            raise ValueError("truncated section")
        if section_id != 0:
            out += data[start:end]
        pos = end
    return bytes(out)


def main() -> int:
    path = sys.argv[1]
    budget = int(sys.argv[2]) if len(sys.argv) > 2 else 200_000
    with open(path, "rb") as f:
        raw = f.read()
    stripped = strip_custom(raw)
    gz = len(gzip.compress(stripped, compresslevel=9, mtime=0))
    print(
        f"{path}: {len(raw)} bytes, {len(stripped)} without custom sections, "
        f"{gz} gzip -9 (budget: below {budget}; upper bound of web/pkg/sbtp_wasm_bg.wasm)"
    )
    if gz >= budget:
        print(f"::error::core wasm is {gz} bytes gzip (upper bound), budget is below {budget}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
