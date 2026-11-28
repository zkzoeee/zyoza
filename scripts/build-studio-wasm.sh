#!/bin/sh
# Builds the browser prover used by Zyoza Studio into apps/gallery-demo/wasm.
# Needs the wasm32-unknown-unknown target and either wasm-pack or wasm-bindgen-cli.
set -eu
cd "$(dirname "$0")/.."
OUT="$(pwd)/apps/gallery-demo/wasm"
mkdir -p "$OUT"

if command -v wasm-pack >/dev/null 2>&1; then
  wasm-pack build crates/zyoza-studio-prover --release --target web \
    --no-typescript --no-pack --out-dir "$OUT"
else
  cargo build --release -p zyoza-studio-prover --target wasm32-unknown-unknown
  wasm-bindgen --target web --no-typescript --out-dir "$OUT" \
    target/wasm32-unknown-unknown/release/zyoza_studio_prover.wasm
fi

rm -f "$OUT/.gitignore"
gzip -9 -k -f "$OUT/zyoza_studio_prover_bg.wasm"
ls -la "$OUT"
