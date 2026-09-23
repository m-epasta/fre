#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

echo "== rust: tests =="
cargo test
echo "== rust: clippy =="
cargo clippy --all-targets

if cargo audit --version >/dev/null 2>&1; then
    echo "== rust: cargo audit =="
    cargo audit
else
    echo "== cargo audit not installed; skipping dependency scan =="
fi

echo "== c: tests (incl. RFC 4231 HMAC KATs, ctx bound) =="
make -C c test

echo "== c: ASan/UBSan tests + build =="
make -C c sanitize

echo "== rust<->c differential fuzz =="
make -C c difftest
mkdir -p target/difftest_in
cargo run --release --quiet --example difftest -- 20000 >target/difftest_in/cases.txt
echo "-- c/difftest --"
./c/difftest <target/difftest_in/cases.txt
echo "-- c/difftest_asan --"
./c/difftest_asan <target/difftest_in/cases.txt

echo "ALL CHECKS PASSED"
