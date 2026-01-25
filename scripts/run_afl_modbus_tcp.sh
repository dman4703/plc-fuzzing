#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v afl-fuzz >/dev/null 2>&1; then
  echo "[!] afl-fuzz not found in PATH. Install AFL++ first: https://aflplus.plus/docs/install/" >&2
  exit 1
fi

PLCFUZZ_BUILD_DIR="${PLCFUZZ_BUILD_DIR:-${ROOT_DIR}/build-plcfuzz-modbus-afl}"
IN_DIR="${IN_DIR:-${ROOT_DIR}/in}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out-modbus}"

# Config file for the Modbus/TCP target plugin
PLCFUZZ_CONFIG="${PLCFUZZ_CONFIG:-${ROOT_DIR}/plcfuzz/targets/modbus_tcp/config.openplc.example.json}"

echo "[+] Building plcfuzz (AFL-instrumented) into: ${PLCFUZZ_BUILD_DIR}"
rm -rf "${PLCFUZZ_BUILD_DIR}"
CC=afl-clang-fast CXX=afl-clang-fast++ cmake -S "${ROOT_DIR}" -B "${PLCFUZZ_BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${PLCFUZZ_BUILD_DIR}" -j"$(nproc)"

export PLCFUZZ_TARGET_LIB="${PLCFUZZ_BUILD_DIR}/targets/libplcfuzz_target_modbus_tcp.so"
export PLCFUZZ_CONFIG="${PLCFUZZ_CONFIG}"

echo "[+] Running AFL++ (Modbus/TCP black-box)"
echo "    in : ${IN_DIR}"
echo "    out: ${OUT_DIR}"
echo "    bin: ${PLCFUZZ_BUILD_DIR}/plcfuzz_afl_harness"
echo "    cfg: ${PLCFUZZ_CONFIG}"

MAX_LEN="${AFL_MAX_LEN:-128}"
afl-fuzz -G "${MAX_LEN}" -i "${IN_DIR}" -o "${OUT_DIR}" -- "${PLCFUZZ_BUILD_DIR}/plcfuzz_afl_harness"

