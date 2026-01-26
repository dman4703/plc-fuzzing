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


CORE_PATTERN_FILE="/proc/sys/kernel/core_pattern"
CORE_PATTERN_BAK="/tmp/core_pattern.bak.plcfuzz_modbus.$$"
CORE_PATTERN_CHANGED=0

restore_core_pattern() {
  if [ "${CORE_PATTERN_CHANGED}" -ne 1 ]; then
    return 0
  fi

  if [ -f "${CORE_PATTERN_BAK}" ]; then
    local old
    old="$(cat "${CORE_PATTERN_BAK}" 2>/dev/null || true)"
    if [ -n "${old}" ]; then
      if [ "${EUID}" -eq 0 ]; then
        echo "${old}" > "${CORE_PATTERN_FILE}" || true
      else
        echo "${old}" | sudo tee "${CORE_PATTERN_FILE}" >/dev/null || true
      fi
    fi
    rm -f "${CORE_PATTERN_BAK}" || true
  fi
}

if [ -r "${CORE_PATTERN_FILE}" ]; then
  CORE_PATTERN_OLD="$(cat "${CORE_PATTERN_FILE}" || true)"
  if [ "${CORE_PATTERN_OLD}" != "core" ]; then
    echo "[+] Temporarily setting core_pattern to 'core' (was: ${CORE_PATTERN_OLD})"
    echo "${CORE_PATTERN_OLD}" > "${CORE_PATTERN_BAK}"
    if [ "${EUID}" -eq 0 ]; then
      echo core > "${CORE_PATTERN_FILE}"
    else
      echo core | sudo tee "${CORE_PATTERN_FILE}" >/dev/null
    fi
    CORE_PATTERN_CHANGED=1
    trap restore_core_pattern EXIT INT TERM
  fi
fi

MAX_LEN="${AFL_MAX_LEN:-128}"
afl-fuzz -G "${MAX_LEN}" -i "${IN_DIR}" -o "${OUT_DIR}" -- "${PLCFUZZ_BUILD_DIR}/plcfuzz_afl_harness"

