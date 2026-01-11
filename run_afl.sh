#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENPLC_DIR="${ROOT_DIR}/openplc-runtime"

if ! command -v afl-fuzz >/dev/null 2>&1; then
  echo "[!] afl-fuzz not found in PATH. Install AFL++ first: https://aflplus.plus/docs/install/" >&2
  exit 1
fi

# Keep fuzz build artifacts isolated from any normal OpenPLC build.
OPENPLC_BUILD_DIR="${OPENPLC_BUILD_DIR:-${OPENPLC_DIR}/build-afl}"

echo "[+] Building OpenPLC core (FUZZING=ON) into: ${OPENPLC_BUILD_DIR}"
rm -rf "${OPENPLC_BUILD_DIR}"
CC=afl-clang-fast CXX=afl-clang-fast++ cmake -S "${OPENPLC_DIR}" -B "${OPENPLC_BUILD_DIR}" -DFUZZING=ON
cmake --build "${OPENPLC_BUILD_DIR}" -j"$(nproc)"

echo "[+] Building AFL-instrumented PLC program (libplc_*.so)"
(cd "${OPENPLC_DIR}" && \
  OPENPLC_BUILD_DIR="${OPENPLC_BUILD_DIR}" CC=afl-clang-fast CXX=afl-clang-fast++ bash ./scripts/compile.sh && \
  OPENPLC_BUILD_DIR="${OPENPLC_BUILD_DIR}" bash ./scripts/compile-clean.sh)

LIBPLC="$(ls -1 "${OPENPLC_BUILD_DIR}"/libplc_*.so | head -n 1)"
echo "[+] Using PLC program library: ${LIBPLC}"

IN_DIR="${ROOT_DIR}/in"
OUT_DIR="${ROOT_DIR}/out"

if [ ! -d "${IN_DIR}" ]; then
  echo "[!] Missing seed corpus directory: ${IN_DIR}" >&2
  echo "    Create it (or re-run repo setup) before fuzzing." >&2
  exit 1
fi

# AFL++ note: the PLC program is loaded via dlopen(). To get coverage for an instrumented
# dlopen()'ed library, preload it so AFL sees it before forkserver startup.
export AFL_PRELOAD="${LIBPLC}"
export OPENPLC_BUILD_DIR="${OPENPLC_BUILD_DIR}"

CORE_PATTERN_FILE="/proc/sys/kernel/core_pattern"
CORE_PATTERN_BAK="/tmp/core_pattern.bak.openplc_fuzz.$$"
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

echo "[+] Running AFL++"
echo "    in : ${IN_DIR}"
echo "    out: ${OUT_DIR}"
echo "    bin: ${OPENPLC_BUILD_DIR}/openplc_fuzz_target"

cd "${OPENPLC_DIR}"
MAX_LEN="${AFL_MAX_LEN:-20}"
afl-fuzz -G "${MAX_LEN}" -i "${IN_DIR}" -o "${OUT_DIR}" -- "${OPENPLC_BUILD_DIR}/openplc_fuzz_target"

