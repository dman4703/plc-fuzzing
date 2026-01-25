/**
 * @file afl_harness.c
 * @brief AFL++ harness frontend for plcfuzz
 *
 * Environment variables:
 * - PLCFUZZ_TARGET_LIB: path to target plugin .so (preferred)
 * - PLCFUZZ_TARGET:     target name (e.g., openplc_inproc, modbus_tcp)
 * - PLCFUZZ_CONFIG:     optional target config path (e.g., JSON)
 * - PLCFUZZ_VERBOSE:    set to 1 for verbose target logging
 * - PLCFUZZ_ENABLE_TEST_CRASH: set to 1 to enable target test crash knob
 *
 * This harness keeps the fuzzing engine generic: it only sends bytes to a target
 * plugin and reacts to the returned outcome.
 */

#include "core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* AFL++ shared-memory testcase buffer (only available when compiled with afl-cc/afl-clang-fast) */
#ifdef __AFL_COMPILER
__AFL_FUZZ_INIT();
#endif

static const char *resolve_target_lib(void)
{
    const char *lib = getenv("PLCFUZZ_TARGET_LIB");
    if (lib && lib[0])
    {
        return lib;
    }

    const char *name = getenv("PLCFUZZ_TARGET");
    if (name && name[0])
    {
        /* Try typical build layouts */
        static char path1[512];
        static char path2[512];
        snprintf(path1, sizeof(path1), "./targets/libplcfuzz_target_%s.so", name);
        snprintf(path2, sizeof(path2), "./build/targets/libplcfuzz_target_%s.so", name);

        if (access(path1, R_OK) == 0)
        {
            return path1;
        }
        if (access(path2, R_OK) == 0)
        {
            return path2;
        }

        /* Fall back to path1 for error messages */
        return path1;
    }

    return NULL;
}

static bool env_is_truthy(const char *name)
{
    const char *v = getenv(name);
    return v && v[0] && strcmp(v, "0") != 0;
}

int main(void)
{
    const char *target_lib = resolve_target_lib();
    if (!target_lib)
    {
        fprintf(stderr,
                "plcfuzz_afl_harness: missing target. Set PLCFUZZ_TARGET_LIB or PLCFUZZ_TARGET.\n");
        return 1;
    }

    plcfuzz_target_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.config_path = getenv("PLCFUZZ_CONFIG");
    cfg.verbose = env_is_truthy("PLCFUZZ_VERBOSE");
    cfg.enable_test_crash = env_is_truthy("PLCFUZZ_ENABLE_TEST_CRASH");

    plcfuzz_handle_t *h = NULL;
    if (!plcfuzz_load_target(target_lib, &cfg, &h))
    {
        const char *err = plcfuzz_get_error();
        fprintf(stderr, "plcfuzz_afl_harness: failed to load target: %s\n", err ? err : "(unknown)");
        return 1;
    }

    /* If AFL_DEFER_FORKSRV=1 is used, start the forkserver after init/dlopen. */
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    const plcfuzz_target_api_t *api = plcfuzz_get_api(h);
    const size_t max_len = api ? api->max_input_len : 0;

#ifdef __AFL_COMPILER
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(1000))
    {
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
        if (len == 0)
        {
            continue;
        }
        if (max_len > 0 && len > max_len)
        {
            len = max_len;
        }

        plcfuzz_result_t res;
        if (!plcfuzz_run_one(h, buf, len, &res))
        {
            __builtin_trap();
        }

        if (res.outcome == PLCFUZZ_OUTCOME_TARGET_CRASH)
        {
            __builtin_trap();
        }
        else if (res.outcome == PLCFUZZ_OUTCOME_TARGET_HANG)
        {
            for (;;)
            {
                /* Let AFL++ timeout */
            }
        }
        else if (res.outcome == PLCFUZZ_OUTCOME_ERROR)
        {
            __builtin_trap();
        }
    }
#else
    /* Non-AFL build: read a single testcase from stdin and run once. */
    uint8_t buf[1024 * 1024];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n > 0)
    {
        size_t len = (size_t)n;
        if (max_len > 0 && len > max_len)
        {
            len = max_len;
        }
        plcfuzz_result_t res;
        if (!plcfuzz_run_one(h, buf, len, &res))
        {
            fprintf(stderr, "plcfuzz_afl_harness: target run failed\n");
            plcfuzz_unload_target(h);
            return 2;
        }
        fprintf(stderr, "plcfuzz_afl_harness: outcome=%d feedback_len=%zu\n", (int)res.outcome, res.feedback_len);
    }
#endif

    plcfuzz_unload_target(h);
    return 0;
}

