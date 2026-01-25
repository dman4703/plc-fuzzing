/**
 * @file openplc_inproc_target.c
 * @brief OpenPLC in-process target plugin for plcfuzz
 *
 * This plugin reuses the existing OpenPLC in-process harness logic, but exposes it
 * through the generic TargetAPI so the fuzzing engine stays transport/target-agnostic.
 */

#include "plcfuzz_target_api.h"

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "image_tables.h"
#include "plcapp_manager.h"
#include "utils/log.h"
#include "utils/utils.h"

/* Required by OpenPLC logging implementation (utils/log.c) */
volatile sig_atomic_t keep_running = 1;

/* Keep input small and deterministic, matching the original harness */
#define OPENPLC_FUZZ_MAX_WORDS 8
#define OPENPLC_FUZZ_BOOL_OFFSET_BYTES (OPENPLC_FUZZ_MAX_WORDS * 2)
#define OPENPLC_FUZZ_BOOL_BYTES 4
#define OPENPLC_FUZZ_MAX_INPUT (OPENPLC_FUZZ_BOOL_OFFSET_BYTES + OPENPLC_FUZZ_BOOL_BYTES)

struct plcfuzz_target_ctx
{
    PluginManager *pm;
    IEC_TIMESPEC *current_time;      /* __CURRENT_TIME (optional) */
    IEC_BOOL *debug_flag;            /* __DEBUG (optional) */
    void (*trace_reset)(void);       /* trace_reset (optional) */

    bool crash_enabled;
    bool verbose;
};

static uint16_t load_u16_le(const uint8_t *data, size_t len, size_t off)
{
    uint16_t v = 0;
    if (off < len)
    {
        v |= (uint16_t)data[off];
    }
    if (off + 1 < len)
    {
        v |= (uint16_t)((uint16_t)data[off + 1] << 8);
    }
    return v;
}

static void map_testcase_to_image(const uint8_t *data, size_t len)
{
    /* Clear mapped regions first so state doesn't bleed between testcases. */
    for (size_t i = 0; i < OPENPLC_FUZZ_MAX_WORDS; i++)
    {
        if (int_memory[i] != NULL)
        {
            *int_memory[i] = (IEC_UINT)0;
        }
    }

    for (size_t byte_i = 0; byte_i < OPENPLC_FUZZ_BOOL_BYTES; byte_i++)
    {
        for (size_t bit = 0; bit < 8; bit++)
        {
            if (bool_input[byte_i][bit] != NULL)
            {
                *bool_input[byte_i][bit] = (IEC_BOOL)0;
            }
        }
    }

    /* Map first bytes to %MW memory words (int_memory[]). */
    size_t max_words = len / 2;
    if (max_words > OPENPLC_FUZZ_MAX_WORDS)
    {
        max_words = OPENPLC_FUZZ_MAX_WORDS;
    }
    for (size_t i = 0; i < max_words; i++)
    {
        if (int_memory[i] != NULL)
        {
            *int_memory[i] = (IEC_UINT)load_u16_le(data, len, i * 2);
        }
    }

    /* Map a few bytes into digital inputs (%IX*) as bits. */
    const size_t bit_off = OPENPLC_FUZZ_BOOL_OFFSET_BYTES;
    if (len > bit_off)
    {
        size_t bytes = len - bit_off;
        if (bytes > OPENPLC_FUZZ_BOOL_BYTES)
        {
            bytes = OPENPLC_FUZZ_BOOL_BYTES;
        }
        for (size_t byte_i = 0; byte_i < bytes; byte_i++)
        {
            uint8_t b = data[bit_off + byte_i];
            for (size_t bit = 0; bit < 8; bit++)
            {
                if (bool_input[byte_i][bit] != NULL)
                {
                    *bool_input[byte_i][bit] = (IEC_BOOL)((b >> bit) & 1U);
                }
            }
        }
    }
}

static size_t collect_feedback(uint8_t *out, size_t out_cap)
{
    /* This is intentionally small: a snapshot of a few outputs gives black-box style feedback. */
    size_t pos = 0;

    /* First 4 output words (%QW0..%QW3) */
    for (size_t i = 0; i < 4 && (pos + 2) <= out_cap; i++)
    {
        uint16_t v = 0;
        if (int_output[i])
        {
            v = (uint16_t)(*int_output[i]);
        }
        out[pos++] = (uint8_t)(v & 0xff);
        out[pos++] = (uint8_t)((v >> 8) & 0xff);
    }

    /* First 8 output bits (%QX0.0..%QX0.7) packed into 1 byte */
    if (pos < out_cap)
    {
        uint8_t bits = 0;
        for (size_t bit = 0; bit < 8; bit++)
        {
            if (bool_output[0][bit] && *bool_output[0][bit])
            {
                bits |= (uint8_t)(1u << bit);
            }
        }
        out[pos++] = bits;
    }

    return pos;
}

static bool openplc_init(const plcfuzz_target_config_t *config, plcfuzz_target_ctx_t **ctx_out)
{
    if (!ctx_out)
    {
        return false;
    }
    *ctx_out = NULL;

    const bool verbose = config ? config->verbose : false;
    log_set_level(verbose ? LOG_LEVEL_INFO : LOG_LEVEL_ERROR);

    struct plcfuzz_target_ctx *ctx = (struct plcfuzz_target_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        return false;
    }

    ctx->verbose = verbose;
    ctx->crash_enabled = (config && config->enable_test_crash) || (getenv("OPENPLC_FUZZ_CRASH") != NULL);

    const char *build_dir = getenv("OPENPLC_BUILD_DIR");
    if (build_dir == NULL || build_dir[0] == '\0')
    {
        build_dir = "./build";
    }

    char *libplc_path = find_libplc_file(build_dir);
    if (libplc_path == NULL)
    {
        /* Helpful fallback if the user runs from inside the build dir. */
        libplc_path = find_libplc_file(".");
    }
    if (libplc_path == NULL)
    {
        free(ctx);
        return false;
    }

    ctx->pm = plugin_manager_create(libplc_path);
    free(libplc_path);
    if (ctx->pm == NULL)
    {
        free(ctx);
        return false;
    }

    if (!plugin_manager_load(ctx->pm))
    {
        plugin_manager_destroy(ctx->pm);
        free(ctx);
        return false;
    }

    if (symbols_init(ctx->pm) < 0)
    {
        plugin_manager_destroy(ctx->pm);
        free(ctx);
        return false;
    }

    /* Optional globals improve stability */
    ctx->current_time = (IEC_TIMESPEC *)plugin_manager_get_symbol(ctx->pm, "__CURRENT_TIME");
    ctx->debug_flag = (IEC_BOOL *)plugin_manager_get_symbol(ctx->pm, "__DEBUG");
    ctx->trace_reset = (void (*)(void))plugin_manager_get_symbol(ctx->pm, "trace_reset");

    /* Initialize PLC program + map located variables into image tables. */
    ext_config_init__();
    ext_glueVars();
    image_tables_fill_null_pointers();

    *ctx_out = ctx;
    return true;
}

static bool openplc_run(plcfuzz_target_ctx_t *ctx, const uint8_t *data, size_t len,
                        plcfuzz_result_t *result)
{
    if (!ctx || !result)
    {
        return false;
    }

    memset(result, 0, sizeof(*result));

    /* Reset time/debug globals so behavior doesn't depend on previous cycles. */
    if (ctx->debug_flag != NULL)
    {
        *ctx->debug_flag = (IEC_BOOL)0;
    }
    if (ctx->current_time != NULL)
    {
        ctx->current_time->tv_sec = 0;
        ctx->current_time->tv_nsec = 0;
    }

    /* Reset PLC state for testcase isolation. */
    ext_config_init__();
    if (ctx->trace_reset != NULL)
    {
        ctx->trace_reset();
    }
    tick__ = 0;

    if (len > OPENPLC_FUZZ_MAX_INPUT)
    {
        len = OPENPLC_FUZZ_MAX_INPUT;
    }

    map_testcase_to_image(data, len);

    /* Optional controllable crash for validation (do NOT crash here; frontends decide). */
    if (ctx->crash_enabled && len >= 2)
    {
        uint16_t v0 = load_u16_le(data, len, 0);
        if (v0 == 0x1337)
        {
            result->outcome = PLCFUZZ_OUTCOME_TARGET_CRASH;
            snprintf(result->error_msg, sizeof(result->error_msg), "OPENPLC_FUZZ_CRASH trigger (MW0==0x1337)");
            return true;
        }
    }

    /* Execute exactly one scan cycle. */
    ext_config_run__(tick__++);
    ext_updateTime();

    result->outcome = PLCFUZZ_OUTCOME_OK;
    result->feedback_len = collect_feedback(result->feedback, PLCFUZZ_MAX_FEEDBACK_SIZE);
    return true;
}

static bool openplc_reset(plcfuzz_target_ctx_t *ctx)
{
    if (!ctx)
    {
        return false;
    }
    /* run() already performs full per-test reset; keep this cheap. */
    return true;
}

static void openplc_deinit(plcfuzz_target_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    if (ctx->pm)
    {
        plugin_manager_destroy(ctx->pm);
    }
    free(ctx);
}

static const plcfuzz_target_api_t g_openplc_api = {
    .abi_version = PLCFUZZ_TARGET_ABI_VERSION,
    .name = "openplc_inproc",
    .max_input_len = OPENPLC_FUZZ_MAX_INPUT,
    .init = openplc_init,
    .run = openplc_run,
    .deinit = openplc_deinit,
    .reset = openplc_reset,
};

const plcfuzz_target_api_t *plcfuzz_get_target_api(void)
{
    return &g_openplc_api;
}

