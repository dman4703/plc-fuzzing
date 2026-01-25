/**
 * @file plcfuzz_target_api.h
 * @brief Target plugin ABI for plcfuzz framework
 *
 * The fuzzing engine should not know whether it talks to OpenPLC-in-process,
 * Modbus/TCP, EtherNet/IP, etc. It only does:
 *   bytes -> run one test -> outcome (+ optional feedback)
 *
 * Targets are implemented as shared libraries and loaded via dlopen().
 */

#ifndef PLCFUZZ_TARGET_API_H
#define PLCFUZZ_TARGET_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ABI version for target plugins (breaking changes increment this)
 */
#define PLCFUZZ_TARGET_ABI_VERSION 1

/**
 * @brief Maximum feedback size (bytes)
 *
 * Feedback is optional. Under AFL++, coverage is the primary signal; targets may still
 * provide lightweight feedback (e.g., response codes, small output snapshots) for
 * debugging or future state-aware extensions.
 */
#define PLCFUZZ_MAX_FEEDBACK_SIZE 256

/**
 * @brief Outcome of a single test execution
 */
typedef enum
{
    PLCFUZZ_OUTCOME_OK = 0,
    PLCFUZZ_OUTCOME_TARGET_CRASH,
    PLCFUZZ_OUTCOME_TARGET_HANG,
    PLCFUZZ_OUTCOME_ERROR,
} plcfuzz_outcome_t;

/**
 * @brief Result of a single test execution
 */
typedef struct
{
    plcfuzz_outcome_t outcome;

    /* Optional, opaque feedback bytes */
    uint8_t feedback[PLCFUZZ_MAX_FEEDBACK_SIZE];
    size_t feedback_len;

    /* Optional error message (only meaningful for PLCFUZZ_OUTCOME_ERROR) */
    char error_msg[256];
} plcfuzz_result_t;

/**
 * @brief Target configuration passed to init()
 */
typedef struct
{
    const char *config_path; /* Target-specific config file (e.g., JSON), optional */
    bool verbose;
    bool enable_test_crash;  /* Target-specific validation knob */
} plcfuzz_target_config_t;

/**
 * @brief Opaque per-target context
 */
typedef struct plcfuzz_target_ctx plcfuzz_target_ctx_t;

/**
 * @brief Target plugin API vtable
 */
typedef struct
{
    uint32_t abi_version;
    const char *name;
    size_t max_input_len;

    bool (*init)(const plcfuzz_target_config_t *config, plcfuzz_target_ctx_t **ctx_out);
    bool (*run)(plcfuzz_target_ctx_t *ctx, const uint8_t *data, size_t len, plcfuzz_result_t *result);
    void (*deinit)(plcfuzz_target_ctx_t *ctx);

    /* Optional: reset target state between iterations in persistent mode */
    bool (*reset)(plcfuzz_target_ctx_t *ctx);
} plcfuzz_target_api_t;

/**
 * @brief Required exported symbol name in each target plugin
 */
#define PLCFUZZ_TARGET_API_SYMBOL "plcfuzz_get_target_api"

/**
 * @brief Signature of the exported entrypoint
 */
typedef const plcfuzz_target_api_t *(*plcfuzz_get_target_api_fn)(void);

#ifdef __cplusplus
}
#endif

#endif /* PLCFUZZ_TARGET_API_H */

