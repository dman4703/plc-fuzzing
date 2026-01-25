/**
 * @file core.h
 * @brief plcfuzz core runtime (dlopen target plugins and run testcases)
 */

#ifndef PLCFUZZ_CORE_H
#define PLCFUZZ_CORE_H

#include "../include/plcfuzz_target_api.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct plcfuzz_handle plcfuzz_handle_t;

bool plcfuzz_load_target(const char *lib_path, const plcfuzz_target_config_t *config,
                         plcfuzz_handle_t **handle_out);

bool plcfuzz_run_one(plcfuzz_handle_t *handle, const uint8_t *data, size_t len,
                     plcfuzz_result_t *result);

bool plcfuzz_reset(plcfuzz_handle_t *handle);

const plcfuzz_target_api_t *plcfuzz_get_api(plcfuzz_handle_t *handle);

void plcfuzz_unload_target(plcfuzz_handle_t *handle);

const char *plcfuzz_get_error(void);

#ifdef __cplusplus
}
#endif

#endif /* PLCFUZZ_CORE_H */

