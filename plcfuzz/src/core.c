/**
 * @file core.c
 * @brief plcfuzz core runtime implementation
 */

#include "core.h"

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct plcfuzz_handle
{
    void *dl_handle;
    const plcfuzz_target_api_t *api;
    plcfuzz_target_ctx_t *ctx;
};

static __thread char g_error_msg[512];

static void set_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_error_msg, sizeof(g_error_msg), fmt, args);
    va_end(args);
}

const char *plcfuzz_get_error(void)
{
    return g_error_msg[0] ? g_error_msg : NULL;
}

bool plcfuzz_load_target(const char *lib_path, const plcfuzz_target_config_t *config,
                         plcfuzz_handle_t **handle_out)
{
    g_error_msg[0] = '\0';

    if (!lib_path || !handle_out)
    {
        set_error("plcfuzz_load_target: NULL argument");
        return false;
    }

    *handle_out = NULL;

    plcfuzz_handle_t *h = (plcfuzz_handle_t *)calloc(1, sizeof(plcfuzz_handle_t));
    if (!h)
    {
        set_error("plcfuzz_load_target: out of memory");
        return false;
    }

    h->dl_handle = dlopen(lib_path, RTLD_NOW);
    if (!h->dl_handle)
    {
        set_error("dlopen(%s): %s", lib_path, dlerror());
        free(h);
        return false;
    }

    dlerror(); /* clear */
    plcfuzz_get_target_api_fn get_api =
        (plcfuzz_get_target_api_fn)dlsym(h->dl_handle, PLCFUZZ_TARGET_API_SYMBOL);
    const char *err = dlerror();
    if (err)
    {
        set_error("dlsym(%s): %s", PLCFUZZ_TARGET_API_SYMBOL, err);
        dlclose(h->dl_handle);
        free(h);
        return false;
    }

    h->api = get_api();
    if (!h->api)
    {
        set_error("%s returned NULL", PLCFUZZ_TARGET_API_SYMBOL);
        dlclose(h->dl_handle);
        free(h);
        return false;
    }

    if (h->api->abi_version != PLCFUZZ_TARGET_ABI_VERSION)
    {
        set_error("ABI version mismatch: expected %d got %d", PLCFUZZ_TARGET_ABI_VERSION,
                  h->api->abi_version);
        dlclose(h->dl_handle);
        free(h);
        return false;
    }

    if (!h->api->init || !h->api->run || !h->api->deinit)
    {
        set_error("Target API missing required init/run/deinit");
        dlclose(h->dl_handle);
        free(h);
        return false;
    }

    plcfuzz_target_config_t default_cfg;
    memset(&default_cfg, 0, sizeof(default_cfg));
    if (!config)
    {
        config = &default_cfg;
    }

    if (!h->api->init(config, &h->ctx))
    {
        set_error("Target init() failed");
        dlclose(h->dl_handle);
        free(h);
        return false;
    }

    *handle_out = h;
    return true;
}

bool plcfuzz_run_one(plcfuzz_handle_t *handle, const uint8_t *data, size_t len,
                     plcfuzz_result_t *result)
{
    g_error_msg[0] = '\0';

    if (!handle || !result)
    {
        set_error("plcfuzz_run_one: NULL argument");
        return false;
    }

    memset(result, 0, sizeof(*result));

    size_t max_len = handle->api->max_input_len;
    if (max_len > 0 && len > max_len)
    {
        len = max_len;
    }

    if (!handle->api->run(handle->ctx, data, len, result))
    {
        set_error("Target run() returned false");
        return false;
    }

    return true;
}

bool plcfuzz_reset(plcfuzz_handle_t *handle)
{
    if (!handle)
    {
        return false;
    }

    if (handle->api->reset)
    {
        return handle->api->reset(handle->ctx);
    }

    return true;
}

const plcfuzz_target_api_t *plcfuzz_get_api(plcfuzz_handle_t *handle)
{
    return handle ? handle->api : NULL;
}

void plcfuzz_unload_target(plcfuzz_handle_t *handle)
{
    if (!handle)
    {
        return;
    }

    if (handle->api && handle->api->deinit && handle->ctx)
    {
        handle->api->deinit(handle->ctx);
    }

    if (handle->dl_handle)
    {
        dlclose(handle->dl_handle);
    }

    free(handle);
}

