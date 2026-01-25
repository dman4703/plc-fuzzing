/**
 * @file modbus_tcp_target.c
 * @brief Modbus/TCP black-box target plugin for plcfuzz
 *
 * - Takes fuzz bytes, interprets them as little-endian u16 register values
 * - Writes them via Modbus function 0x10 (Write Multiple Registers)
 * - Optionally reads back selected holding registers / coils for feedback
 *
 * No external dependencies (pure POSIX sockets + minimal JSON key parsing).
 */

#include "plcfuzz_target_api.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MODBUS_TCP_PROTOCOL_ID 0

struct plcfuzz_target_ctx
{
    char host[256];
    int port;
    uint8_t unit_id;

    int address_base; /* 0 or 1 (user-visible addressing convention) */

    int write_start_addr; /* user-visible */
    int write_count;      /* number of registers written each testcase */

    int read_holding_start_addr; /* user-visible */
    int read_holding_count;

    int read_coils_start_addr; /* user-visible */
    int read_coils_count;

    int timeout_ms;
    int post_write_delay_ms;

    plcfuzz_outcome_t comm_error_outcome; /* crash or hang */

    int sockfd;
    uint16_t tx_id;
    bool verbose;
};

static void set_result_error(plcfuzz_result_t *result, plcfuzz_outcome_t outcome, const char *msg)
{
    if (!result)
    {
        return;
    }
    result->outcome = outcome;
    result->feedback_len = 0;
    if (msg)
    {
        snprintf(result->error_msg, sizeof(result->error_msg), "%s", msg);
    }
}

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

static void sleep_ms(int ms)
{
    if (ms <= 0)
    {
        return;
    }
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static ssize_t send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (n == 0)
        {
            return -1;
        }
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

static ssize_t recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len)
    {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (n == 0)
        {
            return -1;
        }
        got += (size_t)n;
    }
    return (ssize_t)got;
}

static void close_socket(struct plcfuzz_target_ctx *ctx)
{
    if (ctx->sockfd >= 0)
    {
        close(ctx->sockfd);
        ctx->sockfd = -1;
    }
}

static bool connect_socket(struct plcfuzz_target_ctx *ctx)
{
    if (!ctx)
    {
        return false;
    }
    if (ctx->sockfd >= 0)
    {
        return true;
    }

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", ctx->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(ctx->host, port_str, &hints, &res);
    if (rc != 0 || !res)
    {
        return false;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next)
    {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
        {
            continue;
        }

        /* Set timeouts */
        struct timeval tv;
        tv.tv_sec = ctx->timeout_ms / 1000;
        tv.tv_usec = (ctx->timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
        {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0)
    {
        return false;
    }

    ctx->sockfd = fd;
    return true;
}

static int addr_to_pdu(struct plcfuzz_target_ctx *ctx, int user_addr, uint16_t *out)
{
    if (!ctx || !out)
    {
        return -1;
    }
    int pdu = user_addr - ctx->address_base;
    if (pdu < 0 || pdu > 0xFFFF)
    {
        return -1;
    }
    *out = (uint16_t)pdu;
    return 0;
}

static bool modbus_exchange(struct plcfuzz_target_ctx *ctx, const uint8_t *pdu, size_t pdu_len,
                            uint8_t *pdu_out, size_t pdu_out_cap, size_t *pdu_out_len)
{
    if (!ctx || !pdu || pdu_len == 0 || !pdu_out || !pdu_out_len)
    {
        return false;
    }

    if (!connect_socket(ctx))
    {
        return false;
    }

    /* MBAP: tx_id(2) proto_id(2) length(2) unit_id(1) */
    uint8_t hdr[7];
    ctx->tx_id++;
    uint16_t tx = ctx->tx_id;

    hdr[0] = (uint8_t)((tx >> 8) & 0xff);
    hdr[1] = (uint8_t)(tx & 0xff);
    hdr[2] = 0;
    hdr[3] = 0;
    uint16_t length = (uint16_t)(1 + pdu_len);
    hdr[4] = (uint8_t)((length >> 8) & 0xff);
    hdr[5] = (uint8_t)(length & 0xff);
    hdr[6] = ctx->unit_id;

    /* Send header + pdu */
    if (send_all(ctx->sockfd, hdr, sizeof(hdr)) < 0 || send_all(ctx->sockfd, pdu, pdu_len) < 0)
    {
        close_socket(ctx);
        return false;
    }

    /* Read response header */
    uint8_t rhdr[7];
    if (recv_all(ctx->sockfd, rhdr, sizeof(rhdr)) < 0)
    {
        close_socket(ctx);
        return false;
    }

    uint16_t rlen = (uint16_t)((uint16_t)rhdr[4] << 8 | rhdr[5]);
    if (rlen < 1)
    {
        close_socket(ctx);
        return false;
    }
    size_t rpdu_len = (size_t)(rlen - 1);
    if (rpdu_len > pdu_out_cap)
    {
        /* Drain and fail */
        uint8_t tmp[256];
        while (rpdu_len > 0)
        {
            size_t chunk = rpdu_len > sizeof(tmp) ? sizeof(tmp) : rpdu_len;
            if (recv_all(ctx->sockfd, tmp, chunk) < 0)
            {
                break;
            }
            rpdu_len -= chunk;
        }
        return false;
    }

    if (recv_all(ctx->sockfd, pdu_out, rpdu_len) < 0)
    {
        close_socket(ctx);
        return false;
    }

    *pdu_out_len = rpdu_len;
    return true;
}

/* ------------------------------ Minimal JSON parsing ------------------------------ */

static char *read_entire_file(const char *path)
{
    if (!path)
    {
        return NULL;
    }

    FILE *f = fopen(path, "rb");
    if (!f)
    {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0)
    {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return NULL;
    }

    char *buf = (char *)calloc(1, (size_t)sz + 1);
    if (!buf)
    {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static const char *skip_ws(const char *p)
{
    while (p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
    {
        p++;
    }
    return p;
}

static const char *find_json_key(const char *json, const char *key)
{
    if (!json || !key)
    {
        return NULL;
    }
    /* naive search for \"key\" */
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p)
    {
        return NULL;
    }
    p += strlen(needle);
    p = skip_ws(p);
    if (*p != ':')
    {
        return NULL;
    }
    p++;
    return skip_ws(p);
}

static bool json_get_int(const char *json, const char *key, int *out)
{
    const char *p = find_json_key(json, key);
    if (!p)
    {
        return false;
    }
    char *end = NULL;
    long v = strtol(p, &end, 0);
    if (end == p)
    {
        return false;
    }
    *out = (int)v;
    return true;
}

static bool json_get_string(const char *json, const char *key, char *out, size_t out_cap)
{
    const char *p = find_json_key(json, key);
    if (!p)
    {
        return false;
    }
    if (*p != '"')
    {
        return false;
    }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_cap)
    {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (*p == '"');
}

static plcfuzz_outcome_t parse_comm_error_outcome(const char *json)
{
    char tmp[64];
    if (json_get_string(json, "comm_error_outcome", tmp, sizeof(tmp)))
    {
        if (strcmp(tmp, "crash") == 0)
        {
            return PLCFUZZ_OUTCOME_TARGET_CRASH;
        }
        if (strcmp(tmp, "hang") == 0)
        {
            return PLCFUZZ_OUTCOME_TARGET_HANG;
        }
    }
    return PLCFUZZ_OUTCOME_TARGET_HANG;
}

static bool modbus_init(const plcfuzz_target_config_t *config, plcfuzz_target_ctx_t **ctx_out)
{
    if (!ctx_out)
    {
        return false;
    }
    *ctx_out = NULL;

    struct plcfuzz_target_ctx *ctx = (struct plcfuzz_target_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        return false;
    }

    /* Defaults (OpenPLC-ish) */
    snprintf(ctx->host, sizeof(ctx->host), "127.0.0.1");
    ctx->port = 1502;
    ctx->unit_id = 1;
    ctx->address_base = 1;
    ctx->write_start_addr = 1025; /* With OpenPLC segmented map, %MW0 is typically at 1025 (1-based) */
    ctx->write_count = 8;
    ctx->read_holding_start_addr = 0;
    ctx->read_holding_count = 0;
    ctx->read_coils_start_addr = 0;
    ctx->read_coils_count = 0;
    ctx->timeout_ms = 200;
    ctx->post_write_delay_ms = 0;
    ctx->sockfd = -1;
    ctx->tx_id = 0;
    ctx->verbose = config ? config->verbose : false;
    ctx->comm_error_outcome = PLCFUZZ_OUTCOME_TARGET_HANG;

    const char *cfg_path = NULL;
    if (config && config->config_path)
    {
        cfg_path = config->config_path;
    }
    if (!cfg_path)
    {
        cfg_path = getenv("PLCFUZZ_CONFIG");
    }

    if (cfg_path && cfg_path[0])
    {
        char *json = read_entire_file(cfg_path);
        if (json)
        {
            (void)json_get_string(json, "host", ctx->host, sizeof(ctx->host));
            (void)json_get_int(json, "port", &ctx->port);
            int unit_id = 0;
            if (json_get_int(json, "unit_id", &unit_id))
            {
                if (unit_id >= 0 && unit_id <= 255)
                {
                    ctx->unit_id = (uint8_t)unit_id;
                }
            }
            (void)json_get_int(json, "address_base", &ctx->address_base);
            (void)json_get_int(json, "write_start_addr", &ctx->write_start_addr);
            (void)json_get_int(json, "write_count", &ctx->write_count);
            (void)json_get_int(json, "timeout_ms", &ctx->timeout_ms);
            (void)json_get_int(json, "post_write_delay_ms", &ctx->post_write_delay_ms);
            (void)json_get_int(json, "read_holding_start_addr", &ctx->read_holding_start_addr);
            (void)json_get_int(json, "read_holding_count", &ctx->read_holding_count);
            (void)json_get_int(json, "read_coils_start_addr", &ctx->read_coils_start_addr);
            (void)json_get_int(json, "read_coils_count", &ctx->read_coils_count);
            ctx->comm_error_outcome = parse_comm_error_outcome(json);
            free(json);
        }
    }

    /* Sanity */
    if (ctx->write_count <= 0)
    {
        ctx->write_count = 1;
    }
    if (ctx->write_count > 64)
    {
        /* Avoid huge single requests by default */
        ctx->write_count = 64;
    }
    if (ctx->timeout_ms <= 0)
    {
        ctx->timeout_ms = 200;
    }
    if (ctx->address_base != 0 && ctx->address_base != 1)
    {
        ctx->address_base = 1;
    }
    if (ctx->read_holding_count < 0)
    {
        ctx->read_holding_count = 0;
    }
    if (ctx->read_holding_count > 32)
    {
        ctx->read_holding_count = 32;
    }
    if (ctx->read_coils_count < 0)
    {
        ctx->read_coils_count = 0;
    }
    if (ctx->read_coils_count > 64)
    {
        ctx->read_coils_count = 64;
    }

    *ctx_out = ctx;
    return true;
}

static bool modbus_run(plcfuzz_target_ctx_t *ctx, const uint8_t *data, size_t len,
                       plcfuzz_result_t *result)
{
    if (!ctx || !result)
    {
        return false;
    }

    memset(result, 0, sizeof(*result));

    if (!connect_socket(ctx))
    {
        set_result_error(result, ctx->comm_error_outcome, "connect() failed");
        return true;
    }

    uint16_t start_addr_pdu = 0;
    if (addr_to_pdu(ctx, ctx->write_start_addr, &start_addr_pdu) != 0)
    {
        set_result_error(result, PLCFUZZ_OUTCOME_ERROR, "Invalid write_start_addr/address_base");
        return true;
    }

    /* Build values from fuzz bytes (little-endian u16) */
    const int count = ctx->write_count;
    uint8_t pdu[260];
    size_t p = 0;
    pdu[p++] = 0x10; /* Write Multiple Registers */
    pdu[p++] = (uint8_t)((start_addr_pdu >> 8) & 0xff);
    pdu[p++] = (uint8_t)(start_addr_pdu & 0xff);
    pdu[p++] = (uint8_t)((count >> 8) & 0xff);
    pdu[p++] = (uint8_t)(count & 0xff);
    pdu[p++] = (uint8_t)(count * 2);

    for (int i = 0; i < count; i++)
    {
        uint16_t v = load_u16_le(data, len, (size_t)i * 2);
        /* Modbus register payload is big-endian */
        pdu[p++] = (uint8_t)((v >> 8) & 0xff);
        pdu[p++] = (uint8_t)(v & 0xff);
    }

    uint8_t rpdu[260];
    size_t rpdu_len = 0;
    if (!modbus_exchange(ctx, pdu, p, rpdu, sizeof(rpdu), &rpdu_len))
    {
        set_result_error(result, ctx->comm_error_outcome, "write exchange failed");
        return true;
    }

    /* Feedback: response classification */
    size_t fb = 0;
    result->feedback[fb++] = 0; /* 0=ok, 1=exception */

    if (rpdu_len >= 2 && (rpdu[0] & 0x80u))
    {
        result->feedback[0] = 1;
        uint8_t exc = rpdu[1];
        if (fb < PLCFUZZ_MAX_FEEDBACK_SIZE)
        {
            result->feedback[fb++] = exc;
        }
        result->outcome = PLCFUZZ_OUTCOME_OK;
        result->feedback_len = fb;
        return true;
    }

    /* Optional delay to allow PLC scan cycle to apply changes */
    sleep_ms(ctx->post_write_delay_ms);

    /* Optional readback: holding registers */
    if (ctx->read_holding_count > 0 && fb + 2 <= PLCFUZZ_MAX_FEEDBACK_SIZE)
    {
        uint16_t rh_start_pdu = 0;
        if (addr_to_pdu(ctx, ctx->read_holding_start_addr, &rh_start_pdu) == 0)
        {
            uint8_t rq[5];
            rq[0] = 0x03;
            rq[1] = (uint8_t)((rh_start_pdu >> 8) & 0xff);
            rq[2] = (uint8_t)(rh_start_pdu & 0xff);
            rq[3] = (uint8_t)((ctx->read_holding_count >> 8) & 0xff);
            rq[4] = (uint8_t)(ctx->read_holding_count & 0xff);

            uint8_t rr[260];
            size_t rr_len = 0;
            if (modbus_exchange(ctx, rq, sizeof(rq), rr, sizeof(rr), &rr_len) && rr_len >= 2 &&
                !(rr[0] & 0x80u) && rr[0] == 0x03)
            {
                uint8_t byte_count = rr[1];
                size_t avail = rr_len >= 2 ? (rr_len - 2) : 0;
                if (byte_count <= avail)
                {
                    size_t to_copy = byte_count;
                    if (to_copy > (PLCFUZZ_MAX_FEEDBACK_SIZE - fb))
                    {
                        to_copy = PLCFUZZ_MAX_FEEDBACK_SIZE - fb;
                    }
                    memcpy(&result->feedback[fb], &rr[2], to_copy);
                    fb += to_copy;
                }
            }
        }
    }

    /* Optional readback: coils */
    if (ctx->read_coils_count > 0 && fb < PLCFUZZ_MAX_FEEDBACK_SIZE)
    {
        uint16_t rc_start_pdu = 0;
        if (addr_to_pdu(ctx, ctx->read_coils_start_addr, &rc_start_pdu) == 0)
        {
            uint8_t rq[5];
            rq[0] = 0x01;
            rq[1] = (uint8_t)((rc_start_pdu >> 8) & 0xff);
            rq[2] = (uint8_t)(rc_start_pdu & 0xff);
            rq[3] = (uint8_t)((ctx->read_coils_count >> 8) & 0xff);
            rq[4] = (uint8_t)(ctx->read_coils_count & 0xff);

            uint8_t rr[260];
            size_t rr_len = 0;
            if (modbus_exchange(ctx, rq, sizeof(rq), rr, sizeof(rr), &rr_len) && rr_len >= 2 &&
                !(rr[0] & 0x80u) && rr[0] == 0x01)
            {
                uint8_t byte_count = rr[1];
                size_t avail = rr_len >= 2 ? (rr_len - 2) : 0;
                if (byte_count <= avail)
                {
                    size_t to_copy = byte_count;
                    if (to_copy > (PLCFUZZ_MAX_FEEDBACK_SIZE - fb))
                    {
                        to_copy = PLCFUZZ_MAX_FEEDBACK_SIZE - fb;
                    }
                    memcpy(&result->feedback[fb], &rr[2], to_copy);
                    fb += to_copy;
                }
            }
        }
    }

    result->outcome = PLCFUZZ_OUTCOME_OK;
    result->feedback_len = fb;
    return true;
}

static bool modbus_reset(plcfuzz_target_ctx_t *ctx)
{
    if (!ctx)
    {
        return false;
    }
    /* Keep connection alive; if it died, reconnect on next run(). */
    return true;
}

static void modbus_deinit(plcfuzz_target_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }
    close_socket(ctx);
    free(ctx);
}

static const plcfuzz_target_api_t g_modbus_api = {
    .abi_version = PLCFUZZ_TARGET_ABI_VERSION,
    .name = "modbus_tcp",
    .max_input_len = 128, /* plenty for register payloads; frontend may truncate further */
    .init = modbus_init,
    .run = modbus_run,
    .deinit = modbus_deinit,
    .reset = modbus_reset,
};

const plcfuzz_target_api_t *plcfuzz_get_target_api(void)
{
    return &g_modbus_api;
}

