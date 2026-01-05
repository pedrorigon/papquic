/*
 * QUIC handshake timing helpers for packet-mode internal logging.
 */

#include "../ssl_local.h"
#include "internal/ssl_unwrap.h"
#include "internal/quic_debug.h"
#include "internal/quic_types.h"

#ifndef OPENSSL_NO_QUIC

#include <stdio.h>
#include <string.h>

static QUIC_HANDSHAKE_TIMING *quic_timing_activate(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm;

    if (sc == NULL || !SSL_IS_QUIC_HANDSHAKE(sc))
        return NULL;

    tm = &sc->quic_timing;
    if (!tm->initialized) {
        memset(tm, 0, sizeof(*tm));
        tm->initialized = 1;
        tm->enabled = ossl_quic_packet_log_enabled() ? 1 : 0;
    }

    if (!tm->enabled)
        return NULL;

    return tm;
}

static void quic_timing_clear_buffer(BUF_MEM **slot)
{
    if (slot == NULL || *slot == NULL)
        return;
    BUF_MEM_free(*slot);
    *slot = NULL;
}

static int quic_timing_store_buffer(BUF_MEM **slot,
                                    const char *data, size_t len)
{
    BUF_MEM *buf;

    if (slot == NULL || data == NULL || len == 0)
        return 0;

    buf = BUF_MEM_new();
    if (buf == NULL)
        return 0;
    if (!BUF_MEM_grow(buf, len)) {
        BUF_MEM_free(buf);
        return 0;
    }
    memcpy(buf->data, data, len);
    *slot = buf;
    return 1;
}

static void quic_timing_flush_buffer(BUF_MEM **slot, FILE *stream)
{
    BUF_MEM *buf;

    if (slot == NULL || *slot == NULL)
        return;
    buf = *slot;
    if (stream != NULL && buf->length > 0) {
        fwrite(buf->data, 1, buf->length, stream);
        fflush(stream);
    }
    BUF_MEM_free(buf);
    *slot = NULL;
}

QUIC_HANDSHAKE_TIMING *ossl_quic_timing_get(SSL_CONNECTION *sc)
{
    return quic_timing_activate(sc);
}

int ossl_quic_timing_buffer_server_hello_line(SSL_CONNECTION *sc,
                                              const char *data, size_t len)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);
    if (tm == NULL)
        return 0;
    quic_timing_clear_buffer(&tm->pending_server_initial_line);
    return quic_timing_store_buffer(&tm->pending_server_initial_line,
                                    data, len);
}

void ossl_quic_timing_flush_server_hello_line(SSL_CONNECTION *sc, FILE *stream)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);
    if (tm == NULL)
        return;
    quic_timing_flush_buffer(&tm->pending_server_initial_line, stream);
}

int ossl_quic_timing_buffer_client_finished_line(SSL_CONNECTION *sc,
                                                 const char *data, size_t len)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);
    if (tm == NULL)
        return 0;
    quic_timing_clear_buffer(&tm->pending_client_finished_line);
    return quic_timing_store_buffer(&tm->pending_client_finished_line,
                                    data, len);
}

void ossl_quic_timing_flush_client_finished_line(SSL_CONNECTION *sc,
                                                 FILE *stream)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);
    if (tm == NULL)
        return;
    quic_timing_flush_buffer(&tm->pending_client_finished_line, stream);
}

int ossl_quic_timing_buffer_server_hs_done_line(SSL_CONNECTION *sc,
                                                const char *data, size_t len)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);
    if (tm == NULL)
        return 0;
    quic_timing_clear_buffer(&tm->pending_server_handshake_done_line);
    return quic_timing_store_buffer(&tm->pending_server_handshake_done_line,
                                    data, len);
}

void ossl_quic_timing_flush_server_hs_done_line(SSL_CONNECTION *sc,
                                                FILE *stream)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);
    if (tm == NULL)
        return;
    quic_timing_flush_buffer(&tm->pending_server_handshake_done_line, stream);
}

static void quic_timing_stage_begin(int *active, OSSL_TIME *start)
{
    if (*active)
        return;
    *active = 1;
    *start = ossl_time_now();
}

static void quic_timing_stage_complete(int *active,
                                       OSSL_TIME *start,
                                       int *have_value,
                                       OSSL_TIME *value)
{
    OSSL_TIME delta;

    if (!*active || *have_value)
        return;
    delta = ossl_time_subtract(ossl_time_now(), *start);
    *value = delta;
    *have_value = 1;
    *active = 0;
}

static void quic_timing_stage_abort(int *active)
{
    *active = 0;
}

static void quic_timing_print_metric(FILE *stream, int *first,
                                     const char *name,
                                     int have_value,
                                     const OSSL_TIME *value);
static void quic_timing_print_header(FILE *stream, double display_ms,
                                     const char *role, const char *tag);
static void quic_timing_maybe_log_server_hello_build(SSL_CONNECTION *sc,
                                                     QUIC_HANDSHAKE_TIMING *tm);

static double quic_timing_display_ms_from_now(OSSL_TIME now)
{
    double elapsed_ms = (double)ossl_time2ticks(now) / 1000000.0;
    uint64_t integral = (elapsed_ms >= 0)
        ? (uint64_t)elapsed_ms
        : (uint64_t)(-elapsed_ms);
    double fractional = elapsed_ms - (elapsed_ms >= 0
                                      ? (double)integral
                                      : -(double)integral);
    uint64_t mod = integral % 100000;
    double display_ms = (elapsed_ms >= 0)
        ? (double)mod + fractional
        : -((double)mod + fractional);

    if (display_ms < 0)
        display_ms += 100000.0;
    return display_ms;
}

static void quic_timing_emit_single_metric_line(SSL_CONNECTION *sc,
                                                QUIC_HANDSHAKE_TIMING *tm,
                                                const char *tag,
                                                const char *metric_name,
                                                int have_value,
                                                const OSSL_TIME *value)
{
    FILE *stream = tm->log_stream != NULL ? tm->log_stream : stderr;
    const char *role = sc->server ? "SERVER" : "CLIENT";
    OSSL_TIME now = ossl_time_now();
    double display_ms = quic_timing_display_ms_from_now(now);
    int first = 1;

    quic_timing_print_header(stream, display_ms, role, tag);
    quic_timing_print_metric(stream, &first, metric_name, have_value, value);
    fputc('\n', stream);
    fflush(stream);
}

void ossl_quic_timing_client_keyshare_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_client_keyshare)
        return;
    quic_timing_stage_begin(&tm->client_keyshare_active,
                            &tm->client_keyshare_start);
}

void ossl_quic_timing_client_keyshare_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->client_keyshare_active,
                               &tm->client_keyshare_start,
                               &tm->have_client_keyshare,
                               &tm->client_keyshare);
}

void ossl_quic_timing_client_keyshare_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->client_keyshare_active);
}

void ossl_quic_timing_client_hello_build_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_client_hello_build)
        return;
    quic_timing_stage_begin(&tm->client_hello_build_active,
                            &tm->client_hello_build_start);
}

void ossl_quic_timing_client_hello_build_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->client_hello_build_active,
                               &tm->client_hello_build_start,
                               &tm->have_client_hello_build,
                               &tm->client_hello_build);
}

void ossl_quic_timing_client_hello_build_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->client_hello_build_active);
}

void ossl_quic_timing_client_hello_sent(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_client_hello_sent)
        return;
    tm->client_hello_sent = ossl_time_now();
    tm->have_client_hello_sent = 1;
}

void ossl_quic_timing_client_processed_server_hello(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL || !tm->have_client_hello_sent
            || tm->have_client_hello_rtt)
        return;

    tm->client_hello_rtt
        = ossl_time_subtract(ossl_time_now(), tm->client_hello_sent);
    tm->have_client_hello_rtt = 1;
}

void ossl_quic_timing_client_kex_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_client_kex)
        return;
    quic_timing_stage_begin(&tm->client_kex_active, &tm->client_kex_start);
}

void ossl_quic_timing_client_kex_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->client_kex_active,
                               &tm->client_kex_start,
                               &tm->have_client_kex,
                               &tm->client_kex);
}

void ossl_quic_timing_client_kex_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->client_kex_active);
}

void ossl_quic_timing_client_cert_chain_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_client_cert_chain)
        return;
    if (!tm->client_cert_chain_active) {
        tm->client_cert_chain_active = 1;
        tm->client_cert_chain_start = ossl_time_now();
    }
}

void ossl_quic_timing_client_cert_chain_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->client_cert_chain_active,
                               &tm->client_cert_chain_start,
                               &tm->have_client_cert_chain,
                               &tm->client_cert_chain);
    if (tm->have_client_cert_chain && !tm->client_cert_logged) {
        quic_timing_emit_single_metric_line(sc, tm,
                                            "CERTIFICATE PROCESSED",
                                            "clientCertificateProcess",
                                            tm->have_client_cert_chain,
                                            &tm->client_cert_chain);
        tm->client_cert_logged = 1;
    }
}

void ossl_quic_timing_client_cert_chain_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->client_cert_chain_active);
}

void ossl_quic_timing_client_cert_verify_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_client_cert_verify)
        return;
    quic_timing_stage_begin(&tm->client_cert_verify_active,
                            &tm->client_cert_verify_start);
}

void ossl_quic_timing_client_cert_verify_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->client_cert_verify_active,
                               &tm->client_cert_verify_start,
                               &tm->have_client_cert_verify,
                               &tm->client_cert_verify);
}

void ossl_quic_timing_client_cert_verify_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->client_cert_verify_active);
}

void ossl_quic_timing_client_cert_verify_check_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_client_cv_check)
        return;
    quic_timing_stage_begin(&tm->client_cv_check_active,
                            &tm->client_cv_check_start);
}

void ossl_quic_timing_client_cert_verify_check_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->client_cv_check_active,
                               &tm->client_cv_check_start,
                               &tm->have_client_cv_check,
                               &tm->client_cv_check);
    tm->client_ready = 1;
    if (tm->have_client_cv_check && !tm->client_cv_logged) {
        quic_timing_emit_single_metric_line(sc, tm,
                                            "CERTIFICATE VERIFY CHECK",
                                            "clientCertVerifyCheck",
                                            tm->have_client_cv_check,
                                            &tm->client_cv_check);
        tm->client_cv_logged = 1;
    }
}

void ossl_quic_timing_client_cert_verify_check_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->client_cv_check_active);
}

void ossl_quic_timing_server_client_hello_process_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_server_clienthello_process
            || tm->server_clienthello_process_active)
        return;
    tm->server_clienthello_process_active = 1;
    tm->server_clienthello_process_start = ossl_time_now();
}

void ossl_quic_timing_server_client_hello_processed(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);
    OSSL_TIME now;

    if (tm == NULL || tm->have_server_clienthello_time)
        return;
    now = ossl_time_now();
    if (tm->server_clienthello_process_active
            && !tm->have_server_clienthello_process) {
        tm->server_clienthello_process
            = ossl_time_subtract(now, tm->server_clienthello_process_start);
        tm->have_server_clienthello_process = 1;
        tm->server_clienthello_process_active = 0;
    }
    tm->server_clienthello_time = now;
    tm->have_server_clienthello_time = 1;
}

void ossl_quic_timing_server_hello_ready(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL || tm->have_server_hello_preparation
            || !tm->have_server_clienthello_time)
        return;

    tm->server_hello_preparation
        = ossl_time_subtract(ossl_time_now(), tm->server_clienthello_time);
    tm->have_server_hello_preparation = 1;
    quic_timing_maybe_log_server_hello_build(sc, tm);
}

void ossl_quic_timing_server_kex_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_server_kex_latency)
        return;
    quic_timing_stage_begin(&tm->server_kex_active, &tm->server_kex_start);
}

void ossl_quic_timing_server_kex_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->server_kex_active,
                               &tm->server_kex_start,
                               &tm->have_server_kex_latency,
                               &tm->server_kex_latency);
    quic_timing_maybe_log_server_hello_build(sc, tm);
}

void ossl_quic_timing_server_kex_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->server_kex_active);
}

void ossl_quic_timing_server_cert_build_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_server_cert_build)
        return;
    quic_timing_stage_begin(&tm->server_cert_build_active,
                            &tm->server_cert_build_start);
}

void ossl_quic_timing_server_cert_build_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->server_cert_build_active,
                               &tm->server_cert_build_start,
                               &tm->have_server_cert_build,
                               &tm->server_cert_build);
    if (tm->have_server_cert_build && !tm->server_cert_logged) {
        quic_timing_emit_single_metric_line(sc, tm,
                                            "CERTIFICATE BUILD",
                                            "serverCertificateBuild",
                                            tm->have_server_cert_build,
                                            &tm->server_cert_build);
        tm->server_cert_logged = 1;
    }
}

void ossl_quic_timing_server_cert_build_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->server_cert_build_active);
}

void ossl_quic_timing_server_cert_verify_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_server_cert_verify)
        return;
    quic_timing_stage_begin(&tm->server_cert_verify_active,
                            &tm->server_cert_verify_start);
}

void ossl_quic_timing_server_cert_verify_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->server_cert_verify_active,
                               &tm->server_cert_verify_start,
                               &tm->have_server_cert_verify,
                               &tm->server_cert_verify);
    if (tm->have_server_cert_verify && !tm->server_cv_logged) {
        quic_timing_emit_single_metric_line(sc, tm,
                                            "CERTIFICATE VERIFY SIGN",
                                            "serverCertVerifySign",
                                            tm->have_server_cert_verify,
                                            &tm->server_cert_verify);
        tm->server_cv_logged = 1;
    }
}

void ossl_quic_timing_server_cert_verify_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->server_cert_verify_active);
}

void ossl_quic_timing_server_handshake_build_begin(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = quic_timing_activate(sc);

    if (tm == NULL || tm->have_server_handshake_build)
        return;
    quic_timing_stage_begin(&tm->server_handshake_build_active,
                            &tm->server_handshake_build_start);
}

void ossl_quic_timing_server_handshake_build_complete(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_complete(&tm->server_handshake_build_active,
                               &tm->server_handshake_build_start,
                               &tm->have_server_handshake_build,
                               &tm->server_handshake_build);
    if (tm->have_server_handshake_build && !tm->server_hsbuild_logged) {
        quic_timing_emit_single_metric_line(sc, tm,
                                            "HANDSHAKE BUILD",
                                            "serverHandshakePreparation",
                                            tm->have_server_handshake_build,
                                            &tm->server_handshake_build);
        tm->server_hsbuild_logged = 1;
    }
}

void ossl_quic_timing_server_handshake_build_abort(SSL_CONNECTION *sc)
{
    QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

    if (tm == NULL)
        return;
    quic_timing_stage_abort(&tm->server_handshake_build_active);
}

static double quic_timing_to_ms(OSSL_TIME t)
{
    return (double)ossl_time2us(t) / 1000.0;
}

static void quic_timing_print_metric(FILE *stream, int *first,
                                     const char *name,
                                     int have_value,
                                     const OSSL_TIME *value)
{
    if (*first) {
        fputc(' ', stream);
        *first = 0;
    } else {
        fprintf(stream, " | ");
    }

    if (!have_value)
        fprintf(stream, "%s=N/A", name);
    else
        fprintf(stream, "%s=%.3fms", name, quic_timing_to_ms(*value));
}

static void quic_timing_print_header(FILE *stream, double display_ms,
                                     const char *role, const char *tag)
{
    fprintf(stream, "[%12.8f ms] [%s INTERNAL] [%s]", display_ms, role, tag);
}

static void quic_timing_maybe_log_server_hello_build(SSL_CONNECTION *sc,
                                                     QUIC_HANDSHAKE_TIMING *tm)
{
    FILE *stream;
    double display_ms;
    int first = 1;

    if (sc == NULL || tm == NULL || tm->server_shprep_logged
            || !tm->have_server_kex_latency
            || !tm->have_server_hello_preparation)
        return;

    stream = tm->log_stream != NULL ? tm->log_stream : stderr;
    display_ms = quic_timing_display_ms_from_now(ossl_time_now());

    quic_timing_print_header(stream, display_ms,
                             sc->server ? "SERVER" : "CLIENT",
                             "SERVER HELLO BUILD");
    quic_timing_print_metric(stream, &first,
                             "serverKeyExchangeLatency",
                             tm->have_server_kex_latency,
                             &tm->server_kex_latency);
    quic_timing_print_metric(stream, &first,
                             "serverHelloPreparation",
                             tm->have_server_hello_preparation,
                             &tm->server_hello_preparation);
    fputc('\n', stream);
    fflush(stream);
    ossl_quic_timing_flush_server_hello_line(sc, stream);
    tm->server_shprep_logged = 1;
    tm->server_client_logged = 1;
}

void ossl_quic_timing_maybe_emit_internal(const OSSL_QUIC_PACKET_LOG_EVENT *event,
                                          OSSL_TIME now,
                                          double display_ms,
                                          unsigned int tls_event_mask,
                                          OSSL_QUIC_TIMING_PHASE phase)
{
    SSL_CONNECTION *sc;
    QUIC_HANDSHAKE_TIMING *tm;
    const char *role;
    FILE *stream;
    int first;
    uint64_t hs_us = 0;
    double hs_ms = 0.0;
    int have_handshake_latency = 0;

    if (event == NULL || event->ssl == NULL || event->stream == NULL)
        return;

    sc = SSL_CONNECTION_FROM_SSL(event->ssl);
    tm = ossl_quic_timing_get(sc);
    if (tm == NULL)
        return;

    role = event->is_server ? "SERVER" : "CLIENT";
    stream = event->stream;
    tm->log_stream = stream;

    if (!event->is_server) {
        if (phase == OSSL_QUIC_TIMING_PHASE_BEFORE
                && !tm->client_ch_logged
                && event->is_send
                && tm->have_client_keyshare
                && tm->have_client_hello_build) {
            first = 1;
            quic_timing_print_header(stream, display_ms, role,
                                     "CLIENT HELLO BUILD");
            quic_timing_print_metric(stream, &first,
                                     "clientKeyshareGeneration",
                                     tm->have_client_keyshare,
                                     &tm->client_keyshare);
            quic_timing_print_metric(stream, &first,
                                     "clientHelloBuild",
                                     tm->have_client_hello_build,
                                     &tm->client_hello_build);
            fputc('\n', stream);
            fflush(stream);
            tm->client_ch_logged = 1;
        }

        if (phase == OSSL_QUIC_TIMING_PHASE_BEFORE
                && !tm->client_sh_logged
                && !event->is_send
                && tm->have_client_hello_rtt
                && tm->have_client_kex) {
            first = 1;
            quic_timing_print_header(stream, display_ms, role,
                                     "SERVER HELLO PROCESSED");
            quic_timing_print_metric(stream, &first,
                                     "clientHelloRoundTrip",
                                     tm->have_client_hello_rtt,
                                     &tm->client_hello_rtt);
            quic_timing_print_metric(stream, &first,
                                     "clientKeyExchangeLatency",
                                     tm->have_client_kex,
                                     &tm->client_kex);
            fputc('\n', stream);
            fflush(stream);
            tm->client_sh_logged = 1;
        }

        if (phase == OSSL_QUIC_TIMING_PHASE_BEFORE
                && !tm->client_hs_done_logged && tm->client_ready) {
            first = 1;
            if (SSL_get_handshake_rtt(event->ssl, &hs_us) == 1) {
                hs_ms = hs_us / 1000.0;
                have_handshake_latency = 1;
            }

            quic_timing_print_header(stream, display_ms, role,
                                     "HANDSHAKE DONE");
            if (first) {
                fputc(' ', stream);
                first = 0;
            } else {
                fputs(" | ", stream);
            }
            if (have_handshake_latency)
                fprintf(stream, "handshakeLatency=%.2fms", hs_ms);
            else
                fputs("handshakeLatency=N/A", stream);
            fputc('\n', stream);
            fflush(stream);
            ossl_quic_timing_flush_client_finished_line(sc, stream);
            tm->client_hs_done_logged = 1;
        }
        return;
    }

    if (phase == OSSL_QUIC_TIMING_PHASE_AFTER
            && !tm->server_validated_logged
            && !event->is_send
            && event->enc_level == QUIC_ENC_LEVEL_HANDSHAKE
            && tm->have_server_clienthello_time) {
        first = 1;
        tm->client_validation_delay
            = ossl_time_subtract(now, tm->server_clienthello_time);
        tm->have_client_validation_delay = 1;

        quic_timing_print_header(stream, display_ms, role,
                                 "CLIENT VALIDATED");
        quic_timing_print_metric(stream, &first,
                                 "clientValidationDelay",
                                 tm->have_client_validation_delay,
                                 &tm->client_validation_delay);
        if (first)
            fputc(' ', stream);
        else
            fputs(" | ", stream);
        fputs("serverCreditState=UNLIMITED", stream);
        fputc('\n', stream);
        fflush(stream);
        tm->server_validated_logged = 1;
        return;
    }

    if (phase == OSSL_QUIC_TIMING_PHASE_BEFORE
            && !tm->server_hs_done_logged
            && event->is_send
            && (tls_event_mask & TLS_EVENT_HANDSHAKE_DONE) != 0) {
        quic_timing_print_header(stream, display_ms, role, "HANDSHAKE DONE");
        fputc('\n', stream);
        fflush(stream);
        ossl_quic_timing_flush_server_hs_done_line(sc, stream);
        tm->server_hs_done_logged = 1;
    }
}

#endif /* OPENSSL_NO_QUIC */
