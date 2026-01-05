/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Portions of this file are derived from:
 *   "PQC-and-QUIC-Performance-analysis-and-trade-offs"
 *   Copyright (c) 2025 Ivan Starcevic — MIT License.
 *
 * Modifications: Copyright (c) 2025 Pedro Rigon
 * SPDX-License-Identifier: Apache-2.0 AND MIT
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/provider.h>
#ifdef _WIN32 /* Windows */
# include <winsock2.h>
# include <windows.h>
#else /* Linux/Unix */
# include <netinet/in.h>
# include <unistd.h>
# include <signal.h>
# include <sys/select.h>
# include <sys/time.h>
#endif
#include <assert.h>
#include <string.h> /* For strcmp */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* -------------------- Runtime-configurable behaviour -------------------- */

/* Default: close stream right after sending "hello" (original demo). */
#define DEFAULT_CLOSE_AFTER_HELLO 1

/* ----------------------------- Globals ---------------------------------- */

/* Flag is set when the user presses Ctrl+\ (SIGQUIT) to close the *current* connection. */
static volatile sig_atomic_t g_quit_received = 0;
static int g_server_debug_enabled = 0;
static double server_debug_wallclock_ms(void)
{
#ifdef _WIN32
    return (double)GetTickCount64();
#else
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

static void server_debug_log(const char *fmt, ...)
{
    va_list args;
    double elapsed_ms;

    if (!g_server_debug_enabled)
        return;

    elapsed_ms = server_debug_wallclock_ms();
    fprintf(stderr, "[DEBUG][%12.8f ms][SERVER][STATE] ", elapsed_ms);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);
}

static void quic_server_info_cb(const SSL *ssl, int where, int ret)
{
    if (!g_server_debug_enabled)
        return;

    if ((where & SSL_CB_HANDSHAKE_START) != 0)
        server_debug_log("Handshake start ssl=%p", (const void *)ssl);
    if ((where & SSL_CB_HANDSHAKE_DONE) != 0)
        server_debug_log("Handshake done ssl=%p ret=%d", (const void *)ssl, ret);
}

static void handle_sigquit(int sig)
{
    (void)sig;
    g_quit_received = 1; /* handled inside the echo loop */
}

#ifndef OPENSSL_NO_QUIC
static void log_quic_crypto_buffer_exceeded(SSL *conn, const char *context)
{
    SSL_CONN_CLOSE_INFO cc_info;

    if (conn == NULL || !SSL_is_quic(conn))
        return;

    if (!SSL_get_conn_close_info(conn, &cc_info, sizeof(cc_info)))
        return;

    if ((cc_info.flags & SSL_CONN_CLOSE_FLAG_TRANSPORT) == 0
            || cc_info.error_code != OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED)
        return;

    fprintf(stderr,
            "%s: QUIC transport error CRYPTO_BUFFER_EXCEEDED -- peer could not buffer the handshake payload.\n"
            "       Increase the configured QUIC CRYPTO buffer size to avoid this condition.\n",
            context);
}
#endif

/* ------------------------- TLS/QUIC helpers ----------------------------- */

/* ALPN string for TLS handshake */
static const unsigned char alpn_ossltest[] = {
    /* "\x08ossltest" (hex for EBCDIC resilience) */
    0x08, 0x6f, 0x73, 0x73, 0x6c, 0x74, 0x65, 0x73, 0x74
};

/* This callback validates and negotiates the desired ALPN on the server side. */
static int select_alpn(SSL *ssl,
                       const unsigned char **out, unsigned char *out_len,
                       const unsigned char *in, unsigned int in_len,
                       void *arg)
{
    (void)ssl;
    (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, out_len,
                              alpn_ossltest, sizeof(alpn_ossltest), in, in_len)
            != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ctx(const char *cert_path, const char *key_path,
                           const char *groups_list, int handshake_only)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /* Load certificate and corresponding private key. */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "couldn't load key file: %s\n", key_path);
        goto err;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "private key check failed\n");
        goto err;
    }

    /* Setup ALPN negotiation callback. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);

    /* Optionally set key exchange. */
    if (groups_list != NULL && groups_list[0] != '\0') {
        if (!SSL_CTX_set1_groups_list(ctx, groups_list)) {
            fprintf(stderr, "failed to set key exchange group list: %s\n",
                    groups_list);
            goto err;
        }
    }

    /* Para benchmark “frio”: sem resumption, sem tickets/0-RTT. */
    if (handshake_only) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
#if !defined(OPENSSL_NO_TLS1_3)
        SSL_CTX_set_num_tickets(ctx, 0);
#endif
        SSL_CTX_set_max_early_data(ctx, 0);
    }

    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket using given port. */
static int create_socket(uint16_t port)
{
    int fd = -1;
    struct sockaddr_in sa = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        goto err;
    }

    sa.sin_family  = AF_INET;
    sa.sin_port    = htons(port);

    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        goto err;
    }

    return fd;

err:
    if (fd >= 0)
        BIO_closesocket(fd);

    return -1;
}

/* Gracefully conclude the default stream by sending a FIN (no payload). */
static int conclude_default_stream(SSL *conn)
{
    /* Zero-length write with the CONCLUDE flag = FIN only. */
    return SSL_stream_conclude(conn, 0);
}

/*
 * Main loop for servicing a single incoming QUIC connection.
 *
 * If \p close_after_hello is non-zero the server behaves like the original
 * demo: send "hello\n" with FIN and tear down the connection.
 *
 * Otherwise the stream is kept open and the server enters an interactive echo
 * loop.  When the user hits Ctrl+C the server sends FIN to the client,
 * performs a clean shutdown, and returns so that it can wait for the next
 * connection.
 */
static int run_quic_conn(SSL *conn, int close_after_hello, int handshake_only)
{
    size_t written = 0;
    server_debug_log("Received connection %p", (void *)conn);

    if (handshake_only) {
        /* Handshake-only: esperar a handshake concluir e encerrar limpo. */
        if (!SSL_set_blocking_mode(conn, 0)) {
            fprintf(stderr, "failed to set non-blocking mode\n");
            return 0;
        }

        server_debug_log("Handshake-only: waiting for QUIC handshake on %p", (void *)conn);
        for (;;) {
            if (SSL_is_init_finished(conn))
                break;

            int fd = SSL_get_fd(conn);
            int want_rd = SSL_net_read_desired(conn);
            int want_wr = SSL_net_write_desired(conn);
            fd_set rfds, wfds;
            struct timeval tv, *tvp = NULL;
            int is_inf = 0;

            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            if (want_rd) FD_SET(fd, &rfds);
            if (want_wr) FD_SET(fd, &wfds);

            if (SSL_get_event_timeout(conn, &tv, &is_inf) && !is_inf)
                tvp = &tv;

            (void)select(fd + 1, want_rd ? &rfds : NULL,
                         want_wr ? &wfds : NULL, NULL, tvp);

            server_debug_log("Handshake-only: select wake (want_rd=%d want_wr=%d)",
                             want_rd, want_wr);
            SSL_handle_events(conn);
        }

        server_debug_log("Handshake-only: handshake complete, initiating shutdown for %p",
                         (void *)conn);

        /* Encerramento QUIC/TLS limpo. */
        for (;;) {
            int ret = SSL_shutdown(conn);
            if (ret == 1)
                break;               /* sucesso */
            if (ret == 0) {
                SSL_handle_events(conn);
                continue;            /* continuar a troca de fechamento */
            }
            ERR_print_errors_fp(stderr);
            return 0;                /* erro */
        }

        server_debug_log("Handshake-only: connection %p closed cleanly", (void *)conn);
        return 1;
    }

    if (close_after_hello) {
        /* Original behaviour: send greeting + FIN. */
        if (!SSL_write_ex2(conn, "hello\n", 6, SSL_WRITE_FLAG_CONCLUDE, &written)
            || written != 6) {
            fprintf(stderr, "couldn't write on connection\n");
            ERR_print_errors_fp(stderr);
            return 0;
        }

        if (SSL_shutdown(conn) != 1) {
            ERR_print_errors_fp(stderr);
            return 0;
        }

        server_debug_log("Finished hello-only connection %p", (void *)conn);
        return 1;
    }

    /* Keep-open mode: send greeting without FIN. */
    if (!SSL_write_ex(conn, "hello\n", 6, &written) || written != 6) {
        fprintf(stderr, "couldn't write greeting\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Turn the connection non-blocking for the echo loop. */
    if (!SSL_set_blocking_mode(conn, 0)) {
        fprintf(stderr, "failed to set non-blocking mode\n");
        return 0;
    }

    server_debug_log("Echo loop active for connection %p", (void *)conn);

    for (;;) {
        /* Detect Ctrl+\ request to close connection gracefully. */
        if (g_quit_received) {
            server_debug_log("SIGQUIT caught — closing connection %p", (void *)conn);
            conclude_default_stream(conn);
            SSL_shutdown(conn); /* Best-effort */
            g_quit_received = 0; /* Reset flag for next connection. */
            break;
        }

        char buf[2048];
        size_t readbytes = 0;
        int ret = SSL_read_ex(conn, buf, sizeof(buf), &readbytes);

        if (ret == 0) {
            /* QUIC stack wants more network I/O. */
            continue;
        }

        if (ret < 0) {
            int err = SSL_get_error(conn, ret);
            if (err == SSL_ERROR_ZERO_RETURN) {
                server_debug_log("Peer closed the connection");
                break;
            }
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue; /* Retry. */

            fprintf(stderr, "read error in echo loop\n");
            ERR_print_errors_fp(stderr);
            break;
        }

        /* Print what we got to stdout. */
        fwrite(buf, 1, readbytes, stdout);
        fflush(stdout);
    }

    /* Ensure proper closure if we exited without FIN. */
    if (!SSL_get_shutdown(conn)) {
        conclude_default_stream(conn);
        SSL_shutdown(conn);
    }

    server_debug_log("Finished connection %p", (void *)conn);
    return 1;
}

/* Main loop for server to accept QUIC connections. */
static int run_quic_server(SSL_CTX *ctx, int fd, int close_after_hello,
                           int handshake_only, int disable_addr_validation,
                           int unlimited_amplification)
{
    int ok = 0;
    SSL *listener = NULL, *conn = NULL;
    uint64_t listener_flags = 0;

    if (disable_addr_validation)
        listener_flags |= SSL_LISTENER_FLAG_NO_VALIDATE;

    if (unlimited_amplification)
        listener_flags |= SSL_LISTENER_FLAG_UNLIMITED_AMPLIFICATION;

    if ((listener = SSL_new_listener(ctx, listener_flags)) == NULL)
        goto err;

    if (!SSL_set_fd(listener, fd))
        goto err;

    if (!SSL_listen(listener))
        goto err;

    if (!SSL_set_blocking_mode(listener, 1))
        goto err;

    for (;;) {
        server_debug_log("Waiting for connection...");

        conn = SSL_accept_connection(listener, 0); /* blocking */
        if (conn == NULL) {
            fprintf(stderr, "error while accepting connection\n");
            goto err;
        }
        server_debug_log("Accepted connection handle %p", (void *)conn);

        {
            int conn_ok = run_quic_conn(conn, close_after_hello, handshake_only);
#ifndef OPENSSL_NO_QUIC
            log_quic_crypto_buffer_exceeded(conn, "server");
#endif
            if (!conn_ok) {
                SSL_free(conn);
                goto err;
            }
        }

        SSL_free(conn);
    }

    ok = 1;
err:
    if (!ok)
        ERR_print_errors_fp(stderr);

    SSL_free(listener);
    return ok;
}

/* ------------------------------ main() ---------------------------------- */
int main(int argc, char **argv)
{
    int rc = 1;
    SSL_CTX *ctx = NULL;
    int fd = -1;
    unsigned long port;
    int close_after_hello = DEFAULT_CLOSE_AFTER_HELLO;
    const char *groups_list = NULL;
    int handshake_only = 0;
    int disable_addr_validation = 1;  /* RFC 9000 default: no RETRY (1-RTT handshake) */
    int unlimited_amplification = 0;  /* For QUIC_MODE=1: disable anti-amplification */
    int enable_debug_logging = 0;
    int enable_packet_logging = 0;
    int argi;

    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <port> <server.crt> <server.key> [--keep-open]\n"
                "       [--groups <group-list>] [--handshake-only]\n"
                "       [--enable-retry] [--unlimited-amplification]\n"
                "       [--debug] [--packet-log]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    for (argi = 4; argi < argc; ++argi) {
        if (strcmp(argv[argi], "--keep-open") == 0) {
            close_after_hello = 0;
            continue;
        }

        if (strcmp(argv[argi], "--groups") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "--groups requires a value\n");
                return EXIT_FAILURE;
            }
            groups_list = argv[++argi];
            continue;
        }

        if (strcmp(argv[argi], "--handshake-only") == 0) {
            handshake_only = 1;
            continue;
        }

        if (strcmp(argv[argi], "--enable-retry") == 0) {
            disable_addr_validation = 0;  /* Enable validation = send RETRY */
            continue;
        }

        if (strcmp(argv[argi], "--unlimited-amplification") == 0) {
            unlimited_amplification = 1;
            continue;
        }
        if (strcmp(argv[argi], "--debug") == 0) {
            enable_debug_logging = 1;
            continue;
        }

        if (strcmp(argv[argi], "--packet-log") == 0) {
            enable_packet_logging = 1;
            continue;
        }

        fprintf(stderr, "unknown argument: %s\n", argv[argi]);
        fprintf(stderr,
                "usage: %s <port> <server.crt> <server.key> [--keep-open]\n"
                "       [--groups <group-list>] [--handshake-only]\n"
                "       [--enable-retry] [--unlimited-amplification]\n"
                "       [--debug] [--packet-log]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    /* Install Ctrl+C handler (only on non-Windows). */
#ifndef _WIN32
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigquit;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGQUIT, &sa, NULL);
#endif

    if (enable_debug_logging) {
        g_server_debug_enabled = 1;
        OSSL_QUIC_set_debug_role("SERVER");
        OSSL_QUIC_set_debug_mode(1);
        server_debug_log("Debug logging enabled");
    }

    if (enable_packet_logging || enable_debug_logging)
        OSSL_QUIC_set_packet_log_mode(1);

    /* Create SSL_CTX. */
    if ((ctx = create_ctx(argv[2], argv[3], groups_list, handshake_only)) == NULL)
        goto err;

    if (g_server_debug_enabled)
        SSL_CTX_set_info_callback(ctx, quic_server_info_cb);

    /* Parse port number. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port: %lu\n", port);
        goto err;
    }
    server_debug_log("Starting QUIC server on port %lu", port);

    /* Create UDP socket. */
    if ((fd = create_socket((uint16_t)port)) < 0)
        goto err;

    /* Run the QUIC server loop. */
    if (!run_quic_server(ctx, fd, close_after_hello, handshake_only, disable_addr_validation, unlimited_amplification))
        goto err;

    rc = 0;
err:
    if (rc != 0)
        ERR_print_errors_fp(stderr);

    SSL_CTX_free(ctx);

    if (fd != -1)
        BIO_closesocket(fd);

    return rc;
}
