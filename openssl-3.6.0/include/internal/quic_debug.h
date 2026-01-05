/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_QUIC_DEBUG_H
# define OSSL_INTERNAL_QUIC_DEBUG_H
# pragma once

# include <stdio.h>
# include <stdint.h>
# include <stddef.h>
# include <openssl/ssl.h>

# define TLS_EVENT_CLIENT_HELLO        0x0001u
# define TLS_EVENT_SERVER_HELLO        0x0002u
# define TLS_EVENT_ENCRYPTED_EXT       0x0004u
# define TLS_EVENT_CERTIFICATE         0x0008u
# define TLS_EVENT_CERT_VERIFY         0x0010u
# define TLS_EVENT_FINISHED            0x0020u
# define TLS_EVENT_HANDSHAKE_DONE      0x0040u

int ossl_quic_debug_enabled(void);
void ossl_quic_debug_set_enabled(int enabled);
void ossl_quic_debug_set_role(const char *role);
void ossl_quic_debug_log(FILE *stream, const char *component,
                         const char *fmt, ...);

typedef struct ossl_quic_packet_log_event_st {
    FILE *stream;
    int is_server;
    int is_send;
    uint32_t enc_level;
    const char *packet_type;
    uint64_t packet_number;
    size_t datagram_size;
    const unsigned char *payload;
    size_t payload_len;
    int have_credit_before;
    size_t credit_before;
    int credit_before_unlimited;
    int have_credit_after;
    size_t credit_after;
    int credit_after_unlimited;
    int client_credit_known;
    int client_credit_unlimited;
    int have_credit_delta;
    long long credit_delta;
    SSL *ssl;
} OSSL_QUIC_PACKET_LOG_EVENT;

int ossl_quic_packet_log_enabled(void);
void ossl_quic_packet_log_set_enabled(int enabled);
void ossl_quic_packet_log(const OSSL_QUIC_PACKET_LOG_EVENT *event);
const char *ossl_quic_packet_type_name(uint32_t type);

# define OSSL_QUIC_DEBUG_LOG(stream, component, ...)                         \
    do {                                                                     \
        if (ossl_quic_debug_enabled())                                       \
            ossl_quic_debug_log((stream), (component), __VA_ARGS__);         \
    } while (0)

#endif /* OSSL_INTERNAL_QUIC_DEBUG_H */
