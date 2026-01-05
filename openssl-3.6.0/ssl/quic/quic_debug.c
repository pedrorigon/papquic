/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/ssl3.h>
#include <openssl/x509.h>
#include "internal/time.h"
#include "internal/quic_debug.h"
#include "internal/quic_wire.h"
#include "internal/quic_wire_pkt.h"
#include "internal/ssl_unwrap.h"
#include "internal/quic_types.h"
#include "internal/packet.h"
#include "internal/nelem.h"
#include "internal/tlsgroups.h"
#include "../ssl_local.h"

static unsigned int g_quic_log_modes = 0;
static char g_quic_log_role[32] = "QUIC";

#define PACKET_LOG_ROLE_CLIENT 0
#define PACKET_LOG_ROLE_SERVER 1
#define PACKET_LOG_DIR_RECV    0
#define PACKET_LOG_DIR_SEND    1

typedef struct {
    int active;
    unsigned int hs_type;
    size_t remaining;
    BUF_MEM *buffer;
    size_t total_len;
    size_t collected;
} PACKET_LOG_HS_STATE;

static PACKET_LOG_HS_STATE g_hs_state[2][2][QUIC_ENC_LEVEL_NUM];

typedef struct {
    int have_label;
    int have_detail;
    int have_packet_note;
    char label[64];
    char detail[512];
    char packet_note[256];
} TLS_HANDSHAKE_METADATA;

static TLS_HANDSHAKE_METADATA g_tls_metadata[256];

typedef struct {
    int have_detail;
    char detail[128];
} PACKET_LOG_MISC_METADATA;

static PACKET_LOG_MISC_METADATA g_handshake_done_meta;

#define QUIC_LOG_MODE_DEBUG   0x1u
#define QUIC_LOG_MODE_PACKET  0x2u

static void packet_log_reset_hs_state(PACKET_LOG_HS_STATE *state)
{
    if (state == NULL)
        return;

    state->active = 0;
    state->hs_type = 0;
    state->remaining = 0;
    state->total_len = 0;
    state->collected = 0;
    if (state->buffer != NULL) {
        BUF_MEM_free(state->buffer);
        state->buffer = NULL;
    }
}

static TLS_HANDSHAKE_METADATA *packet_log_get_metadata_slot(unsigned int hs_type)
{
    if (hs_type >= OSSL_NELEM(g_tls_metadata))
        return NULL;
    return &g_tls_metadata[hs_type];
}

static void packet_log_set_label(unsigned int hs_type, const char *label)
{
    TLS_HANDSHAKE_METADATA *slot = packet_log_get_metadata_slot(hs_type);

    if (slot == NULL || label == NULL)
        return;

    slot->have_label = 1;
    OPENSSL_strlcpy(slot->label, label, sizeof(slot->label));
}

static void packet_log_set_detail(unsigned int hs_type, const char *detail)
{
    TLS_HANDSHAKE_METADATA *slot = packet_log_get_metadata_slot(hs_type);

    if (slot == NULL || detail == NULL)
        return;

    slot->have_detail = 1;
    OPENSSL_strlcpy(slot->detail, detail, sizeof(slot->detail));
}

static void packet_log_set_packet_note(unsigned int hs_type,
                                       const char *note)
{
    TLS_HANDSHAKE_METADATA *slot = packet_log_get_metadata_slot(hs_type);

    if (slot == NULL || note == NULL)
        return;

    slot->have_packet_note = 1;
    OPENSSL_strlcpy(slot->packet_note, note, sizeof(slot->packet_note));
}

static void packet_log_record_metadata(unsigned int hs_type,
                                       const char *label,
                                       const char *detail,
                                       const char *packet_note)
{
    if (label != NULL)
        packet_log_set_label(hs_type, label);
    if (detail != NULL)
        packet_log_set_detail(hs_type, detail);
    if (packet_note != NULL)
        packet_log_set_packet_note(hs_type, packet_note);
}

static unsigned int packet_log_event_mask_for_type(unsigned int hs_type)
{
    switch (hs_type) {
    case 1:
        return TLS_EVENT_CLIENT_HELLO;
    case 2:
        return TLS_EVENT_SERVER_HELLO;
    case 8:
        return TLS_EVENT_ENCRYPTED_EXT;
    case 11:
        return TLS_EVENT_CERTIFICATE;
    case 15:
        return TLS_EVENT_CERT_VERIFY;
    case 20:
        return TLS_EVENT_FINISHED;
    default:
        return 0;
    }
}

typedef struct {
    uint16_t id;
    const char *name;
} TLS_NUM_NAME;

#define TLS_GROUP_X25519        0x001D
#define TLS_GROUP_X448          0x001E
#define TLS_GROUP_SECP256R1     0x0017
#define TLS_GROUP_SECP384R1     0x0018
#define TLS_GROUP_SECP521R1     0x0019
#define TLS_GROUP_FFDHE2048     0x0100
#define TLS_GROUP_FFDHE3072     0x0101
#define TLS_GROUP_FFDHE4096     0x0102
#define TLS_GROUP_FFDHE6144     0x0103
#define TLS_GROUP_FFDHE8192     0x0104

static const TLS_NUM_NAME kGroupNameMap[] = {
    { TLS_GROUP_X25519,        "x25519" },
    { TLS_GROUP_X448,          "x448" },
    { TLS_GROUP_SECP256R1,     "secp256r1" },
    { TLS_GROUP_SECP384R1,     "secp384r1" },
    { TLS_GROUP_SECP521R1,     "secp521r1" },
    { TLS_GROUP_FFDHE2048,     "ffdhe2048" },
    { TLS_GROUP_FFDHE3072,     "ffdhe3072" },
    { TLS_GROUP_FFDHE4096,     "ffdhe4096" },
    { TLS_GROUP_FFDHE6144,     "ffdhe6144" },
    { TLS_GROUP_FFDHE8192,     "ffdhe8192" },
    /* Pure ML-KEM */
    { OSSL_TLS_GROUP_ID_mlkem512,  "mlkem512" },
    { OSSL_TLS_GROUP_ID_mlkem768,  "mlkem768" },
    { OSSL_TLS_GROUP_ID_mlkem1024, "mlkem1024" },
    /* ML-KEM hybrids */
    { 0x2F4B, "p256_mlkem512" },
    { 0x2FB6, "x25519_mlkem512" },
    { 0x2F4C, "p384_mlkem768" },
    { 0x2FB7, "x448_mlkem768" },
    { 0x2F4D, "p521_mlkem1024" },
    { 0x11EB, "secp256r1mlkem768" },
    { 0x11EC, "x25519mlkem768" },
    { 0x11ED, "secp384r1mlkem1024" },
    { 0xFE40, "bp256_mlkem512" },
    { 0xFE41, "bp384_mlkem768" },
    { 0xFE42, "bp512_mlkem1024" },
    /* FrodoKEM pure + hybrids */
    { 0xFE00, "frodo640aes" },
    { 0xFE01, "p256_frodo640aes" },
    { 0xFE02, "x25519_frodo640aes" },
    { 0xFE03, "frodo640shake" },
    { 0xFE04, "p256_frodo640shake" },
    { 0xFE05, "x25519_frodo640shake" },
    { 0xFE06, "frodo976aes" },
    { 0xFE07, "p384_frodo976aes" },
    { 0xFE08, "x448_frodo976aes" },
    { 0xFE09, "frodo976shake" },
    { 0xFE0A, "p384_frodo976shake" },
    { 0xFE0B, "x448_frodo976shake" },
    { 0xFE0C, "frodo1344aes" },
    { 0xFE0D, "p521_frodo1344aes" },
    { 0xFE0E, "frodo1344shake" },
    { 0xFE0F, "p521_frodo1344shake" },
    /* BIKE pure + hybrids */
    { 0xFE10, "bikel1" },
    { 0xFE11, "p256_bikel1" },
    { 0xFE12, "x25519_bikel1" },
    { 0xFE13, "bikel3" },
    { 0xFE14, "p384_bikel3" },
    { 0xFE15, "x448_bikel3" },
    { 0xFE16, "bikel5" },
    { 0xFE17, "p521_bikel5" },
    /* HQC pure + hybrids (legacy and current code points) */
    { 0x022C, "hqc128" },
    { 0x2F2C, "p256_hqc128" },
    { 0x2FAC, "x25519_hqc128" },
    { 0x022D, "hqc192" },
    { 0x2F2D, "p384_hqc192" },
    { 0x2FAD, "x448_hqc192" },
    { 0x022E, "hqc256" },
    { 0x2F2E, "p521_hqc256" },
    { 0xFE18, "hqc128" },
    { 0xFE19, "p256_hqc128" },
    { 0xFE1A, "x25519_hqc128" },
    { 0xFE1B, "hqc192" },
    { 0xFE1C, "p384_hqc192" },
    { 0xFE1D, "x448_hqc192" },
    { 0xFE1E, "hqc256" },
    { 0xFE1F, "p521_hqc256" },
};

static const char *tls_group_name_from_id(uint16_t group_id)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(kGroupNameMap); ++i)
        if (kGroupNameMap[i].id == group_id)
            return kGroupNameMap[i].name;
    return NULL;
}

static void format_group_name(uint16_t group_id, char *buf, size_t buf_len)
{
    const char *name = tls_group_name_from_id(group_id);

    if (name != NULL) {
        OPENSSL_strlcpy(buf, name, buf_len);
        return;
    }

    BIO_snprintf(buf, buf_len, "0x%04x", group_id);
}

static const TLS_NUM_NAME kCipherNameMap[] = {
    { TLS1_3_CK_AES_128_GCM_SHA256 & 0xffff, TLS1_3_RFC_AES_128_GCM_SHA256 },
    { TLS1_3_CK_AES_256_GCM_SHA384 & 0xffff, TLS1_3_RFC_AES_256_GCM_SHA384 },
    { TLS1_3_CK_CHACHA20_POLY1305_SHA256 & 0xffff, "TLS_CHACHA20_POLY1305_SHA256" },
    { TLS1_3_CK_AES_128_CCM_SHA256 & 0xffff, "TLS_AES_128_CCM_SHA256" },
    { TLS1_3_CK_AES_128_CCM_8_SHA256 & 0xffff, "TLS_AES_128_CCM_8_SHA256" },
};

static const char *tls_cipher_name(uint16_t cipher)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(kCipherNameMap); ++i)
        if (kCipherNameMap[i].id == cipher)
            return kCipherNameMap[i].name;
    return "UNKNOWN";
}

static const char *tls_version_name(uint16_t version)
{
    switch (version) {
    case TLS1_3_VERSION:
        return "TLS1.3";
    case TLS1_2_VERSION:
        return "TLS1.2";
    case TLS1_1_VERSION:
        return "TLS1.1";
    case TLS1_VERSION:
        return "TLS1.0";
    default:
        return "UNKNOWN";
    }
}

static const TLS_NUM_NAME kSigAlgNameMap[] = {
    { 0x0403, "ECDSA_secp256r1_SHA256" },
    { 0x0503, "ECDSA_secp384r1_SHA384" },
    { 0x0603, "ECDSA_secp521r1_SHA512" },
    { 0x0804, "RSA_PSS_RSAE_SHA256" },
    { 0x0805, "RSA_PSS_RSAE_SHA384" },
    { 0x0806, "RSA_PSS_RSAE_SHA512" },
    { 0x0807, "ed25519" },
    { 0x0808, "ed448" },
    { 0x0904, "mldsa44" },
    { 0x0905, "mldsa65" },
    { 0x0906, "mldsa87" },
    { 0xff06, "p256_mldsa44" },
    { 0xff07, "rsa3072_mldsa44" },
    { 0xff08, "p384_mldsa65" },
    { 0xff09, "p521_mldsa87" },
    { 0xfed7, "falcon512" },
    { 0xfed8, "p256_falcon512" },
    { 0xfed9, "rsa3072_falcon512" },
    { 0xfedc, "falconpadded512" },
    { 0xfedd, "p256_falconpadded512" },
    { 0xfede, "rsa3072_falconpadded512" },
    { 0xfeda, "falcon1024" },
    { 0xfedb, "p521_falcon1024" },
    { 0xfedf, "falconpadded1024" },
    { 0xfee0, "p521_falconpadded1024" },
    { 0xfeb3, "sphincssha2128fsimple" },
    { 0xfeb4, "p256_sphincssha2128fsimple" },
    { 0xfeb5, "rsa3072_sphincssha2128fsimple" },
    { 0xfeb6, "sphincssha2128ssimple" },
    { 0xfeb7, "p256_sphincssha2128ssimple" },
    { 0xfeb8, "rsa3072_sphincssha2128ssimple" },
    { 0xfeb9, "sphincssha2192fsimple" },
    { 0xfeba, "p384_sphincssha2192fsimple" },
    { 0xfec2, "sphincsshake128fsimple" },
    { 0xfec3, "p256_sphincsshake128fsimple" },
    { 0xfec4, "rsa3072_sphincsshake128fsimple" },
    { 0xfec1, "p521_sphincssha2256ssimple" },
};

static const char *tls_sigalg_name(uint16_t scheme, char *buf, size_t buf_len)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(kSigAlgNameMap); ++i)
        if (kSigAlgNameMap[i].id == scheme)
            return kSigAlgNameMap[i].name;

    BIO_snprintf(buf, buf_len, "0x%04x", scheme);
    return buf;
}

static void packet_log_append_token(char *buf, size_t buf_len,
                                    const char *token)
{
    if (token == NULL || token[0] == '\0')
        return;

    if (buf[0] != '\0')
        OPENSSL_strlcat(buf, ", ", buf_len);
    OPENSSL_strlcat(buf, token, buf_len);
}

static void packet_log_format_version_list(PACKET *versions,
                                           char *buf, size_t buf_len)
{
    PACKET tmp = *versions;
    size_t count = 0;

    buf[0] = '\0';
    while (PACKET_remaining(&tmp) >= 2) {
        unsigned int version = 0;

        if (!PACKET_get_net_2(&tmp, &version))
            break;
        packet_log_append_token(buf, buf_len,
                                tls_version_name((uint16_t)version));
        if (++count >= 4 && PACKET_remaining(&tmp) >= 2) {
            packet_log_append_token(buf, buf_len, "...");
            break;
        }
    }
}

static void packet_log_format_group_vector(PACKET *groups,
                                           char *buf, size_t buf_len)
{
    PACKET tmp = *groups;
    size_t count = 0;
    char name_buf[32];

    buf[0] = '\0';
    while (PACKET_remaining(&tmp) >= 2) {
        unsigned int group_id = 0;

        if (!PACKET_get_net_2(&tmp, &group_id))
            break;
        format_group_name((uint16_t)group_id, name_buf, sizeof(name_buf));
        packet_log_append_token(buf, buf_len, name_buf);
        if (++count >= 5 && PACKET_remaining(&tmp) >= 2) {
            packet_log_append_token(buf, buf_len, "...");
            break;
        }
    }
}

static void packet_log_format_sigalg_vector(PACKET *sigpkt,
                                            char *buf, size_t buf_len)
{
    PACKET tmp = *sigpkt;
    size_t count = 0;
    char name_buf[32];

    buf[0] = '\0';
    while (PACKET_remaining(&tmp) >= 2) {
        unsigned int scheme = 0;
        const char *name;

        if (!PACKET_get_net_2(&tmp, &scheme))
            break;
        name = tls_sigalg_name((uint16_t)scheme, name_buf, sizeof(name_buf));
        packet_log_append_token(buf, buf_len, name);
        if (++count >= 5 && PACKET_remaining(&tmp) >= 2) {
            packet_log_append_token(buf, buf_len, "...");
            break;
        }
    }
}

static void packet_log_parse_client_hello(const unsigned char *body,
                                          size_t len)
{
    PACKET pkt, session_id, cipher_suites, comp_methods, extensions;
    unsigned int first_cipher = 0;
    unsigned int keyshare_group = 0;
    size_t keyshare_len = 0;
    char keyshare_label[32] = "";
    char sigalgs_buf[256];
    char groups_buf[256];
    char versions_buf[128];
    char detail[512];
    char packet_note[256];

    if (!PACKET_buf_init(&pkt, body, len))
        return;
    if (!PACKET_forward(&pkt, 2 + 32))
        return;
    if (!PACKET_get_length_prefixed_1(&pkt, &session_id))
        return;
    if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites))
        return;
    if (PACKET_remaining(&cipher_suites) >= 2)
        (void)PACKET_get_net_2(&cipher_suites, &first_cipher);
    if (!PACKET_get_length_prefixed_1(&pkt, &comp_methods))
        return;
    if (!PACKET_get_length_prefixed_2(&pkt, &extensions))
        return;

    sigalgs_buf[0] = '\0';
    groups_buf[0] = '\0';
    versions_buf[0] = '\0';

    while (PACKET_remaining(&extensions) > 0) {
        unsigned int ext_type = 0;
        PACKET ext_data;

        if (!PACKET_get_net_2(&extensions, &ext_type)
                || !PACKET_get_length_prefixed_2(&extensions, &ext_data))
            return;

        switch (ext_type) {
        case TLSEXT_TYPE_key_share:
            {
                PACKET shares, key;

                if (!PACKET_get_length_prefixed_2(&ext_data, &shares))
                    break;
                if (!PACKET_get_net_2(&shares, &keyshare_group)
                        || !PACKET_get_length_prefixed_2(&shares, &key))
                    break;
                keyshare_len = PACKET_remaining(&key);
                format_group_name((uint16_t)keyshare_group, keyshare_label,
                                  sizeof(keyshare_label));
            }
            break;
        case TLSEXT_TYPE_signature_algorithms:
            {
                PACKET sigpkt = ext_data;

                packet_log_format_sigalg_vector(&sigpkt, sigalgs_buf,
                                                sizeof(sigalgs_buf));
            }
            break;
        case TLSEXT_TYPE_supported_groups:
            {
                PACKET grpvec = ext_data;

                packet_log_format_group_vector(&grpvec, groups_buf,
                                               sizeof(groups_buf));
            }
            break;
        case TLSEXT_TYPE_supported_versions:
            {
                PACKET verlist;

                if (!PACKET_get_length_prefixed_1(&ext_data, &verlist))
                    break;
                packet_log_format_version_list(&verlist, versions_buf,
                                               sizeof(versions_buf));
            }
            break;
        default:
            break;
        }
    }

    if (keyshare_label[0] == '\0')
        OPENSSL_strlcpy(keyshare_label, "UNKNOWN", sizeof(keyshare_label));
    if (sigalgs_buf[0] == '\0')
        OPENSSL_strlcpy(sigalgs_buf, "unknown", sizeof(sigalgs_buf));

    BIO_snprintf(detail, sizeof(detail),
                 "KeyShare=%s(%zuB) | Cipher[0]=%s | SigAlgs=[%s]",
                 keyshare_label, keyshare_len,
                 tls_cipher_name((uint16_t)first_cipher), sigalgs_buf);
    if (versions_buf[0] != '\0') {
        OPENSSL_strlcat(detail, " | Versions=[", sizeof(detail));
        OPENSSL_strlcat(detail, versions_buf, sizeof(detail));
        OPENSSL_strlcat(detail, "]", sizeof(detail));
    }
    if (groups_buf[0] != '\0') {
        OPENSSL_strlcat(detail, " | Groups=[", sizeof(detail));
        OPENSSL_strlcat(detail, groups_buf, sizeof(detail));
        OPENSSL_strlcat(detail, "]", sizeof(detail));
    }

    BIO_snprintf(packet_note, sizeof(packet_note),
                 "KeyShare=%s(%zuB) , Cipher[0]=%s",
                 keyshare_label, keyshare_len,
                 tls_cipher_name((uint16_t)first_cipher));

    packet_log_record_metadata(SSL3_MT_CLIENT_HELLO, keyshare_label, detail,
                               packet_note);
}

static void packet_log_parse_server_hello(const unsigned char *body,
                                          size_t len)
{
    PACKET pkt, session_id, extensions;
    unsigned int cipher_suite = 0;
    char label[32] = "";
    size_t keyshare_len = 0;
    char detail[256];
    char packet_note[256];

    if (!PACKET_buf_init(&pkt, body, len))
        return;
    if (!PACKET_forward(&pkt, 2 + 32))
        return;
    if (!PACKET_get_length_prefixed_1(&pkt, &session_id))
        return;
    if (!PACKET_get_net_2(&pkt, &cipher_suite))
        return;
    if (!PACKET_forward(&pkt, 1))
        return;
    if (!PACKET_get_length_prefixed_2(&pkt, &extensions))
        return;

    while (PACKET_remaining(&extensions) > 0) {
        unsigned int ext_type = 0;
        PACKET ext_data;

        if (!PACKET_get_net_2(&extensions, &ext_type)
                || !PACKET_get_length_prefixed_2(&extensions, &ext_data))
            return;

        if (ext_type == TLSEXT_TYPE_key_share) {
            PACKET key;
            unsigned int group_id = 0;

            if (!PACKET_get_net_2(&ext_data, &group_id))
                break;
            if (PACKET_remaining(&ext_data) == 0) {
                keyshare_len = 0;
                format_group_name((uint16_t)group_id, label, sizeof(label));
                continue;
            }
            if (!PACKET_get_length_prefixed_2(&ext_data, &key))
                break;
            keyshare_len = PACKET_remaining(&key);
            format_group_name((uint16_t)group_id, label, sizeof(label));
            break;
        }
    }

    if (label[0] == '\0')
        OPENSSL_strlcpy(label, "UNKNOWN", sizeof(label));
    BIO_snprintf(detail, sizeof(detail),
                 "KeyShare=%s(%zuB) | Cipher=%s",
                 label, keyshare_len,
                 tls_cipher_name((uint16_t)cipher_suite));
    BIO_snprintf(packet_note, sizeof(packet_note),
                 "KeyShare=%s(%zuB) , Cipher=%s",
                 label, keyshare_len,
                 tls_cipher_name((uint16_t)cipher_suite));

    packet_log_record_metadata(SSL3_MT_SERVER_HELLO, label, detail,
                               packet_note);
}

static void packet_log_parse_encrypted_extensions(const unsigned char *body,
                                                  size_t len)
{
    PACKET pkt, ext_block;
    unsigned int ext_count = 0;
    char detail[128];
    size_t payload_len = 0;

    if (!PACKET_buf_init(&pkt, body, len))
        return;
    if (!PACKET_get_length_prefixed_2(&pkt, &ext_block))
        return;

    payload_len = PACKET_remaining(&ext_block);

    while (PACKET_remaining(&ext_block) > 0) {
        unsigned int ext_type = 0;
        PACKET ext_data;

        if (!PACKET_get_net_2(&ext_block, &ext_type)
                || !PACKET_get_length_prefixed_2(&ext_block, &ext_data))
            return;
        ++ext_count;
    }

    BIO_snprintf(detail, sizeof(detail),
                 "Extensions=%u | Payload=%zuB",
                 ext_count, payload_len);
    packet_log_record_metadata(SSL3_MT_ENCRYPTED_EXTENSIONS, NULL, detail, NULL);
}

static void packet_log_parse_certificate(const unsigned char *body,
                                         size_t len)
{
    PACKET pkt, context, cert_list, cert_bytes, extensions;
    size_t chain_len = 0;
    size_t leaf_len = 0;
    char sigalg_buf[64];
    char detail[256];
    const unsigned char *der = NULL;
    X509 *x = NULL;
    int sig_nid = NID_undef;

    if (!PACKET_buf_init(&pkt, body, len))
        return;
    if (!PACKET_get_length_prefixed_1(&pkt, &context))
        return;
    if (!PACKET_get_length_prefixed_3(&pkt, &cert_list))
        return;

    chain_len = PACKET_remaining(&cert_list);
    if (chain_len == 0) {
        packet_log_record_metadata(SSL3_MT_CERTIFICATE, "NONE",
                                   "Empty certificate list", NULL);
        return;
    }

    if (!PACKET_get_length_prefixed_3(&cert_list, &cert_bytes))
        goto end;
    leaf_len = PACKET_remaining(&cert_bytes);
    der = PACKET_data(&cert_bytes);
    x = d2i_X509(NULL, &der, (long)leaf_len);
    if (x != NULL)
        sig_nid = X509_get_signature_nid(x);
    (void)PACKET_get_length_prefixed_2(&cert_list, &extensions);

    if (sig_nid != NID_undef) {
        const char *sig_name = OBJ_nid2sn(sig_nid);

        if (sig_name != NULL)
            OPENSSL_strlcpy(sigalg_buf, sig_name, sizeof(sigalg_buf));
        else
            BIO_snprintf(sigalg_buf, sizeof(sigalg_buf), "NID-%d", sig_nid);
    } else {
        OPENSSL_strlcpy(sigalg_buf, "UNKNOWN", sizeof(sigalg_buf));
    }

    BIO_snprintf(detail, sizeof(detail),
                 "Chain=%zuB | Leaf=%zuB | LeafSig=%s",
                 chain_len, leaf_len, sigalg_buf);
    {
        char packet_note[256];

        BIO_snprintf(packet_note, sizeof(packet_note),
                     "LeafSig=%s ,  Leaf=%zuB",
                     sigalg_buf, leaf_len);
        packet_log_record_metadata(SSL3_MT_CERTIFICATE, sigalg_buf, detail,
                                   packet_note);
    }

 end:
    X509_free(x);
}

static void packet_log_parse_certificate_verify(const unsigned char *body,
                                                size_t len)
{
    PACKET pkt, signature;
    unsigned int scheme = 0;
    char name_buf[32];
    char detail[160];
    const char *name;

    if (!PACKET_buf_init(&pkt, body, len))
        return;
    if (!PACKET_get_net_2(&pkt, &scheme))
        return;
    if (!PACKET_get_length_prefixed_2(&pkt, &signature))
        return;

    name = tls_sigalg_name((uint16_t)scheme, name_buf, sizeof(name_buf));
    BIO_snprintf(detail, sizeof(detail),
                 "Algorithm=%s | Signature=%zuB",
                 name, PACKET_remaining(&signature));
    {
        char packet_note[160];

        BIO_snprintf(packet_note, sizeof(packet_note),
                     "Algorithm=%s , Signature=%zuB",
                     name, PACKET_remaining(&signature));
        packet_log_record_metadata(SSL3_MT_CERTIFICATE_VERIFY, name, detail,
                                   packet_note);
    }
}

static void packet_log_parse_finished(const unsigned char *body, size_t len)
{
    char detail[96];

    BIO_snprintf(detail, sizeof(detail),
                 "VerifyData=%zuB", len);
    packet_log_record_metadata(SSL3_MT_FINISHED, NULL, detail, NULL);
}

static void packet_log_process_handshake_message(unsigned int hs_type,
                                                 const unsigned char *body,
                                                 size_t len)
{
    switch (hs_type) {
    case SSL3_MT_CLIENT_HELLO:
        packet_log_parse_client_hello(body, len);
        break;
    case SSL3_MT_SERVER_HELLO:
        packet_log_parse_server_hello(body, len);
        break;
    case SSL3_MT_ENCRYPTED_EXTENSIONS:
        packet_log_parse_encrypted_extensions(body, len);
        break;
    case SSL3_MT_CERTIFICATE:
        packet_log_parse_certificate(body, len);
        break;
    case SSL3_MT_CERTIFICATE_VERIFY:
        packet_log_parse_certificate_verify(body, len);
        break;
    case SSL3_MT_FINISHED:
        packet_log_parse_finished(body, len);
        break;
    default:
        break;
    }
}

static void packet_log_start_hs_message(PACKET_LOG_HS_STATE *state,
                                        unsigned int hs_type,
                                        size_t total_len)
{
    if (state == NULL)
        return;

    packet_log_reset_hs_state(state);
    state->hs_type = hs_type;
    state->total_len = total_len;
    state->remaining = total_len;
    state->collected = 0;
    state->active = (total_len > 0);

    if (total_len == 0)
        return;

    state->buffer = BUF_MEM_new();
    if (state->buffer == NULL)
        return;
    if (BUF_MEM_grow_clean(state->buffer, total_len) == 0) {
        BUF_MEM_free(state->buffer);
        state->buffer = NULL;
    }
}

static void packet_log_append_hs_chunk(PACKET_LOG_HS_STATE *state,
                                       const unsigned char *data,
                                       size_t chunk_len)
{
    if (state == NULL || chunk_len == 0)
        return;

    if (state->buffer != NULL
            && state->collected + chunk_len <= state->total_len)
        memcpy(state->buffer->data + state->collected, data, chunk_len);

    state->collected += chunk_len;
    if (state->remaining >= chunk_len)
        state->remaining -= chunk_len;
    else
        state->remaining = 0;

    state->active = (state->remaining > 0);
}

static unsigned int packet_log_finish_hs_message(PACKET_LOG_HS_STATE *state,
                                                 unsigned int *tls_event_mask)
{
    unsigned int hs_type = 0;

    if (state == NULL)
        return 0;

    hs_type = state->hs_type;

    if (state->buffer != NULL && state->total_len == state->collected)
        packet_log_process_handshake_message(state->hs_type,
                                             (unsigned char *)state->buffer->data,
                                             state->total_len);

    if (tls_event_mask != NULL)
        *tls_event_mask |= packet_log_event_mask_for_type(state->hs_type);

    packet_log_reset_hs_state(state);
    return hs_type;
}



static void quic_log_enable_mode(unsigned int mode)
{
    if (mode == 0)
        return;

    g_quic_log_modes |= mode;
}

static void quic_log_disable_mode(unsigned int mode)
{
    if (mode == 0)
        return;

    g_quic_log_modes &= ~mode;
}

static double quic_log_wallclock_ms(OSSL_TIME now)
{
    uint64_t ticks = ossl_time2ticks(now);
    return (double)ticks / 1000000.0; /* nanoseconds -> milliseconds */
}

int ossl_quic_debug_enabled(void)
{
    return (g_quic_log_modes & QUIC_LOG_MODE_DEBUG) != 0;
}

void ossl_quic_debug_set_enabled(int enabled)
{
    if (enabled)
        quic_log_enable_mode(QUIC_LOG_MODE_DEBUG);
    else
        quic_log_disable_mode(QUIC_LOG_MODE_DEBUG);
}

void ossl_quic_debug_set_role(const char *role)
{
    const char *selected = (role == NULL || role[0] == '\0') ? "QUIC" : role;

    OPENSSL_strlcpy(g_quic_log_role, selected, sizeof(g_quic_log_role));
}

void ossl_quic_debug_log(FILE *stream, const char *component,
                         const char *fmt, ...)
{
    va_list args;
    OSSL_TIME now;
    double elapsed_ms;

    if (!ossl_quic_debug_enabled())
        return;

    now = ossl_time_now();
    elapsed_ms = quic_log_wallclock_ms(now);

    if (component == NULL)
        component = "QUIC";

    fprintf(stream, "[DEBUG][%12.8f ms][%s][%s] ",
            elapsed_ms, g_quic_log_role, component);
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);
    fputc('\n', stream);
    fflush(stream);
}

int ossl_quic_packet_log_enabled(void)
{
    return (g_quic_log_modes & QUIC_LOG_MODE_PACKET) != 0;
}

void ossl_quic_packet_log_set_enabled(int enabled)
{
    if (enabled)
        quic_log_enable_mode(QUIC_LOG_MODE_PACKET);
    else
        quic_log_disable_mode(QUIC_LOG_MODE_PACKET);
}

static const char *tls_handshake_fragment_name(unsigned int hs_type)
{
    switch (hs_type) {
    case 0:
        return "HelloRequest";
    case 1:
        return "ClientHello";
    case 2:
        return "ServerHello";
    case 4:
        return "NewSessionTicket";
    case 6:
        return "HelloRetryRequest";
    case 8:
        return "EncryptedExtensions";
    case 11:
        return "Certificate";
    case 13:
        return "CertificateRequest";
    case 14:
        return "ServerHelloDone";
    case 15:
        return "CertificateVerify";
    case 20:
        return "Finished";
    case 24:
        return "KeyUpdate";
    case 254:
        return "MessageHash";
    default:
        return "UNKNOWN";
    }
}

static const char *packet_log_format_bytes(char *buf, size_t buf_len, size_t value)
{
    BIO_snprintf(buf, buf_len, "%zuB", value);
    return buf;
}

#define PACKET_LOG_MAX_ACK_RANGES 32

static PACKET_LOG_HS_STATE *packet_log_get_hs_state(
    const OSSL_QUIC_PACKET_LOG_EVENT *event)
{
    int role_idx, dir_idx;

    if (event == NULL || event->enc_level >= QUIC_ENC_LEVEL_NUM)
        return NULL;

    role_idx = event->is_server ? PACKET_LOG_ROLE_SERVER : PACKET_LOG_ROLE_CLIENT;
    dir_idx = event->is_send ? PACKET_LOG_DIR_SEND : PACKET_LOG_DIR_RECV;

    return &g_hs_state[role_idx][dir_idx][event->enc_level];
}

static const char *packet_log_select_note(unsigned int hs_type,
                                          char *buf, size_t buf_len)
{
    TLS_HANDSHAKE_METADATA *meta = packet_log_get_metadata_slot(hs_type);
    const char *source = NULL;

    if (meta != NULL) {
        if (meta->have_packet_note)
            source = meta->packet_note;
        else if ((hs_type == SSL3_MT_CERTIFICATE
                 || hs_type == SSL3_MT_CERTIFICATE_VERIFY)
                 && meta->have_detail)
            source = meta->detail;
    }

    if (source != NULL && buf != NULL && buf_len > 0) {
        OPENSSL_strlcpy(buf, source, buf_len);
        return buf;
    }
    return NULL;
}

static void packet_log_emit_handshake_fragment(BIO *bio, unsigned int hs_type,
                                               const char *note_override,
                                               int *wrote_any)
{
    TLS_HANDSHAKE_METADATA *meta = packet_log_get_metadata_slot(hs_type);
    const char *name = tls_handshake_fragment_name(hs_type);
    const char *annotation = note_override;

    if (*wrote_any)
        BIO_puts(bio, " | ");
    if (annotation == NULL && meta != NULL) {
        if (meta->have_packet_note)
            annotation = meta->packet_note;
        else if ((hs_type == SSL3_MT_CERTIFICATE
                  || hs_type == SSL3_MT_CERTIFICATE_VERIFY)
                 && meta->have_detail)
            annotation = meta->detail;
    }

    if (annotation != NULL) {
        BIO_printf(bio, "%s(%s)", name, annotation);
    } else if (meta != NULL && meta->have_label) {
        BIO_printf(bio, "%s[%s]", name, meta->label);
    } else if (strcmp(name, "UNKNOWN") == 0) {
        BIO_printf(bio, "UNKNOWN(0x%02x)", hs_type);
    } else {
        BIO_puts(bio, name);
    }
    *wrote_any = 1;
}

static void packet_log_append_handshake_bytes(BIO *bio,
                                              PACKET_LOG_HS_STATE *state,
                                              const unsigned char *data,
                                              size_t len,
                                              int *wrote_any,
                                              unsigned int *tls_event_mask)
{
    size_t offset = 0;

    while (offset < len) {
        if (state != NULL && state->active) {
            size_t chunk = len - offset;
            char note_buf[256];
            const char *note = NULL;
            unsigned int log_type = state->hs_type;

            if (chunk > state->remaining)
                chunk = state->remaining;

            if (chunk > 0)
                packet_log_append_hs_chunk(state, data + offset, chunk);
            offset += chunk;
            if (!state->active) {
                log_type = packet_log_finish_hs_message(state, tls_event_mask);
                note = packet_log_select_note(log_type, note_buf,
                                              sizeof(note_buf));
                packet_log_emit_handshake_fragment(bio, log_type, note,
                                                   wrote_any);
            } else {
                packet_log_emit_handshake_fragment(bio, log_type, NULL,
                                                   wrote_any);
                break;
            }
            continue;
        }

        if (len - offset < 4) {
            if (*wrote_any)
                BIO_puts(bio, " | ");
            BIO_puts(bio, "HANDSHAKE-DATA");
            *wrote_any = 1;
            break;
        }

        unsigned int hs_type = data[offset];
        size_t msg_len = ((size_t)data[offset + 1] << 16)
                       | ((size_t)data[offset + 2] << 8)
                       | (size_t)data[offset + 3];

        offset += 4;
        if (msg_len <= len - offset) {
            packet_log_process_handshake_message(hs_type,
                                                 data + offset,
                                                 msg_len);
            if (tls_event_mask != NULL)
                *tls_event_mask |= packet_log_event_mask_for_type(hs_type);
            {
                char note_buf[256];
                const char *note = packet_log_select_note(hs_type,
                                                          note_buf,
                                                          sizeof(note_buf));
                packet_log_emit_handshake_fragment(bio, hs_type, note,
                                                   wrote_any);
            }
            offset += msg_len;
            continue;
        }

        if (state != NULL) {
            size_t chunk = len - offset;
            char note_buf[256];
            const char *note = NULL;
            unsigned int log_type;

            packet_log_start_hs_message(state, hs_type, msg_len);
            if (chunk > 0)
                packet_log_append_hs_chunk(state, data + offset, chunk);
            offset += chunk;
            if (!state->active) {
                log_type = packet_log_finish_hs_message(state, tls_event_mask);
                note = packet_log_select_note(log_type, note_buf,
                                              sizeof(note_buf));
                packet_log_emit_handshake_fragment(bio, log_type, note,
                                                   wrote_any);
                continue;
            } else {
                log_type = state->hs_type;
                packet_log_emit_handshake_fragment(bio, log_type, NULL,
                                                   wrote_any);
                break;
            }
        } else {
            /* No state available; fall back to best-effort logging. */
            offset += msg_len;
            {
                char note_buf[256];
                const char *note = packet_log_select_note(hs_type,
                                                          note_buf,
                                                          sizeof(note_buf));
                packet_log_emit_handshake_fragment(bio, hs_type, note,
                                                   wrote_any);
            }
        }
    }
}

static void packet_log_append_crypto_fragments(
    BIO *bio, const unsigned char *data, size_t len,
    const OSSL_QUIC_PACKET_LOG_EVENT *event, int *wrote_any,
    unsigned int *tls_event_mask)
{
    if (event == NULL) {
        if (len > 0) {
            if (*wrote_any)
                BIO_puts(bio, " | ");
            BIO_puts(bio, "CRYPTO-DATA");
            *wrote_any = 1;
        }
        return;
    }

    if (event->enc_level == QUIC_ENC_LEVEL_INITIAL
        || event->enc_level == QUIC_ENC_LEVEL_HANDSHAKE) {
        PACKET_LOG_HS_STATE *state = packet_log_get_hs_state(event);

        packet_log_append_handshake_bytes(bio, state, data, len, wrote_any,
                                          tls_event_mask);
        return;
    }

    if (*wrote_any)
        BIO_puts(bio, " | ");
    if (event->enc_level == QUIC_ENC_LEVEL_0RTT)
        BIO_puts(bio, "0RTT-DATA");
    else if (event->enc_level == QUIC_ENC_LEVEL_1RTT)
        BIO_puts(bio, "1RTT-DATA");
    else
        BIO_puts(bio, "CRYPTO-DATA");
    *wrote_any = 1;
}

static void packet_log_format_ack_ranges(BIO *bio,
                                         const OSSL_QUIC_FRAME_ACK *ack,
                                         uint64_t total_ranges)
{
    size_t i;

    BIO_puts(bio, "RANGE=[");
    for (i = 0; i < ack->num_ack_ranges; ++i) {
        if (i != 0)
            BIO_puts(bio, ",");

        if (ack->ack_ranges[i].start == ack->ack_ranges[i].end)
            BIO_printf(bio, "%" PRIu64, ack->ack_ranges[i].start);
        else
            BIO_printf(bio, "%" PRIu64 "-%" PRIu64,
                       ack->ack_ranges[i].start, ack->ack_ranges[i].end);
    }

    if (total_ranges > ack->num_ack_ranges)
        BIO_puts(bio, ",...");

    BIO_puts(bio, "]");
}

static int packet_log_append_frame_spec(BIO *bio, PACKET *pkt,
                                        const OSSL_QUIC_PACKET_LOG_EVENT *event,
                                        unsigned int *tls_event_mask)
{
    size_t rem_before = PACKET_remaining(pkt);
    uint64_t frame_type;

    if (rem_before == 0)
        return 1;

    if (!ossl_quic_wire_peek_frame_header(pkt, &frame_type, NULL))
        return 0;


    switch (frame_type) {
    case OSSL_QUIC_FRAME_TYPE_PADDING:
        {
            size_t padding = ossl_quic_wire_decode_padding(pkt);

            BIO_printf(bio, "PADDING--(SIZE=%zuB)", padding);
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN:
    case OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN:
        {
            OSSL_QUIC_FRAME_ACK ack = {0};
            OSSL_QUIC_ACK_RANGE ack_ranges[PACKET_LOG_MAX_ACK_RANGES];
            uint64_t total_ranges = 0;

            ack.ack_ranges = ack_ranges;
            ack.num_ack_ranges = OSSL_NELEM(ack_ranges);
            if (!ossl_quic_wire_decode_frame_ack(pkt, 3, &ack, &total_ranges))
                return 0;

            size_t frame_len = rem_before - PACKET_remaining(pkt);
            BIO_puts(bio, "ACK--(");
            packet_log_format_ack_ranges(bio, &ack, total_ranges);
            BIO_printf(bio, " , SIZE=%zuB)", frame_len);
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_CRYPTO:
        {
            OSSL_QUIC_FRAME_CRYPTO f = {0};
            int wrote = 0;

            if (!ossl_quic_wire_decode_frame_crypto(pkt, 0, &f))
                return 0;

            size_t frame_len = rem_before - PACKET_remaining(pkt);
            BIO_puts(bio, "CRYPTO--( { ");
            if (f.len > SIZE_MAX) {
                BIO_puts(bio, "CRYPTO-DATA");
                wrote = 1;
            } else {
                packet_log_append_crypto_fragments(bio, f.data, (size_t)f.len,
                                                   event, &wrote,
                                                   tls_event_mask);
            }
            if (!wrote)
                BIO_puts(bio, "CRYPTO-DATA");
            BIO_printf(bio, " } , SIZE=%zuB)", frame_len);
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_STREAM:
    case OSSL_QUIC_FRAME_TYPE_STREAM_FIN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_LEN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_LEN_FIN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_FIN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_LEN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_LEN_FIN:
        {
            OSSL_QUIC_FRAME_STREAM f = {0};

            if (!ossl_quic_wire_decode_frame_stream(pkt, 0, &f))
                return 0;

            size_t frame_len = rem_before - PACKET_remaining(pkt);
            BIO_printf(bio, "STREAM--(ID=%" PRIu64, f.stream_id);
            if (f.is_fin)
                BIO_puts(bio, " , FIN=1");
            BIO_printf(bio, " , SIZE=%zuB)", frame_len);
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_PING:
        if (!ossl_quic_wire_decode_frame_ping(pkt))
            return 0;
        BIO_printf(bio, "PING--(SIZE=%zuB)", rem_before - PACKET_remaining(pkt));
        break;
    case OSSL_QUIC_FRAME_TYPE_NEW_TOKEN:
        {
            const unsigned char *token = NULL;
            size_t token_len = 0;

            if (!ossl_quic_wire_decode_frame_new_token(pkt, &token, &token_len))
                return 0;
            BIO_printf(bio, "NEW_TOKEN--(SIZE=%zuB)",
                       rem_before - PACKET_remaining(pkt));
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID:
        {
            OSSL_QUIC_FRAME_NEW_CONN_ID f = {0};

            if (!ossl_quic_wire_decode_frame_new_conn_id(pkt, &f))
                return 0;
            BIO_printf(bio, "NEW_CONNECTION_ID--(SEQ=%" PRIu64 " , SIZE=%zuB)",
                       f.seq_num, rem_before - PACKET_remaining(pkt));
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_APP:
    case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT:
        {
            OSSL_QUIC_FRAME_CONN_CLOSE f = {0};

            if (!ossl_quic_wire_decode_frame_conn_close(pkt, &f))
                return 0;
            BIO_printf(bio,
                       "CONNECTION_CLOSE--(ERROR=0x%04" PRIx64 " , SIZE=%zuB)",
                       f.error_code,
                       rem_before - PACKET_remaining(pkt));
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE:
        {
            uint64_t challenge = 0;

            if (!ossl_quic_wire_decode_frame_path_challenge(pkt, &challenge))
                return 0;
            BIO_printf(bio, "PATH_CHALLENGE--(SIZE=%zuB)",
                       rem_before - PACKET_remaining(pkt));
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE:
        {
            uint64_t challenge = 0;

            if (!ossl_quic_wire_decode_frame_path_response(pkt, &challenge))
                return 0;
            BIO_printf(bio, "PATH_RESPONSE--(SIZE=%zuB)",
                       rem_before - PACKET_remaining(pkt));
        }
        break;
    case OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE:
        if (!ossl_quic_wire_decode_frame_handshake_done(pkt))
            return 0;
        {
            size_t frame_len = rem_before - PACKET_remaining(pkt);

            BIO_printf(bio, "HANDSHAKE_DONE--(SIZE=%zuB)", frame_len);
            if (tls_event_mask != NULL)
                *tls_event_mask |= TLS_EVENT_HANDSHAKE_DONE;
            g_handshake_done_meta.have_detail = 1;
            BIO_snprintf(g_handshake_done_meta.detail,
                         sizeof(g_handshake_done_meta.detail),
                         "FrameSize=%zuB", frame_len);
        }
        break;
    default:
        {
            size_t remaining = PACKET_remaining(pkt);

            BIO_printf(bio, "UNKNOWN--(TYPE=0x%02" PRIx64 " , SIZE=%zuB)",
                       frame_type, remaining);
            (void)PACKET_forward(pkt, remaining);
        }
        break;
    }

    return 1;
}

static int packet_log_append_frames(BIO *bio,
                                    const unsigned char *payload,
                                    size_t payload_len,
                                    const OSSL_QUIC_PACKET_LOG_EVENT *event,
                                    unsigned int *tls_event_mask)
{
    PACKET pkt;
    int wrote_any = 0;

    if (payload_len == 0)
        return 0;

    if (!PACKET_buf_init(&pkt, payload, payload_len))
        return 0;

    while (PACKET_remaining(&pkt) > 0) {
        if (wrote_any)
            BIO_puts(bio, " | ");
        if (!packet_log_append_frame_spec(bio, &pkt, event, tls_event_mask))
            return 0;
        wrote_any = 1;
    }

    return wrote_any;
}

static void packet_log_append_credit_fields(BIO *bio,
                                            const OSSL_QUIC_PACKET_LOG_EVENT *event)
{
    if (event->is_server) {
        char before_buf[64], after_buf[64];
        const char *before = "-";
        const char *after = "-";
        const char *amp = "-";

        if (event->have_credit_before) {
            before = event->credit_before_unlimited
                ? "UNLIMITED"
                : packet_log_format_bytes(before_buf, sizeof(before_buf),
                                          event->credit_before);
            amp = event->credit_before_unlimited ? "UNLIMITED" : "3x";
        }

        if (event->have_credit_after) {
            after = event->credit_after_unlimited
                ? "UNLIMITED"
                : packet_log_format_bytes(after_buf, sizeof(after_buf),
                                          event->credit_after);
            if (amp[0] == '-')
                amp = event->credit_after_unlimited ? "UNLIMITED" : "3x";
        }

        BIO_printf(bio, "[CREDIT-BEFORE : %s] ", before);
        BIO_printf(bio, "[AMPLIFICATION-FACTOR : %s] ", amp);
        BIO_printf(bio, "[CREDIT AFTER : %s]", after);
    } else {
        const char *credit = "-";
        const char *amp = "-";

        if (event->client_credit_known) {
            credit = event->client_credit_unlimited ? "UNLIMITED" : "UNKNOWN";
            amp = event->client_credit_unlimited ? "VALIDATED" : "UNKNOWN";
        }

        BIO_printf(bio, "[CREDIT : %s] ", credit);
        BIO_printf(bio, "[AMPLIFICATION-FACTOR : %s]", amp);
    }
}

static void packet_log_print_detail_line(FILE *stream, const char *label,
                                         unsigned int hs_type)
{
    TLS_HANDSHAKE_METADATA *meta = packet_log_get_metadata_slot(hs_type);

    if (stream == NULL || meta == NULL || !meta->have_detail)
        return;

    fprintf(stream, "    -> %s: %s\n", label, meta->detail);
}

static void packet_log_emit_debug_tls_details(
    const OSSL_QUIC_PACKET_LOG_EVENT *event,
    unsigned int tls_event_mask)
{
    FILE *stream = (event != NULL) ? event->stream : NULL;

    if (stream == NULL || tls_event_mask == 0)
        return;

    if (tls_event_mask & TLS_EVENT_CLIENT_HELLO)
        packet_log_print_detail_line(stream, "ClientHello",
                                     SSL3_MT_CLIENT_HELLO);
    if (tls_event_mask & TLS_EVENT_SERVER_HELLO)
        packet_log_print_detail_line(stream, "ServerHello",
                                     SSL3_MT_SERVER_HELLO);
    if (tls_event_mask & TLS_EVENT_ENCRYPTED_EXT)
        packet_log_print_detail_line(stream, "EncryptedExtensions",
                                     SSL3_MT_ENCRYPTED_EXTENSIONS);
    if (tls_event_mask & TLS_EVENT_CERTIFICATE)
        packet_log_print_detail_line(stream, "Certificate",
                                     SSL3_MT_CERTIFICATE);
    if (tls_event_mask & TLS_EVENT_CERT_VERIFY)
        packet_log_print_detail_line(stream, "CertificateVerify",
                                     SSL3_MT_CERTIFICATE_VERIFY);
    if (tls_event_mask & TLS_EVENT_FINISHED)
        packet_log_print_detail_line(stream, "Finished",
                                     SSL3_MT_FINISHED);
    if ((tls_event_mask & TLS_EVENT_HANDSHAKE_DONE)
            && g_handshake_done_meta.have_detail)
        fprintf(stream, "    -> HandshakeDone: %s\n",
                g_handshake_done_meta.detail);

    fflush(stream);
}

void ossl_quic_packet_log(const OSSL_QUIC_PACKET_LOG_EVENT *event)
{
    OSSL_TIME now;
    double elapsed_ms;
    double display_ms;
    BIO *line = NULL;
    BUF_MEM *bptr = NULL;
    const char *role;
    const char *direction;
    const char *packet_type;
    int have_frames = 0;
    unsigned int tls_event_mask = 0;

    if (!ossl_quic_packet_log_enabled() || event == NULL || event->stream == NULL)
        return;

    now = ossl_time_now();
    elapsed_ms = quic_log_wallclock_ms(now);
    {
        uint64_t integral = (elapsed_ms >= 0)
            ? (uint64_t)elapsed_ms
            : (uint64_t)(-elapsed_ms);
        double fractional = elapsed_ms - (elapsed_ms >= 0
                                          ? (double)integral
                                          : -(double)integral);
        uint64_t mod = integral % 100000;
        display_ms = (elapsed_ms >= 0)
            ? (double)mod + fractional
            : -((double)mod + fractional);
        if (display_ms < 0)
            display_ms += 100000.0;
    }
    role = event->is_server ? "SERVER" : "CLIENT";
    direction = event->is_send ? "SENT" : "RECEIVED";
    packet_type = (event->packet_type != NULL) ? event->packet_type : "Unknown";

    line = BIO_new(BIO_s_mem());
    if (line == NULL)
        return;

    BIO_printf(line,
               "[%12.8f ms] [%s %s] [DATAGRAM-SIZE : %zuB] ",
               display_ms,
               role,
               direction,
               event->datagram_size);

    if (event->is_server && event->have_credit_delta) {
        long long delta = event->credit_delta;
        const char *sign = delta >= 0 ? "+" : "-";
        size_t abs_delta = (size_t)(delta >= 0 ? delta : -delta);
        BIO_printf(line, "[DELTA-CREDIT : %s%zuB] ", sign, abs_delta);
    }

    BIO_printf(line, "PACKET %" PRIu64 " : %s { ",
               event->packet_number,
               packet_type);

    if (event->payload != NULL && event->payload_len > 0)
        have_frames = packet_log_append_frames(line,
                                               event->payload,
                                               event->payload_len,
                                               event,
                                               &tls_event_mask);

    if (!have_frames)
        BIO_puts(line, "UNKNOWN");

    ossl_quic_timing_maybe_emit_internal(event, now, display_ms,
                                         tls_event_mask,
                                         OSSL_QUIC_TIMING_PHASE_BEFORE);

    BIO_puts(line, " }  ");
    packet_log_append_credit_fields(line, event);
    BIO_puts(line, "\n");

    BIO_get_mem_ptr(line, &bptr);
    if (bptr != NULL) {
        int buffered_line = 0;
        SSL_CONNECTION *sc = (event->ssl != NULL)
            ? SSL_CONNECTION_FROM_SSL(event->ssl)
            : NULL;

        if (sc != NULL) {
            QUIC_HANDSHAKE_TIMING *tm = ossl_quic_timing_get(sc);

            if (tm != NULL) {
                if (event->is_server && event->is_send
                        && (tls_event_mask & TLS_EVENT_SERVER_HELLO) != 0
                        && !tm->server_client_logged
                        && tm->pending_server_initial_line == NULL
                        && ossl_quic_timing_buffer_server_hello_line(sc,
                                                                     bptr->data,
                                                                     bptr->length))
                    buffered_line = 1;
                else if (!event->is_server && event->is_send
                        && (tls_event_mask & TLS_EVENT_FINISHED) != 0
                        && !tm->client_hs_done_logged
                        && tm->pending_client_finished_line == NULL
                        && ossl_quic_timing_buffer_client_finished_line(sc,
                                                                        bptr->data,
                                                                        bptr->length))
                    buffered_line = 1;
                else if (event->is_server && event->is_send
                        && (tls_event_mask & TLS_EVENT_HANDSHAKE_DONE) != 0
                        && !tm->server_hs_done_logged
                        && tm->pending_server_handshake_done_line == NULL
                        && ossl_quic_timing_buffer_server_hs_done_line(sc,
                                                                       bptr->data,
                                                                       bptr->length))
                    buffered_line = 1;
            }
        }

        if (!buffered_line) {
            fwrite(bptr->data, 1, bptr->length, event->stream);
            fflush(event->stream);
        }
    }

    ossl_quic_timing_maybe_emit_internal(event, now, display_ms,
                                         tls_event_mask,
                                         OSSL_QUIC_TIMING_PHASE_AFTER);

    BIO_free(line);

    if (ossl_quic_debug_enabled() && tls_event_mask != 0)
        packet_log_emit_debug_tls_details(event, tls_event_mask);
}

const char *ossl_quic_packet_type_name(uint32_t type)
{
    switch (type) {
    case QUIC_PKT_TYPE_INITIAL:
        return "Initial";
    case QUIC_PKT_TYPE_HANDSHAKE:
        return "Handshake";
    case QUIC_PKT_TYPE_0RTT:
        return "0RTT";
    case QUIC_PKT_TYPE_1RTT:
        return "1RTT";
    case QUIC_PKT_TYPE_RETRY:
        return "Retry";
    case QUIC_PKT_TYPE_VERSION_NEG:
        return "Version-Neg";
    default:
        return "Unknown";
    }
}
