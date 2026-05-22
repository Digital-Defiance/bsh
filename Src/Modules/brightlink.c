/*
 * brightlink.c — bsh's BrightLink Protocol v1 client module.
 *
 * Implements the shell side of BrightLink Protocol v1, defined in
 * docs/rfc-brightlink.md.
 *
 * What this module provides:
 *
 *   1. An EBP/1 client over Unix domain socket to BrightNexus
 *      (~/.brightchain/brightnexus/brightnexus.sock).
 *
 *   2. Lazy LINK_REGISTER on first inject — secp256k1 ECIES envelope
 *      out, response envelope in, bilateral HKDF-SHA256 derives K_session,
 *      238-byte canonical transcript verified against the bridge's Apple
 *      SEP P-256 signature with TOFU pinning.
 *
 *   3. The `bsh-inject` builtin: reads a JSON body from stdin, encrypts
 *      under K_session with AES-256-GCM and a length-prefixed AAD
 *      (dir_tag, counter, type, context), and sends a `LINK_DELIVER`
 *      JSON request to the bridge over the EBP/1 socket. Fails closed
 *      on bridge errors — never falls back to plaintext.
 *
 * Wire-format references:
 *
 *   - HKDF info string:                 RFC §4.5.2 ("brightlink-session-key-v1")
 *   - canonical transcript layout:      RFC §4.5.3 (238 bytes)
 *   - LINK_DELIVER JSON request:        RFC §4.9.1
 *   - length-prefixed AAD construction: RFC §4.6.3
 *   - per-direction monotonic counters: RFC §4.6.4
 *
 * Crypto dependencies:
 *   - libsecp256k1 — secp256k1 ECDH for ECIES envelopes.
 *   - OpenSSL libcrypto — AES-256-GCM, HKDF-SHA256, ECDSA-P256-DER verify.
 *
 * The module is link=static, load=yes (see brightlink.mdd). Lifecycle:
 *   - boot_  : do nothing eagerly; LINK_REGISTER fires lazily on first inject.
 *   - finish_: zero K_session, close the bridge socket.
 */

#include "brightlink.mdh"
#include "brightlink.pro"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <pwd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>


/* ------------------------------------------------------------------ */
/*  RFC-pinned constants                                                */
/* ------------------------------------------------------------------ */

/* RFC §4.5.2 — bilateral HKDF info string. */
#define LINK_HKDF_INFO          "brightlink-session-key-v1"
#define LINK_HKDF_INFO_LEN      (sizeof(LINK_HKDF_INFO) - 1)

/* RFC §4.5.3 — canonical transcript header. */
#define LINK_TRANSCRIPT_HEADER  "BrightLink v1 transcript\0"
#define LINK_TRANSCRIPT_HEADER_LEN  25
#define LINK_TRANSCRIPT_TOTAL_LEN   238

/* RFC §4.5 + §4.5.1 — fixed sizes. */
#define LINK_PROTOCOL_VERSION   1
#define LINK_CLIENT_NONCE_LEN   16
#define LINK_SHARE_LEN          32
#define LINK_SESSION_ID_LEN     16
#define LINK_SESSION_KEY_LEN    32
#define LINK_PUB_UNCOMPRESSED   65
#define LINK_PUB_COMPRESSED     33

/* RFC §4.1 — registration TTL ceiling. 8h. */
#define LINK_MAX_TTL_SECONDS    (8 * 3600)
/* Default TTL if the caller doesn't override. */
#define LINK_DEFAULT_TTL_SECONDS 3600

/* RFC §4.6 — AES-GCM nonce / tag sizes. */
#define LINK_GCM_IV_LEN         12
#define LINK_GCM_TAG_LEN        16

/* DD-ECIES Basic envelope outer-AAD prefix. */
#define DD_ECIES_VERSION_BYTE  0x01
#define DD_ECIES_CIPHER_SUITE  0x01
#define DD_ECIES_TYPE_BASIC    0x21
#define DD_ECIES_HKDF_INFO     "ecies-v2-key-derivation"
#define DD_ECIES_HKDF_INFO_LEN (sizeof(DD_ECIES_HKDF_INFO) - 1)

/* Stdin read buffer for bsh-inject. */
#define LINK_BUF_INIT           4096
#define LINK_BUF_MAX            (64 * 1024)   /* hard cap */

/* ------------------------------------------------------------------ */
/*  Module-global state                                                 */
/*  ALL pointers / FDs initialise to "absent" so finish_() is safe even */
/*  if boot_() never ran.                                               */
/* ------------------------------------------------------------------ */

static int link_session_active = 0;
/* Socket FD to the bridge. -1 when not connected. */
static int link_sockfd = -1;
/* Discovered socket path (resolved at first use). */
static char link_socket_path[1024] = "";

/* Bridge identity, populated during LINK_REGISTER. */
static unsigned char link_session_id[LINK_SESSION_ID_LEN];
static unsigned char link_session_key[LINK_SESSION_KEY_LEN];
static int link_session_id_set = 0;
static int link_session_key_set = 0;

/* RFC §4.6.4 monotonic counters. Both shared between Path A (bsh-inject)
 * and Path B (PTY-proxy capture). Allocator: increment-then-use under
 * `link_counter_lock`. */
static uint64_t link_c_shell_to_agent = 0;
static uint64_t link_c_agent_to_shell = 0;

/* TOFU pin: the bridge's SEP public key, captured on first LINK_REGISTER.
 * Future registrations MUST byte-match this. nullable until first use. */
static unsigned char link_pinned_sep_pub[LINK_PUB_UNCOMPRESSED];
static int link_pinned_sep_pub_set = 0;

/* libsecp256k1 context. Lazily created. Single shared instance per process. */
static secp256k1_context *link_secp_ctx = NULL;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                                */
/* ------------------------------------------------------------------ */

static int     link_socket_connect(void);
static void    link_socket_close(void);
static int     link_register_if_needed(char **errmsg);
static int     link_send_request(const char *json, char **response_json);
static int     link_emit_deliver(uint64_t counter,
                                 const char *type, size_t type_len,
                                 const unsigned char *context, size_t ctx_len,
                                 const unsigned char *plaintext, size_t pt_len,
                                 char **errmsg);

static secp256k1_context *link_secp(void);

static int     link_resolve_socket_path(void);

/* AAD helper (RFC §4.6.3 length-prefixed encoding). */
static int     link_build_deliver_aad(uint8_t dir_tag,
                                     const unsigned char *counter, size_t counter_len,
                                     const char *type, size_t type_len,
                                     const unsigned char *context, size_t ctx_len,
                                     unsigned char *aad_out, size_t aad_cap,
                                     size_t *aad_out_len);

/* AES-GCM. */
static int     link_aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                                   const unsigned char *iv, size_t iv_len,
                                   const unsigned char *aad, size_t aad_len,
                                   const unsigned char *pt, size_t pt_len,
                                   unsigned char *ct,
                                   unsigned char *tag);
static int     link_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                                   const unsigned char *iv, size_t iv_len,
                                   const unsigned char *aad, size_t aad_len,
                                   const unsigned char *ct, size_t ct_len,
                                   const unsigned char *tag,
                                   unsigned char *pt);

/* HKDF-SHA256. */
static int     link_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                               const unsigned char *salt, size_t salt_len,
                               const unsigned char *info, size_t info_len,
                               unsigned char *out, size_t out_len);

/* base64 helpers. */
static int     link_b64encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_cap);
static int     link_b64decode(const char *src, size_t src_len, unsigned char *dst, size_t dst_cap, size_t *dst_len);

/* JSON helpers — minimal hand-rolled because we have a tightly-scoped surface.
 * Three functions are enough for everything we send/receive. */
static int     link_json_field_str(const char *json, const char *key, char *out, size_t out_cap);
static int     link_json_field_int(const char *json, const char *key, long long *out);
static int     link_json_field_b64(const char *json, const char *key,
                                  unsigned char *out, size_t out_cap, size_t *out_len);

/* DD-ECIES Basic-mode envelope encrypt + decrypt. */
static int     link_ecies_encrypt(const unsigned char *recipient_pub65,
                                 const unsigned char *plaintext, size_t pt_len,
                                 unsigned char **envelope_out, size_t *envelope_len);
static int     link_ecies_decrypt(const unsigned char *recipient_priv32,
                                 const unsigned char *envelope, size_t envelope_len,
                                 unsigned char **plaintext_out, size_t *pt_len);

/* secp256k1 helpers. */
static int     link_secp_random_priv(unsigned char *priv32);
static int     link_secp_pub_uncompressed(const unsigned char *priv32, unsigned char *pub65_out);
static int     link_secp_pub_compressed(const unsigned char *priv32, unsigned char *pub33_out);
static int     link_secp_ecdh(const unsigned char *priv32,
                             const unsigned char *peer_pub_compressed_or_uncompressed,
                             size_t peer_pub_len,
                             unsigned char *shared32_out);

/* Transcript construction + ECDSA-P256 verify. */
static int     link_build_transcript(const unsigned char *client_nonce,
                                    const unsigned char *client_pub65,
                                    const unsigned char *client_share,
                                    const unsigned char *session_id,
                                    const unsigned char *bridge_share,
                                    double issued_at_bd,
                                    int64_t bridge_issued_at_unix,
                                    uint32_t ttl_seconds,
                                    unsigned char *transcript_out);
static int     link_verify_p256_signature(const unsigned char *sep_pub65,
                                         const unsigned char *transcript, size_t transcript_len,
                                         const unsigned char *sig_der, size_t sig_der_len);

/* Misc. */
static ssize_t link_write_all(int fd, const void *buf, size_t len);
static ssize_t link_read_until_brace(int fd, char *buf, size_t cap);

/* ------------------------------------------------------------------ */
/*  Lazy secp256k1 context                                              */
/* ------------------------------------------------------------------ */

static secp256k1_context *
link_secp(void)
{
    if (link_secp_ctx == NULL) {
        link_secp_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (link_secp_ctx != NULL) {
            /* Best-effort blinding of the context's signing key with random
             * data. Failure is non-fatal — the context still works. */
            unsigned char seed[32];
            if (RAND_bytes(seed, sizeof(seed)) == 1) {
                (void)secp256k1_context_randomize(link_secp_ctx, seed);
            }
            OPENSSL_cleanse(seed, sizeof(seed));
        }
    }
    return link_secp_ctx;
}

/* ------------------------------------------------------------------ */
/*  Socket discovery & connection                                       */
/* ------------------------------------------------------------------ */

static int
link_resolve_socket_path(void)
{
    if (link_socket_path[0] != '\0') return 1;
    /* 1. $BRIGHTNEXUS_SOCKET override. */
    const char *env = getenv("BRIGHTNEXUS_SOCKET");
    if (env != NULL && env[0] != '\0') {
        size_t n = strlen(env);
        if (n >= sizeof(link_socket_path)) return 0;
        memcpy(link_socket_path, env, n + 1);
        return 1;
    }
    /* 2. ~/.brightchain/brightnexus/brightnexus.sock — canonical. */
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        struct passwd *pw = getpwuid(getuid());
        if (pw != NULL) home = pw->pw_dir;
    }
    if (home == NULL) return 0;
    int n = snprintf(link_socket_path, sizeof(link_socket_path),
                     "%s/.brightchain/brightnexus/brightnexus.sock", home);
    return (n > 0 && (size_t)n < sizeof(link_socket_path)) ? 1 : 0;
}

static int
link_socket_connect(void)
{
    if (link_sockfd >= 0) return 1;
    if (!link_resolve_socket_path()) return 0;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(link_socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        return 0;
    }
    strcpy(addr.sun_path, link_socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 0;
    }
    link_sockfd = fd;
    return 1;
}

static void
link_socket_close(void)
{
    if (link_sockfd >= 0) {
        close(link_sockfd);
        link_sockfd = -1;
    }
}

/* ------------------------------------------------------------------ */
/*  EBP/1 brace-counter framing                                         */
/* ------------------------------------------------------------------ */

static ssize_t
link_write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        total += n;
    }
    return (ssize_t)total;
}

/* Read until a complete top-level JSON object is in `buf`. Implements the
 * brace-counter framing from EBP/1 §3.2: the first '{' opens, matching '}'
 * closes. Quotes and backslash-escapes inside strings are honored so that
 * `}` inside a string doesn't end the message early. Returns the number of
 * bytes in the message on success, -1 on error, 0 on EOF before close.
 *
 * `cap` MUST be at least 4 KB; messages are typically under 2 KB. */
static ssize_t
link_read_until_brace(int fd, char *buf, size_t cap)
{
    size_t pos = 0;
    int depth = 0;
    int in_string = 0;
    int escaped = 0;
    int seen_open = 0;

    while (pos < cap - 1) {
        ssize_t n = read(fd, buf + pos, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;  /* EOF */
        char c = buf[pos];
        pos += 1;

        if (escaped) { escaped = 0; continue; }
        if (in_string) {
            if (c == '\\') { escaped = 1; }
            else if (c == '"') { in_string = 0; }
            continue;
        }
        if (c == '"') { in_string = 1; continue; }
        if (c == '{') { depth += 1; seen_open = 1; }
        else if (c == '}') {
            depth -= 1;
            if (seen_open && depth == 0) {
                buf[pos] = '\0';
                return (ssize_t)pos;
            }
        }
    }
    /* Buffer full without close. */
    return -1;
}

/* Send one JSON request, read one JSON response. Caller frees `*response_json`. */
static int
link_send_request(const char *json, char **response_json)
{
    if (response_json) *response_json = NULL;
    if (!link_socket_connect()) return 0;

    size_t json_len = strlen(json);
    if (link_write_all(link_sockfd, json, json_len) < 0) {
        link_socket_close();
        return 0;
    }
    char buf[16 * 1024];
    ssize_t n = link_read_until_brace(link_sockfd, buf, sizeof(buf));
    if (n <= 0) {
        link_socket_close();
        return 0;
    }
    if (response_json) {
        *response_json = strdup(buf);
        if (*response_json == NULL) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Crypto primitives — HKDF, AES-GCM, ECDSA-P256-DER verify            */
/* ------------------------------------------------------------------ */

static int
link_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                const unsigned char *salt, size_t salt_len,
                const unsigned char *info, size_t info_len,
                unsigned char *out, size_t out_len)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) return 0;
    int ok = 0;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto end;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto end;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto end;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) goto end;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto end;
    size_t outlen = out_len;
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) goto end;
    if (outlen != out_len) goto end;
    ok = 1;
end:
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

static int
link_aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv, size_t iv_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *pt, size_t pt_len,
                    unsigned char *ct,
                    unsigned char *tag)
{
    if (key_len != 32 || iv_len != LINK_GCM_IV_LEN) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;
    int ok = 0;
    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto end;
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto end;
    }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto end;
    int totallen = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto end;
    totallen += len;
    if ((size_t)totallen != pt_len) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, LINK_GCM_TAG_LEN, tag) != 1) goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int
link_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv, size_t iv_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *ct, size_t ct_len,
                    const unsigned char *tag,
                    unsigned char *pt)
{
    if (key_len != 32 || iv_len != LINK_GCM_IV_LEN) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;
    int ok = 0;
    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto end;
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto end;
    }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, LINK_GCM_TAG_LEN, (void *)tag) != 1) goto end;
    int finallen = 0;
    if (EVP_DecryptFinal_ex(ctx, pt + len, &finallen) != 1) goto end;
    if ((size_t)(len + finallen) != ct_len) goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int
link_verify_p256_signature(const unsigned char *sep_pub65,
                          const unsigned char *transcript, size_t transcript_len,
                          const unsigned char *sig_der, size_t sig_der_len)
{
    if (sep_pub65 == NULL || sep_pub65[0] != 0x04) return 0;
    int ok = 0;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) goto end;
    point = EC_POINT_new(group);
    if (point == NULL) goto end;
    if (EC_POINT_oct2point(group, point, sep_pub65, LINK_PUB_UNCOMPRESSED, NULL) != 1) goto end;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) goto end;
    if (EC_KEY_set_public_key(eckey, point) != 1) goto end;
    pkey = EVP_PKEY_new();
    if (pkey == NULL) goto end;
    if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) goto end;
    eckey = NULL; /* now owned by pkey */
    md = EVP_MD_CTX_new();
    if (md == NULL) goto end;
    if (EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, pkey) != 1) goto end;
    if (EVP_DigestVerifyUpdate(md, transcript, transcript_len) != 1) goto end;
    if (EVP_DigestVerifyFinal(md, sig_der, sig_der_len) == 1) ok = 1;
end:
    if (md != NULL) EVP_MD_CTX_free(md);
    if (pkey != NULL) EVP_PKEY_free(pkey);
    if (eckey != NULL) EC_KEY_free(eckey);
    if (point != NULL) EC_POINT_free(point);
    if (group != NULL) EC_GROUP_free(group);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  secp256k1 helpers                                                   */
/* ------------------------------------------------------------------ */

static int
link_secp_random_priv(unsigned char *priv32)
{
    secp256k1_context *ctx = link_secp();
    if (ctx == NULL) return 0;
    for (int attempts = 0; attempts < 16; attempts++) {
        if (RAND_bytes(priv32, 32) != 1) return 0;
        if (secp256k1_ec_seckey_verify(ctx, priv32) == 1) return 1;
    }
    return 0;
}

static int
link_secp_pub_uncompressed(const unsigned char *priv32, unsigned char *pub65_out)
{
    secp256k1_context *ctx = link_secp();
    if (ctx == NULL) return 0;
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(ctx, &pk, priv32) != 1) return 0;
    size_t outlen = LINK_PUB_UNCOMPRESSED;
    if (secp256k1_ec_pubkey_serialize(ctx, pub65_out, &outlen, &pk,
                                      SECP256K1_EC_UNCOMPRESSED) != 1) return 0;
    return outlen == LINK_PUB_UNCOMPRESSED ? 1 : 0;
}

static int
link_secp_pub_compressed(const unsigned char *priv32, unsigned char *pub33_out)
{
    secp256k1_context *ctx = link_secp();
    if (ctx == NULL) return 0;
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(ctx, &pk, priv32) != 1) return 0;
    size_t outlen = LINK_PUB_COMPRESSED;
    if (secp256k1_ec_pubkey_serialize(ctx, pub33_out, &outlen, &pk,
                                      SECP256K1_EC_COMPRESSED) != 1) return 0;
    return outlen == LINK_PUB_COMPRESSED ? 1 : 0;
}

/* Returns the 32-byte X coordinate of the shared point, matching DD-ECIES. */
static int
link_secp_ecdh(const unsigned char *priv32,
              const unsigned char *peer_pub, size_t peer_pub_len,
              unsigned char *shared32_out)
{
    secp256k1_context *ctx = link_secp();
    if (ctx == NULL) return 0;
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(ctx, &pk, peer_pub, peer_pub_len) != 1) return 0;
    extern int link_secp_ecdh_xonly_cb(unsigned char *output,
                                       const unsigned char *x32,
                                       const unsigned char *y32,
                                       void *data);
    return secp256k1_ecdh(ctx, shared32_out, &pk, priv32,
                          link_secp_ecdh_xonly_cb, NULL) == 1 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  base64                                                              */
/* ------------------------------------------------------------------ */

static int
link_b64encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_cap)
{
    int needed = 4 * ((int)((src_len + 2) / 3)) + 1;
    if ((size_t)needed > dst_cap) return -1;
    int n = EVP_EncodeBlock((unsigned char *)dst, src, (int)src_len);
    if (n < 0) return -1;
    dst[n] = '\0';
    return n;
}

static int
link_b64decode(const char *src, size_t src_len, unsigned char *dst, size_t dst_cap, size_t *dst_len)
{
    /* `EVP_DecodeBlock` writes the *full* (src_len*3)/4 bytes regardless
     * of padding — the trailing 1 or 2 bytes are zero-filled but they
     * still count against the destination buffer. To let callers size
     * `dst_cap` to the *real* payload length (post-padding-trim), we
     * decode into a local oversized buffer and copy the trimmed bytes.
     *
     * This was a real stack-smash bug: a 65-byte uncompressed pubkey
     * arrives as 88 b64 chars with 1 byte of `=` padding. EVP would write
     * 66 bytes into a `dst_cap == 65` buffer. */
    size_t pad = 0;
    if (src_len >= 1 && src[src_len - 1] == '=') pad++;
    if (src_len >= 2 && src[src_len - 2] == '=') pad++;
    size_t pre_trim = (src_len * 3) / 4;
    if (pre_trim < pad) return -1;  /* malformed */
    size_t real = pre_trim - pad;
    if (real > dst_cap) return -1;

    /* Use a stack scratch buffer for the EVP write so we never overflow
     * the caller's tight destination. */
    unsigned char scratch[8192];
    if (pre_trim > sizeof(scratch)) {
        /* Fall back to malloc for the very-large case (we don't expect
         * this in protocol use; the bridge payloads stay well under
         * 4 KB even for transcript signatures + envelopes). */
        unsigned char *heap = malloc(pre_trim);
        if (heap == NULL) return -1;
        int n = EVP_DecodeBlock(heap, (const unsigned char *)src, (int)src_len);
        if (n < 0 || (size_t)n != pre_trim) { free(heap); return -1; }
        memcpy(dst, heap, real);
        free(heap);
    } else {
        int n = EVP_DecodeBlock(scratch, (const unsigned char *)src, (int)src_len);
        if (n < 0 || (size_t)n != pre_trim) return -1;
        memcpy(dst, scratch, real);
    }
    if (dst_len) *dst_len = real;
    return (int)real;
}

/* ------------------------------------------------------------------ */
/*  Minimal JSON helpers                                                */
/*                                                                      */
/* The bridge's response JSON shape is fixed — we parse only the fields */
/* we know about. These helpers do not validate JSON structure; they    */
/* simply locate `"key"` and pull the value. That's sufficient for our  */
/* tightly-scoped surface and saves us from depending on a JSON library.*/
/* ------------------------------------------------------------------ */

/* Locate `"key"` followed by `:` and return a pointer to the first byte
 * after `:` (skipping whitespace). Returns NULL if not found. */
static const char *
link_json_locate(const char *json, const char *key)
{
    char needle[256];
    int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n < 0 || (size_t)n >= sizeof(needle)) return NULL;
    const char *p = strstr(json, needle);
    if (p == NULL) return NULL;
    p += n;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static int
link_json_field_str(const char *json, const char *key, char *out, size_t out_cap)
{
    const char *p = link_json_locate(json, key);
    if (p == NULL || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p != '\0' && *p != '"') {
        if (*p == '\\' && p[1] != '\0') {
            /* JSON string escapes per RFC 8259 §7. We support the ones the
             * bridge actually emits: \" \\ \/ \n \r \t \u00xx. Anything
             * else passes through with the leading backslash dropped (so
             * `\b` becomes `b`). */
            char c = p[1];
            switch (c) {
            case '"':  if (i + 1 >= out_cap) return 0; out[i++] = '"';  p += 2; break;
            case '\\': if (i + 1 >= out_cap) return 0; out[i++] = '\\'; p += 2; break;
            case '/':  if (i + 1 >= out_cap) return 0; out[i++] = '/';  p += 2; break;
            case 'n':  if (i + 1 >= out_cap) return 0; out[i++] = '\n'; p += 2; break;
            case 'r':  if (i + 1 >= out_cap) return 0; out[i++] = '\r'; p += 2; break;
            case 't':  if (i + 1 >= out_cap) return 0; out[i++] = '\t'; p += 2; break;
            case 'u': {
                if (p[2] == '\0' || p[3] == '\0' || p[4] == '\0' || p[5] == '\0') return 0;
                char hex[5] = {p[2], p[3], p[4], p[5], '\0'};
                unsigned int cp = 0;
                if (sscanf(hex, "%x", &cp) != 1) return 0;
                /* The bridge only escapes ASCII via \u, so we only need
                 * the single-byte form. Anything outside U+007F drops to
                 * a question mark — we don't need full UTF-8 emission for
                 * our protocol surface. */
                if (i + 1 >= out_cap) return 0;
                out[i++] = cp < 0x80 ? (char)cp : '?';
                p += 6;
                break;
            }
            default:   if (i + 1 >= out_cap) return 0; out[i++] = c; p += 2; break;
            }
        } else {
            if (i + 1 >= out_cap) return 0;
            out[i++] = *p++;
        }
    }
    if (*p != '"') return 0;
    out[i] = '\0';
    return 1;
}

static int
link_json_field_int(const char *json, const char *key, long long *out)
{
    const char *p = link_json_locate(json, key);
    if (p == NULL) return 0;
    char *endp;
    long long v = strtoll(p, &endp, 10);
    if (endp == p) return 0;
    *out = v;
    return 1;
}

static int
link_json_field_b64(const char *json, const char *key,
                   unsigned char *out, size_t out_cap, size_t *out_len)
{
    char tmp[4096];
    if (!link_json_field_str(json, key, tmp, sizeof(tmp))) return 0;
    return link_b64decode(tmp, strlen(tmp), out, out_cap, out_len) >= 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  AES-256-GCM AAD construction (RFC §4.6.3)                          */
/* ------------------------------------------------------------------ */

static void
link_le32(unsigned char *out, uint32_t v)
{
    out[0] = (unsigned char)(v & 0xff);
    out[1] = (unsigned char)((v >> 8) & 0xff);
    out[2] = (unsigned char)((v >> 16) & 0xff);
    out[3] = (unsigned char)((v >> 24) & 0xff);
}

static void
link_be64(unsigned char *out, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        out[7 - i] = (unsigned char)((v >> (i * 8)) & 0xff);
    }
}

static int
link_build_deliver_aad(uint8_t dir_tag,
                      const unsigned char *counter, size_t counter_len,
                      const char *type, size_t type_len,
                      const unsigned char *context, size_t ctx_len,
                      unsigned char *aad_out, size_t aad_cap,
                      size_t *aad_out_len)
{
    /* Layout per RFC §4.6.3:
     *   LE32(1) || dir_tag
     *   LE32(len(counter)) || counter
     *   LE32(len(type))    || type
     *   LE32(len(context)) || context
     */
    size_t need = 4 + 1 + 4 + counter_len + 4 + type_len + 4 + ctx_len;
    if (need > aad_cap) return 0;
    unsigned char *p = aad_out;
    link_le32(p, 1); p += 4;
    *p++ = dir_tag;
    link_le32(p, (uint32_t)counter_len); p += 4;
    memcpy(p, counter, counter_len); p += counter_len;
    link_le32(p, (uint32_t)type_len); p += 4;
    memcpy(p, type, type_len); p += type_len;
    link_le32(p, (uint32_t)ctx_len); p += 4;
    memcpy(p, context, ctx_len); p += ctx_len;
    *aad_out_len = need;
    return 1;
}

/*  ECIES Basic-mode envelope (DD-ECIES §18.6)                          */
/* ------------------------------------------------------------------ */

static int
link_ecies_encrypt(const unsigned char *recipient_pub65,
                  const unsigned char *plaintext, size_t pt_len,
                  unsigned char **envelope_out, size_t *envelope_len)
{
    if (envelope_out) *envelope_out = NULL;
    /* Generate ephemeral keypair. */
    unsigned char eph_priv[32];
    if (!link_secp_random_priv(eph_priv)) return 0;
    unsigned char eph_pub_compressed[LINK_PUB_COMPRESSED];
    if (!link_secp_pub_compressed(eph_priv, eph_pub_compressed)) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    /* ECDH shared secret. We need the raw X coordinate. libsecp256k1's
     * default ECDH callback hashes; supply a custom callback that copies
     * X verbatim. */
    secp256k1_context *ctx = link_secp();
    secp256k1_pubkey peer_pk;
    if (secp256k1_ec_pubkey_parse(ctx, &peer_pk, recipient_pub65, LINK_PUB_UNCOMPRESSED) != 1) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }
    /* Custom hash callback: write only X. */
    extern int link_secp_ecdh_xonly_cb(unsigned char *output,
                                       const unsigned char *x32,
                                       const unsigned char *y32,
                                       void *data);
    unsigned char shared_x[32];
    if (secp256k1_ecdh(ctx, shared_x, &peer_pk, eph_priv,
                       link_secp_ecdh_xonly_cb, NULL) != 1) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    /* Derive AES key via HKDF. */
    unsigned char aes_key[32];
    if (!link_hkdf_sha256(shared_x, sizeof(shared_x),
                         (const unsigned char *)"", 0,
                         (const unsigned char *)DD_ECIES_HKDF_INFO, DD_ECIES_HKDF_INFO_LEN,
                         aes_key, sizeof(aes_key))) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        return 0;
    }

    /* IV. */
    unsigned char iv[LINK_GCM_IV_LEN];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }

    /* AAD per DD-ECIES §5.5: version || cipher_suite || type || eph_pub. */
    unsigned char aad[3 + LINK_PUB_COMPRESSED];
    aad[0] = DD_ECIES_VERSION_BYTE;
    aad[1] = DD_ECIES_CIPHER_SUITE;
    aad[2] = DD_ECIES_TYPE_BASIC;
    memcpy(aad + 3, eph_pub_compressed, LINK_PUB_COMPRESSED);

    /* Encrypt. */
    unsigned char *ct = malloc(pt_len);
    unsigned char tag[LINK_GCM_TAG_LEN];
    if (ct == NULL ||
        !link_aes_gcm_encrypt(aes_key, sizeof(aes_key),
                             iv, sizeof(iv), aad, sizeof(aad),
                             plaintext, pt_len, ct, tag)) {
        free(ct);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }

    /* Build envelope: 1+1+1+33+12+16 + ciphertext. */
    size_t env_len = 64 + pt_len;
    unsigned char *env = malloc(env_len);
    if (env == NULL) {
        free(ct);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }
    size_t pos = 0;
    env[pos++] = DD_ECIES_VERSION_BYTE;
    env[pos++] = DD_ECIES_CIPHER_SUITE;
    env[pos++] = DD_ECIES_TYPE_BASIC;
    memcpy(env + pos, eph_pub_compressed, LINK_PUB_COMPRESSED); pos += LINK_PUB_COMPRESSED;
    memcpy(env + pos, iv, LINK_GCM_IV_LEN); pos += LINK_GCM_IV_LEN;
    memcpy(env + pos, tag, LINK_GCM_TAG_LEN); pos += LINK_GCM_TAG_LEN;
    memcpy(env + pos, ct, pt_len); pos += pt_len;

    free(ct);
    OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
    OPENSSL_cleanse(shared_x, sizeof(shared_x));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));

    *envelope_out = env;
    *envelope_len = env_len;
    return 1;
}

static int
link_ecies_decrypt(const unsigned char *recipient_priv32,
                  const unsigned char *envelope, size_t envelope_len,
                  unsigned char **plaintext_out, size_t *pt_len)
{
    if (plaintext_out) *plaintext_out = NULL;
    if (envelope_len < 64) return 0;
    if (envelope[0] != DD_ECIES_VERSION_BYTE) return 0;
    if (envelope[1] != DD_ECIES_CIPHER_SUITE) return 0;
    if (envelope[2] != DD_ECIES_TYPE_BASIC) return 0;
    if (envelope[3] != 0x02 && envelope[3] != 0x03) return 0;

    const unsigned char *eph_pub = envelope + 3;
    const unsigned char *iv = envelope + 36;
    const unsigned char *tag = envelope + 48;
    const unsigned char *ct = envelope + 64;
    size_t ct_len = envelope_len - 64;

    secp256k1_context *ctx = link_secp();
    secp256k1_pubkey peer_pk;
    if (secp256k1_ec_pubkey_parse(ctx, &peer_pk, eph_pub, LINK_PUB_COMPRESSED) != 1) return 0;

    extern int link_secp_ecdh_xonly_cb(unsigned char *, const unsigned char *,
                                       const unsigned char *, void *);
    unsigned char shared_x[32];
    if (secp256k1_ecdh(ctx, shared_x, &peer_pk, recipient_priv32,
                       link_secp_ecdh_xonly_cb, NULL) != 1) return 0;

    unsigned char aes_key[32];
    if (!link_hkdf_sha256(shared_x, sizeof(shared_x),
                         (const unsigned char *)"", 0,
                         (const unsigned char *)DD_ECIES_HKDF_INFO, DD_ECIES_HKDF_INFO_LEN,
                         aes_key, sizeof(aes_key))) {
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        return 0;
    }

    unsigned char aad[3 + LINK_PUB_COMPRESSED];
    aad[0] = DD_ECIES_VERSION_BYTE;
    aad[1] = DD_ECIES_CIPHER_SUITE;
    aad[2] = DD_ECIES_TYPE_BASIC;
    memcpy(aad + 3, eph_pub, LINK_PUB_COMPRESSED);

    unsigned char *pt = malloc(ct_len);
    if (pt == NULL) {
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }
    int ok = link_aes_gcm_decrypt(aes_key, sizeof(aes_key),
                                 iv, LINK_GCM_IV_LEN, aad, sizeof(aad),
                                 ct, ct_len, tag, pt);
    OPENSSL_cleanse(shared_x, sizeof(shared_x));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    if (!ok) {
        free(pt);
        return 0;
    }
    *plaintext_out = pt;
    *pt_len = ct_len;
    return 1;
}

/* ECDH callback: copy raw X coordinate, no hashing. Per libsecp256k1 ABI:
 * `output` is 32 bytes for our use; we write x32 verbatim. */
int
link_secp_ecdh_xonly_cb(unsigned char *output,
                       const unsigned char *x32,
                       const unsigned char *y32,
                       void *data)
{
    (void)y32; (void)data;
    memcpy(output, x32, 32);
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Canonical transcript construction (RFC §4.5.3)                      */
/* ------------------------------------------------------------------ */

static int
link_build_transcript(const unsigned char *client_nonce,
                     const unsigned char *client_pub65,
                     const unsigned char *client_share,
                     const unsigned char *session_id,
                     const unsigned char *bridge_share,
                     double issued_at_bd,
                     int64_t bridge_issued_at_unix,
                     uint32_t ttl_seconds,
                     unsigned char *transcript_out)
{
    unsigned char *p = transcript_out;
    /* 25-byte literal NUL-terminated header. */
    memcpy(p, LINK_TRANSCRIPT_HEADER, LINK_TRANSCRIPT_HEADER_LEN); p += LINK_TRANSCRIPT_HEADER_LEN;

    link_le32(p, LINK_CLIENT_NONCE_LEN); p += 4;
    memcpy(p, client_nonce, LINK_CLIENT_NONCE_LEN); p += LINK_CLIENT_NONCE_LEN;

    link_le32(p, 65); p += 4;
    memcpy(p, client_pub65, 65); p += 65;

    link_le32(p, LINK_SHARE_LEN); p += 4;
    memcpy(p, client_share, LINK_SHARE_LEN); p += LINK_SHARE_LEN;

    link_le32(p, LINK_SESSION_ID_LEN); p += 4;
    memcpy(p, session_id, LINK_SESSION_ID_LEN); p += LINK_SESSION_ID_LEN;

    link_le32(p, LINK_SHARE_LEN); p += 4;
    memcpy(p, bridge_share, LINK_SHARE_LEN); p += LINK_SHARE_LEN;

    /* issued_at_bd → round(bd * 86400) as u64 BE. */
    int64_t issued_at_unix = (int64_t)(issued_at_bd * 86400.0 + 0.5);
    link_le32(p, 8); p += 4;
    link_be64(p, (uint64_t)issued_at_unix); p += 8;

    link_le32(p, 8); p += 4;
    link_be64(p, (uint64_t)bridge_issued_at_unix); p += 8;

    link_le32(p, 4); p += 4;
    p[0] = (unsigned char)((ttl_seconds >> 24) & 0xff);
    p[1] = (unsigned char)((ttl_seconds >> 16) & 0xff);
    p[2] = (unsigned char)((ttl_seconds >> 8) & 0xff);
    p[3] = (unsigned char)(ttl_seconds & 0xff);
    p += 4;

    return (size_t)(p - transcript_out) == LINK_TRANSCRIPT_TOTAL_LEN ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  LINK_REGISTER (RFC §4.5)                                             */
/* ------------------------------------------------------------------ */

/* GET_PUBLIC_KEY → bridge's persistent secp256k1 65-byte uncompressed key. */
static int
link_get_bridge_pubkey(unsigned char *out65)
{
    char *resp = NULL;
    if (!link_send_request("{\"cmd\":\"GET_PUBLIC_KEY\"}", &resp)) return 0;
    int ok = 0;
    if (resp != NULL) {
        size_t n = 0;
        if (link_json_field_b64(resp, "publicKey", out65, LINK_PUB_UNCOMPRESSED, &n)
            && n == LINK_PUB_UNCOMPRESSED && out65[0] == 0x04) {
            ok = 1;
        }
        free(resp);
    }
    return ok;
}

/* GET_ENCLAVE_PUBLIC_KEY → bridge's SEP P-256 65-byte uncompressed key. */
static int
link_get_bridge_sep_pub(unsigned char *out65)
{
    char *resp = NULL;
    if (!link_send_request("{\"cmd\":\"GET_ENCLAVE_PUBLIC_KEY\"}", &resp)) return 0;
    int ok = 0;
    if (resp != NULL) {
        size_t n = 0;
        if (link_json_field_b64(resp, "publicKey", out65, LINK_PUB_UNCOMPRESSED, &n)
            && n == LINK_PUB_UNCOMPRESSED && out65[0] == 0x04) {
            ok = 1;
        }
        free(resp);
    }
    return ok;
}

/* LINK_REGISTER. Performs the full §4.5 handshake. On success, populates
 * `link_session_id` and `link_session_key`. Returns 1 on success. */
static int
link_register_if_needed(char **errmsg)
{
    if (link_session_active) return 1;
    if (errmsg) *errmsg = NULL;

    /* 1. Fetch bridge keys. */
    unsigned char bridge_pub[LINK_PUB_UNCOMPRESSED];
    if (!link_get_bridge_pubkey(bridge_pub)) {
        if (errmsg) *errmsg = strdup("GET_PUBLIC_KEY failed");
        return 0;
    }
    unsigned char sep_pub[LINK_PUB_UNCOMPRESSED];
    if (!link_get_bridge_sep_pub(sep_pub)) {
        if (errmsg) *errmsg = strdup("GET_ENCLAVE_PUBLIC_KEY failed");
        return 0;
    }

    /* TOFU check. */
    if (link_pinned_sep_pub_set) {
        if (memcmp(sep_pub, link_pinned_sep_pub, LINK_PUB_UNCOMPRESSED) != 0) {
            if (errmsg) *errmsg = strdup("SEP key changed since pinned (TOFU mismatch)");
            return 0;
        }
    }

    /* 2. Generate client material. */
    unsigned char client_nonce[LINK_CLIENT_NONCE_LEN];
    unsigned char client_share[LINK_SHARE_LEN];
    unsigned char eph_priv[32];
    unsigned char eph_pub[LINK_PUB_UNCOMPRESSED];
    if (RAND_bytes(client_nonce, sizeof(client_nonce)) != 1 ||
        RAND_bytes(client_share, sizeof(client_share)) != 1 ||
        !link_secp_random_priv(eph_priv) ||
        !link_secp_pub_uncompressed(eph_priv, eph_pub)) {
        if (errmsg) *errmsg = strdup("RNG / secp256k1 setup failed");
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    /* 3. Build the §4.5.1 envelope plaintext. issuedAtBd ≈ now/86400. */
    double issued_at_bd = (double)time(NULL) / 86400.0;
    char client_pub_b64[128];
    char client_share_b64[64];
    link_b64encode(eph_pub, LINK_PUB_UNCOMPRESSED, client_pub_b64, sizeof(client_pub_b64));
    link_b64encode(client_share, LINK_SHARE_LEN, client_share_b64, sizeof(client_share_b64));

    char plaintext_json[1024];
    int n = snprintf(plaintext_json, sizeof(plaintext_json),
        "{\"v\":1,"
        "\"clientPub\":\"%s\","
        "\"clientShare\":\"%s\","
        "\"issuedAtBd\":%.6f,"
        "\"ttlSeconds\":%d,"
        "\"agent\":{\"name\":\"bsh\",\"version\":\"5.11.2\",\"platform\":\"brightlink-v1-c\"}}",
        client_pub_b64, client_share_b64, issued_at_bd, LINK_DEFAULT_TTL_SECONDS);
    if (n < 0 || (size_t)n >= sizeof(plaintext_json)) {
        if (errmsg) *errmsg = strdup("plaintext JSON overflow");
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    unsigned char *envelope = NULL;
    size_t envelope_len = 0;
    if (!link_ecies_encrypt(bridge_pub,
                           (const unsigned char *)plaintext_json, (size_t)n,
                           &envelope, &envelope_len)) {
        if (errmsg) *errmsg = strdup("ECIES encrypt failed");
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    /* 4. Send LINK_REGISTER. */
    size_t env_b64_cap = 4 * ((envelope_len + 2) / 3) + 1;
    char *env_b64 = malloc(env_b64_cap);
    char nonce_b64[32];
    if (env_b64 == NULL ||
        link_b64encode(envelope, envelope_len, env_b64, env_b64_cap) < 0 ||
        link_b64encode(client_nonce, sizeof(client_nonce), nonce_b64, sizeof(nonce_b64)) < 0) {
        free(envelope); free(env_b64);
        if (errmsg) *errmsg = strdup("base64 encode failed");
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }
    free(envelope);

    /* Request body. */
    size_t req_cap = strlen(env_b64) + 256;
    char *request = malloc(req_cap);
    if (request == NULL) { free(env_b64); OPENSSL_cleanse(eph_priv, sizeof(eph_priv)); return 0; }
    int rn = snprintf(request, req_cap,
        "{\"cmd\":\"LINK_REGISTER\",\"protocolVersion\":1,"
        "\"clientNonce\":\"%s\",\"envelope\":\"%s\"}",
        nonce_b64, env_b64);
    free(env_b64);
    if (rn < 0 || (size_t)rn >= req_cap) {
        free(request);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    char *resp = NULL;
    if (!link_send_request(request, &resp)) {
        free(request);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("LINK_REGISTER transport failed");
        return 0;
    }
    free(request);

    /* 5. Parse + validate response. */
    long long bridge_issued_at = 0;
    long long granted_ttl = 0;
    if (!link_json_field_int(resp, "bridgeIssuedAtUnix", &bridge_issued_at) ||
        !link_json_field_int(resp, "ttlSeconds", &granted_ttl)) {
        free(resp);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("LINK_REGISTER response missing fields");
        return 0;
    }
    unsigned char session_id[LINK_SESSION_ID_LEN];
    size_t sid_len = 0;
    if (!link_json_field_b64(resp, "sessionId", session_id, sizeof(session_id), &sid_len)
        || sid_len != LINK_SESSION_ID_LEN) {
        free(resp);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("LINK_REGISTER bad sessionId");
        return 0;
    }
    /* Pull responseEnvelope and decrypt to recover bridgeShare. */
    /* Allocate a generously-sized buffer for the b64 string. */
    size_t resp_env_b64_cap = strlen(resp) + 1;
    char *resp_env_b64 = malloc(resp_env_b64_cap);
    if (resp_env_b64 == NULL) { free(resp); OPENSSL_cleanse(eph_priv, sizeof(eph_priv)); return 0; }
    if (!link_json_field_str(resp, "responseEnvelope", resp_env_b64, resp_env_b64_cap)) {
        free(resp); free(resp_env_b64);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("LINK_REGISTER missing responseEnvelope");
        return 0;
    }
    unsigned char *resp_envelope = malloc(resp_env_b64_cap);
    if (resp_envelope == NULL) { free(resp); free(resp_env_b64); OPENSSL_cleanse(eph_priv, sizeof(eph_priv)); return 0; }
    size_t resp_env_len = 0;
    if (link_b64decode(resp_env_b64, strlen(resp_env_b64), resp_envelope, resp_env_b64_cap, &resp_env_len) < 0) {
        free(resp); free(resp_env_b64); free(resp_envelope);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("responseEnvelope b64 decode failed");
        return 0;
    }
    free(resp_env_b64);

    unsigned char *bridge_share = NULL;
    size_t bridge_share_len = 0;
    if (!link_ecies_decrypt(eph_priv, resp_envelope, resp_env_len,
                           &bridge_share, &bridge_share_len)
        || bridge_share_len != LINK_SHARE_LEN) {
        free(resp); free(resp_envelope); free(bridge_share);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("responseEnvelope decrypt failed");
        return 0;
    }
    free(resp_envelope);

    /* 6. Derive K_session via bilateral HKDF. */
    unsigned char ikm[2 * LINK_SHARE_LEN];
    memcpy(ikm, client_share, LINK_SHARE_LEN);
    memcpy(ikm + LINK_SHARE_LEN, bridge_share, LINK_SHARE_LEN);
    unsigned char salt[LINK_CLIENT_NONCE_LEN + LINK_SESSION_ID_LEN];
    memcpy(salt, client_nonce, LINK_CLIENT_NONCE_LEN);
    memcpy(salt + LINK_CLIENT_NONCE_LEN, session_id, LINK_SESSION_ID_LEN);

    unsigned char k_session[LINK_SESSION_KEY_LEN];
    if (!link_hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt),
                         (const unsigned char *)LINK_HKDF_INFO, LINK_HKDF_INFO_LEN,
                         k_session, sizeof(k_session))) {
        free(resp); free(bridge_share);
        OPENSSL_cleanse(ikm, sizeof(ikm));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("HKDF derive failed");
        return 0;
    }
    OPENSSL_cleanse(ikm, sizeof(ikm));

    /* 7. Verify SEP-signed transcript. */
    unsigned char transcript[LINK_TRANSCRIPT_TOTAL_LEN];
    if (!link_build_transcript(client_nonce, eph_pub, client_share,
                              session_id, bridge_share,
                              issued_at_bd, (int64_t)bridge_issued_at,
                              (uint32_t)granted_ttl, transcript)) {
        free(resp); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("transcript build failed");
        return 0;
    }
    /* Pull the DER signature. */
    char sig_b64[1024];
    if (!link_json_field_str(resp, "transcriptSig", sig_b64, sizeof(sig_b64))) {
        free(resp); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("missing transcriptSig");
        return 0;
    }
    unsigned char sig_der[256];
    size_t sig_der_len = 0;
    if (link_b64decode(sig_b64, strlen(sig_b64), sig_der, sizeof(sig_der), &sig_der_len) < 0) {
        free(resp); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("transcriptSig b64 decode failed");
        return 0;
    }
    if (!link_verify_p256_signature(sep_pub, transcript, sizeof(transcript),
                                   sig_der, sig_der_len)) {
        free(resp); free(bridge_share);
        OPENSSL_cleanse(k_session, sizeof(k_session));
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        if (errmsg) *errmsg = strdup("transcript signature verify failed");
        return 0;
    }
    free(resp);

    /* 8. Pin SEP key on first registration. */
    if (!link_pinned_sep_pub_set) {
        memcpy(link_pinned_sep_pub, sep_pub, LINK_PUB_UNCOMPRESSED);
        link_pinned_sep_pub_set = 1;
    }

    /* 9. Commit session state. Wipe staging buffers. */
    memcpy(link_session_id, session_id, LINK_SESSION_ID_LEN);
    memcpy(link_session_key, k_session, LINK_SESSION_KEY_LEN);
    link_session_id_set = 1;
    link_session_key_set = 1;
    link_session_active = 1;
    link_c_shell_to_agent = 0;
    link_c_agent_to_shell = 0;

    OPENSSL_cleanse(bridge_share, LINK_SHARE_LEN);
    free(bridge_share);
    OPENSSL_cleanse(client_share, sizeof(client_share));
    OPENSSL_cleanse(client_nonce, sizeof(client_nonce));
    OPENSSL_cleanse(k_session, sizeof(k_session));
    OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
    return 1;
}

/* ------------------------------------------------------------------ */
/*  LINK_DELIVER (RFC §4.9) — encrypt + JSON wire emit + send           */
/* ------------------------------------------------------------------ */

static int
link_emit_deliver(uint64_t counter,
                  const char *type, size_t type_len,
                  const unsigned char *context, size_t ctx_len,
                  const unsigned char *plaintext, size_t pt_len,
                  char **errmsg)
{
    if (errmsg) *errmsg = NULL;
    if (!link_session_key_set || !link_session_id_set) {
        if (errmsg) *errmsg = strdup("session not registered");
        return 0;
    }

    /* Counter encoded for AAD: 8-byte big-endian. */
    unsigned char counter_be[8];
    link_be64(counter_be, counter);

    /* AAD (RFC §4.6.3). dir_tag = 0x01 (Shell → Agent). */
    unsigned char aad[2048];
    size_t aad_len = 0;
    if (!link_build_deliver_aad(0x01, counter_be, sizeof(counter_be),
                                type, type_len, context, ctx_len,
                                aad, sizeof(aad), &aad_len)) {
        if (errmsg) *errmsg = strdup("AAD build failed");
        return 0;
    }

    /* IV. */
    unsigned char iv[LINK_GCM_IV_LEN];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        if (errmsg) *errmsg = strdup("RNG failed");
        return 0;
    }

    /* Encrypt. */
    unsigned char *ct = malloc(pt_len);
    unsigned char tag[LINK_GCM_TAG_LEN];
    if (ct == NULL) {
        if (errmsg) *errmsg = strdup("oom");
        return 0;
    }
    if (!link_aes_gcm_encrypt(link_session_key, sizeof(link_session_key),
                              iv, sizeof(iv), aad, aad_len,
                              plaintext, pt_len, ct, tag)) {
        free(ct);
        if (errmsg) *errmsg = strdup("AES-GCM encrypt failed");
        return 0;
    }

    /* base64 the binary fields. */
    char iv_b64[32];
    char tag_b64[32];
    size_t ct_b64_cap = 4 * ((pt_len + 2) / 3) + 1;
    char *ct_b64 = malloc(ct_b64_cap);
    if (ct_b64 == NULL ||
        link_b64encode(iv, sizeof(iv), iv_b64, sizeof(iv_b64)) < 0 ||
        link_b64encode(tag, sizeof(tag), tag_b64, sizeof(tag_b64)) < 0 ||
        link_b64encode(ct, pt_len, ct_b64, ct_b64_cap) < 0) {
        free(ct); free(ct_b64);
        if (errmsg) *errmsg = strdup("base64 encode failed");
        return 0;
    }
    free(ct);

    /* JSON-escape `type` and `context`. */
    size_t type_esc_cap = type_len * 6 + 1;
    size_t ctx_esc_cap = ctx_len * 6 + 1;
    char *type_esc = malloc(type_esc_cap);
    char *ctx_esc = malloc(ctx_esc_cap);
    if (type_esc == NULL || ctx_esc == NULL) {
        free(ct_b64); free(type_esc); free(ctx_esc);
        if (errmsg) *errmsg = strdup("oom");
        return 0;
    }
    size_t te = 0;
    for (size_t i = 0; i < type_len; i++) {
        unsigned char c = (unsigned char)type[i];
        if (c == '"' || c == '\\')
            te += snprintf(type_esc + te, type_esc_cap - te, "\\%c", c);
        else if (c >= 0x20 && c < 0x7f)
            type_esc[te++] = (char)c;
        else
            te += snprintf(type_esc + te, type_esc_cap - te, "\\u%04x", c);
    }
    type_esc[te] = '\0';
    size_t ce = 0;
    for (size_t i = 0; i < ctx_len; i++) {
        unsigned char c = context[i];
        if (c == '"' || c == '\\')
            ce += snprintf(ctx_esc + ce, ctx_esc_cap - ce, "\\%c", c);
        else if (c >= 0x20 && c < 0x7f)
            ctx_esc[ce++] = (char)c;
        else
            ce += snprintf(ctx_esc + ce, ctx_esc_cap - ce, "\\u%04x", c);
    }
    ctx_esc[ce] = '\0';

    /* Build the JSON request. */
    size_t req_cap = strlen(ct_b64) + te + ce + 256;
    char *req = malloc(req_cap);
    if (req == NULL) {
        free(ct_b64); free(type_esc); free(ctx_esc);
        if (errmsg) *errmsg = strdup("oom");
        return 0;
    }
    int n = snprintf(req, req_cap,
        "{\"cmd\":\"LINK_DELIVER\","
        "\"counter\":%llu,"
        "\"type\":\"%s\","
        "\"context\":\"%s\","
        "\"iv\":\"%s\","
        "\"ciphertext\":\"%s\","
        "\"authTag\":\"%s\"}",
        (unsigned long long)counter, type_esc, ctx_esc, iv_b64, ct_b64, tag_b64);
    free(ct_b64); free(type_esc); free(ctx_esc);
    if (n < 0 || (size_t)n >= req_cap) {
        free(req);
        if (errmsg) *errmsg = strdup("request JSON overflow");
        return 0;
    }

    /* Send. */
    char *resp = NULL;
    int ok = link_send_request(req, &resp);
    free(req);
    if (!ok) {
        if (errmsg) *errmsg = strdup("LINK_DELIVER transport failed");
        return 0;
    }
    if (resp != NULL) {
        if (strstr(resp, "\"error\"") != NULL) {
            char err[256] = {0};
            link_json_field_str(resp, "error", err, sizeof(err));
            if (errmsg) *errmsg = strdup(err[0] ? err : "LINK_DELIVER rejected");
            free(resp);
            return 0;
        }
        free(resp);
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  bsh-inject builtin (Subsystem 2 — Path A)                           */
/* ------------------------------------------------------------------ */

/* Read all of stdin into a malloc'd buffer (NUL-terminated). Returns 1 on
 * success, 0 on overflow or read error. */
static int
link_read_stdin(unsigned char **out, size_t *out_len)
{
    size_t cap = LINK_BUF_INIT;
    size_t pos = 0;
    unsigned char *buf = malloc(cap);
    if (buf == NULL) return 0;
    for (;;) {
        if (pos == cap) {
            if (cap >= LINK_BUF_MAX) { free(buf); return 0; }
            size_t nc = cap * 2;
            if (nc > LINK_BUF_MAX) nc = LINK_BUF_MAX;
            unsigned char *nb = realloc(buf, nc);
            if (nb == NULL) { free(buf); return 0; }
            buf = nb;
            cap = nc;
        }
        ssize_t n = read(0, buf + pos, cap - pos);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); return 0;
        }
        if (n == 0) break;
        pos += (size_t)n;
    }
    *out = buf;
    *out_len = pos;
    return 1;
}

/* The builtin's argument parser. Returns 0 on success; emits errors
 * to stderr and returns 1 on usage error. */
static int
bin_bsh_inject(char *nam, char **argv, UNUSED(Options ops), UNUSED(int func))
{
    const char *type = NULL;
    const char *context = NULL;

    for (int i = 0; argv[i] != NULL; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--type") == 0 && argv[i + 1] != NULL) {
            type = argv[++i];
        } else if (strcmp(a, "--context") == 0 && argv[i + 1] != NULL) {
            context = argv[++i];
        } else {
            fprintf(stderr, "%s: unknown argument: %s\n", nam, a);
            return 1;
        }
    }
    if (type == NULL || context == NULL) {
        fprintf(stderr, "%s: --type and --context are required\n", nam);
        return 1;
    }

    /* Read body from stdin. */
    unsigned char *body = NULL;
    size_t body_len = 0;
    if (!link_read_stdin(&body, &body_len)) {
        fprintf(stderr, "%s: stdin read failed or exceeded %d bytes\n", nam, LINK_BUF_MAX);
        return 1;
    }

    /* Lazy register. */
    char *err = NULL;
    if (!link_register_if_needed(&err)) {
        fprintf(stderr, "%s: LINK_REGISTER failed: %s\n", nam, err ? err : "unknown");
        free(err);
        OPENSSL_cleanse(body, body_len);
        free(body);
        return 1;
    }

    /* Allocate next counter. RFC §4.6.4: shell increments before each
     * emit; counter values are strictly monotonic per direction. */
    uint64_t counter = ++link_c_shell_to_agent;

    /* Encrypt + send LINK_DELIVER to the bridge. Fail closed — never
     * fall back to plaintext emit. */
    if (!link_emit_deliver(counter,
                           type, strlen(type),
                           (const unsigned char *)context, strlen(context),
                           body, body_len,
                           &err)) {
        fprintf(stderr, "%s: LINK_DELIVER failed: %s\n", nam, err ? err : "unknown");
        free(err);
        OPENSSL_cleanse(body, body_len);
        free(body);
        /* Roll back the counter so the next emit retries with the same
         * value (the bridge never advanced its inbound counter for a
         * failed deliver). */
        link_c_shell_to_agent--;
        return 1;
    }
    OPENSSL_cleanse(body, body_len);
    free(body);
    return 0;
}

/* ------------------------------------------------------------------ */
/* link-geo builtin                                                    */
/* ------------------------------------------------------------------ */
/*
 * `link-geo` is the bsh user-facing geo client. It speaks the BrightLink
 * v1 LINK_GEO_* command surface (RFC §9) over the same Unix socket as
 * bsh-inject. Subcommands map 1:1 to RFC §9 commands:
 *
 *   link-geo status                            → LINK_GEO_STATUS
 *   link-geo proximity <zone-id>               → LINK_GEO_PROXIMITY
 *   link-geo zone                              → LINK_GEO_ZONE
 *   link-geo get [--format wgs84|brightspace|both]  → LINK_GEO_GET
 *   link-geo refresh [--timeout N]             → LINK_GEO_REFRESH
 *
 * Output format: human-readable lines by default; pass `--json` to print
 * the bridge's raw response. Both forms exit non-zero on bridge error.
 *
 * No session is required — none of the LINK_GEO_* commands need
 * K_session today (RFC §9 currently treats them as session-optional;
 * gating on session-registered is reserved for a future revision).
 */

/* Tiny helper: locate a key's value-start in a flat JSON string and copy
 * up to a comma/closing-brace into `out`. Handles numeric, boolean, null,
 * and unquoted values that link_json_field_str misses. Returns 1 on
 * success. */
static int
link_json_field_raw(const char *json, const char *key, char *out, size_t out_cap)
{
    if (out_cap == 0 || out == NULL || json == NULL || key == NULL) return 0;
    char needle[64];
    int nl = snprintf(needle, sizeof(needle), "\"%s\":", key);
    if (nl <= 0 || (size_t)nl >= sizeof(needle)) return 0;
    const char *p = strstr(json, needle);
    if (p == NULL) return 0;
    p += nl;
    /* Skip leading whitespace and an opening quote if any. */
    while (*p == ' ' || *p == '\t') p++;
    int quoted = (*p == '"');
    if (quoted) p++;
    size_t i = 0;
    while (*p != '\0' && i + 1 < out_cap) {
        if (quoted && *p == '"') break;
        if (!quoted && (*p == ',' || *p == '}' || *p == ']')) break;
        out[i++] = *p++;
    }
    out[i] = '\0';
    /* Trim trailing whitespace. */
    while (i > 0 && (out[i - 1] == ' ' || out[i - 1] == '\t' || out[i - 1] == '\n')) {
        out[--i] = '\0';
    }
    return i > 0 ? 1 : 0;
}

static int
link_geo_print_status(const char *resp, int json_mode)
{
    if (json_mode) { printf("%s\n", resp); return 0; }
    char tmp[256];
    if (link_json_field_raw(resp, "alive", tmp, sizeof(tmp)))
        printf("alive: %s\n", tmp);
    if (link_json_field_str(resp, "engine_kind", tmp, sizeof(tmp)))
        printf("engine_kind: %s\n", tmp);
    if (link_json_field_raw(resp, "fix_age_seconds", tmp, sizeof(tmp)))
        printf("fix_age_seconds: %s\n", tmp);
    if (link_json_field_raw(resp, "accuracy_m", tmp, sizeof(tmp)))
        printf("accuracy_m: %s\n", tmp);
    return 0;
}

static int
link_geo_print_zone(const char *resp, int json_mode)
{
    if (json_mode) { printf("%s\n", resp); return 0; }
    char tmp[256];
    if (link_json_field_raw(resp, "zone", tmp, sizeof(tmp)))
        printf("zone: %s\n", tmp);
    if (link_json_field_raw(resp, "dwell_seconds", tmp, sizeof(tmp)))
        printf("dwell_seconds: %s\n", tmp);
    if (link_json_field_raw(resp, "brightdate", tmp, sizeof(tmp)))
        printf("brightdate: %s\n", tmp);
    return 0;
}

static int
link_geo_print_proximity(const char *resp, int json_mode)
{
    if (json_mode) { printf("%s\n", resp); return 0; }
    char tmp[256];
    if (link_json_field_raw(resp, "in_zone", tmp, sizeof(tmp)))
        printf("in_zone: %s\n", tmp);
    if (link_json_field_raw(resp, "brightdate", tmp, sizeof(tmp)))
        printf("brightdate: %s\n", tmp);
    return 0;
}

static int
link_geo_print_refresh(const char *resp, int json_mode)
{
    if (json_mode) { printf("%s\n", resp); return 0; }
    char tmp[256];
    if (link_json_field_raw(resp, "fix_age_seconds", tmp, sizeof(tmp)))
        printf("fix_age_seconds: %s\n", tmp);
    if (link_json_field_raw(resp, "accuracy_m", tmp, sizeof(tmp)))
        printf("accuracy_m: %s\n", tmp);
    return 0;
}

static int
link_geo_print_position(const char *resp, int json_mode)
{
    if (json_mode) {
        printf("%s\n", resp);
        return 0;
    }
    /* The response shape for LINK_GEO_GET is:
     *   {"ok":true,"position":{"wgs84":{"lat":N,"lon":N,"alt_m":N},
     *                          "brightspace":{"x_bm":N,...}},
     *    "accuracy_m":N,"brightdate":N}
     *
     * Hand-extract the inner fields. Field names are unique enough not
     * to need a real recursive parser — `lat`/`lon` only appear inside
     * `wgs84`, `x_bm`/`y_bm`/`z_bm` only inside `brightspace`. */
    char tmp[256];
    int printed = 0;
    if (link_json_field_raw(resp, "lat", tmp, sizeof(tmp))) {
        printf("lat: %s\n", tmp); printed = 1;
    }
    if (link_json_field_raw(resp, "lon", tmp, sizeof(tmp))) {
        printf("lon: %s\n", tmp); printed = 1;
    }
    if (link_json_field_raw(resp, "alt_m", tmp, sizeof(tmp))) {
        printf("alt_m: %s\n", tmp); printed = 1;
    }
    if (link_json_field_raw(resp, "x_bm", tmp, sizeof(tmp))) {
        printf("x_bm: %s\n", tmp); printed = 1;
    }
    if (link_json_field_raw(resp, "y_bm", tmp, sizeof(tmp))) {
        printf("y_bm: %s\n", tmp); printed = 1;
    }
    if (link_json_field_raw(resp, "z_bm", tmp, sizeof(tmp))) {
        printf("z_bm: %s\n", tmp); printed = 1;
    }
    if (link_json_field_raw(resp, "accuracy_m", tmp, sizeof(tmp))) {
        printf("accuracy_m: %s\n", tmp); printed = 1;
    }
    if (link_json_field_raw(resp, "brightdate", tmp, sizeof(tmp))) {
        printf("brightdate: %s\n", tmp); printed = 1;
    }
    if (!printed) {
        printf("%s\n", resp);
    }
    return 0;
}

static int
link_geo_handle_response(const char *nam, const char *resp,
                         int json_mode, const char *cmd_label)
{
    if (resp == NULL) {
        fprintf(stderr, "%s: no response from bridge\n", nam);
        return 1;
    }
    /* Bridge error path. */
    if (strstr(resp, "\"error\"") != NULL) {
        char err[256] = {0};
        link_json_field_str(resp, "error", err, sizeof(err));
        if (json_mode) {
            printf("%s\n", resp);
        } else {
            fprintf(stderr, "%s: %s: %s\n", nam, cmd_label,
                    err[0] ? err : "bridge error");
        }
        return 1;
    }
    /* Dispatch to per-subcommand printer. */
    if (strcmp(cmd_label, "status") == 0) {
        return link_geo_print_status(resp, json_mode);
    } else if (strcmp(cmd_label, "zone") == 0) {
        return link_geo_print_zone(resp, json_mode);
    } else if (strcmp(cmd_label, "proximity") == 0) {
        return link_geo_print_proximity(resp, json_mode);
    } else if (strcmp(cmd_label, "refresh") == 0) {
        return link_geo_print_refresh(resp, json_mode);
    } else { /* get */
        return link_geo_print_position(resp, json_mode);
    }
}

static int
bin_link_geo(char *nam, char **argv, UNUSED(Options ops), UNUSED(int func))
{
    if (argv[0] == NULL) {
        fprintf(stderr,
            "Usage: %s <subcommand> [args...]\n"
            "Subcommands:\n"
            "  status                                  engine alive + fix freshness\n"
            "  proximity <zone-id>                     yes/no for one named zone\n"
            "  zone                                    current zone + dwell\n"
            "  get [--format wgs84|brightspace|both]   precise position\n"
            "  refresh [--timeout SECONDS]             trigger a fresh fix\n"
            "\n"
            "Common flags:\n"
            "  --json                                  emit raw bridge response\n",
            nam);
        return 1;
    }

    int json_mode = 0;
    /* Strip --json out of argv anywhere it appears (argv stays NULL-
     * terminated thanks to in-place compaction). */
    {
        int r = 0, w = 0;
        while (argv[r] != NULL) {
            if (strcmp(argv[r], "--json") == 0) {
                json_mode = 1; r++; continue;
            }
            argv[w++] = argv[r++];
        }
        argv[w] = NULL;
    }

    const char *sub = argv[0];
    char *resp = NULL;
    char request[512];
    int rc = 1;

    if (strcmp(sub, "status") == 0) {
        if (!link_send_request("{\"cmd\":\"LINK_GEO_STATUS\"}", &resp)) {
            fprintf(stderr, "%s: bridge unavailable\n", nam);
            return 1;
        }
        rc = link_geo_handle_response(nam, resp, json_mode, "status");
    } else if (strcmp(sub, "proximity") == 0) {
        if (argv[1] == NULL) {
            fprintf(stderr, "%s: proximity requires a zone id\n", nam);
            free(resp);
            return 1;
        }
        /* Tightly bounded length so snprintf never truncates the
         * surrounding JSON syntax. */
        if (strlen(argv[1]) > 256) {
            fprintf(stderr, "%s: zone id too long\n", nam);
            return 1;
        }
        snprintf(request, sizeof(request),
                 "{\"cmd\":\"LINK_GEO_PROXIMITY\",\"zone\":\"%s\"}", argv[1]);
        if (!link_send_request(request, &resp)) {
            fprintf(stderr, "%s: bridge unavailable\n", nam);
            return 1;
        }
        rc = link_geo_handle_response(nam, resp, json_mode, "proximity");
    } else if (strcmp(sub, "zone") == 0) {
        if (!link_send_request("{\"cmd\":\"LINK_GEO_ZONE\"}", &resp)) {
            fprintf(stderr, "%s: bridge unavailable\n", nam);
            return 1;
        }
        rc = link_geo_handle_response(nam, resp, json_mode, "zone");
    } else if (strcmp(sub, "get") == 0) {
        const char *fmt = "wgs84";
        for (int i = 1; argv[i] != NULL; i++) {
            if (strcmp(argv[i], "--format") == 0 && argv[i + 1] != NULL) {
                fmt = argv[i + 1];
                i++;
                continue;
            }
        }
        if (strcmp(fmt, "wgs84") != 0
            && strcmp(fmt, "brightspace") != 0
            && strcmp(fmt, "both") != 0) {
            fprintf(stderr, "%s: --format must be wgs84, brightspace, or both\n",
                    nam);
            return 1;
        }
        snprintf(request, sizeof(request),
                 "{\"cmd\":\"LINK_GEO_GET\",\"format\":\"%s\"}", fmt);
        if (!link_send_request(request, &resp)) {
            fprintf(stderr, "%s: bridge unavailable\n", nam);
            return 1;
        }
        rc = link_geo_handle_response(nam, resp, json_mode, "get");
    } else if (strcmp(sub, "refresh") == 0) {
        long timeout_s = 30;
        for (int i = 1; argv[i] != NULL; i++) {
            if (strcmp(argv[i], "--timeout") == 0 && argv[i + 1] != NULL) {
                char *end = NULL;
                long v = strtol(argv[i + 1], &end, 10);
                if (end == argv[i + 1] || *end != '\0' || v < 1 || v > 300) {
                    fprintf(stderr,
                            "%s: --timeout must be 1..300\n", nam);
                    return 1;
                }
                timeout_s = v;
                i++;
                continue;
            }
        }
        snprintf(request, sizeof(request),
                 "{\"cmd\":\"LINK_GEO_REFRESH\",\"timeout_seconds\":%ld}",
                 timeout_s);
        if (!link_send_request(request, &resp)) {
            fprintf(stderr, "%s: bridge unavailable\n", nam);
            return 1;
        }
        rc = link_geo_handle_response(nam, resp, json_mode, "refresh");
    } else {
        fprintf(stderr, "%s: unknown subcommand: %s\n", nam, sub);
        free(resp);
        return 1;
    }

    free(resp);
    return rc;
}

/*  Module registration                                                 */
/* ------------------------------------------------------------------ */

static struct builtin bintab[] = {
    BUILTIN("bsh-inject", 0, bin_bsh_inject, 0, -1, 0, NULL, NULL),
    BUILTIN("link-geo",   0, bin_link_geo,   0, -1, 0, NULL, NULL),
};

static struct features module_features = {
    bintab, sizeof(bintab) / sizeof(*bintab),
    NULL, 0,
    NULL, 0,
    NULL, 0,
    0
};

/**/
int
setup_(UNUSED(Module m))
{
    return 0;
}

/**/
int
features_(Module m, char ***features)
{
    *features = featuresarray(m, &module_features);
    return 0;
}

/**/
int
enables_(Module m, int **enables)
{
    return handlefeatures(m, &module_features, enables);
}

/**/
int
boot_(UNUSED(Module m))
{
    /* No eager work; LINK_REGISTER is lazy on first inject. */
    return 0;
}

/**/
int
cleanup_(Module m)
{
    return setfeatureenables(m, &module_features, NULL);
}

/**/
int
finish_(UNUSED(Module m))
{
    link_socket_close();
    OPENSSL_cleanse(link_session_key, sizeof(link_session_key));
    OPENSSL_cleanse(link_session_id, sizeof(link_session_id));
    link_session_active = 0;
    link_session_key_set = 0;
    link_session_id_set = 0;
    if (link_secp_ctx != NULL) {
        secp256k1_context_destroy(link_secp_ctx);
        link_secp_ctx = NULL;
    }
    return 0;
}
