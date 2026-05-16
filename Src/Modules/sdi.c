/*
 * sdi.c - Secure Data Injection (SDI) module for bsh
 *
 * Implements two features described in the Phased SDI Implementation Plan:
 *
 *   Task 1.1 – Session Initialisation & Handshake Hook
 *     On boot, checks for the Desktop Agent's Unix domain socket at
 *     SDI_SOCKET_PATH.  If present, performs an X25519 ECDH key exchange
 *     and derives a 256-bit AES session key via HKDF-SHA256.  The session
 *     id and key are kept in module-level static memory and are never
 *     exported to the environment.
 *
 *   Task 1.2 – bsh-inject builtin
 *     Reads a payload from stdin, encrypts it with AES-256-GCM using the
 *     session key, and writes an OSC 7777 escape sequence to stdout.
 *
 * Syntax:
 *   generate-test-data | bsh-inject --type ephemeral-auth \
 *                                   --context "http://localhost:3005"
 *
 * Requires OpenSSL 1.1.0+.  Link with -lcrypto.
 */

#include "sdi.mdh"
#include "sdi.pro"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

#define SDI_SOCKET_PATH     "/tmp/sdi_secure.sock"
#define SDI_SESSION_ID_LEN  16      /* bytes  */
#define SDI_SESSION_KEY_LEN 32      /* bytes, 256-bit AES key */
#define SDI_X25519_KEY_LEN  32      /* bytes  */
#define SDI_NONCE_LEN       12      /* bytes, GCM nonce */
#define SDI_TAG_LEN         16      /* bytes, GCM auth tag */

/* Initial / maximum sizes for the stdin read buffer */
#define SDI_BUF_INIT        4096
#define SDI_BUF_MAX         (64 * 1024 * 1024)   /* 64 MB hard cap */

/* ------------------------------------------------------------------ */
/*  Session state – never exported to the environment                   */
/* ------------------------------------------------------------------ */

static unsigned char sdi_session_id[SDI_SESSION_ID_LEN];
static unsigned char sdi_session_key[SDI_SESSION_KEY_LEN];
static int           sdi_session_active = 0;
static uint64_t      sdi_session_counter = 0;  /* per-session monotonic counter (RFC §3.5) */
static int           sdi_sockfd = -1;           /* persistent socket kept open for OSC relay  */

/* ------------------------------------------------------------------ */
/*  Low-level I/O helpers                                               */
/* ------------------------------------------------------------------ */

/* Blocking write of exactly `len` bytes; returns -1 on error. */
static ssize_t
write_all(int fd, const void *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, (const char *)buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

/* Blocking read of exactly `len` bytes; returns -1 on error / EOF. */
static ssize_t
read_all(int fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;  /* unexpected EOF */
        got += (size_t)n;
    }
    return (ssize_t)got;
}

/* ------------------------------------------------------------------ */
/*  Cryptographic helpers                                               */
/* ------------------------------------------------------------------ */

/*
 * HKDF-SHA256 (RFC 5869) – extract then expand.
 *
 * Derives `okm_len` bytes (must be <= SHA256_DIGEST_LENGTH == 32) of
 * keying material into `okm`.
 *
 * Uses HMAC() from OpenSSL/LibreSSL which is present in every version.
 */
static int
hkdf_sha256(const unsigned char *ikm,  size_t ikm_len,
            const unsigned char *salt, size_t salt_len,
            const unsigned char *info, size_t info_len,
            unsigned char       *okm,  size_t okm_len)
{
    unsigned char prk[32];
    unsigned char t1_input[32 + 256 + 1];   /* T(0) || info || counter  */
    unsigned int  hmac_len = 32;

    if (okm_len > 32 || info_len > 256)
        return 0;

    /* Extract: PRK = HMAC-SHA256(salt, IKM) */
    if (!HMAC(EVP_sha256(),
              salt, (int)salt_len,
              ikm,  (int)ikm_len,
              prk, &hmac_len))
        return 0;

    /*
     * Expand: T(1) = HMAC-SHA256(PRK, "" || info || 0x01)
     * (T(0) is the empty string, so T(0) || info || counter = info || 0x01)
     */
    memcpy(t1_input, info, info_len);
    t1_input[info_len] = 0x01;
    hmac_len = 32;
    if (!HMAC(EVP_sha256(),
              prk, 32,
              t1_input, (unsigned int)(info_len + 1),
              okm, &hmac_len))
        return 0;

    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(t1_input, sizeof(t1_input));
    return 1;
}

/*
 * Base64-encode `srclen` bytes from `src`.
 * Returns a freshly zalloc'd NUL-terminated string; caller must zsfree().
 */
static char *
sdi_b64enc(const unsigned char *src, int srclen)
{
    int   dstlen = ((srclen + 2) / 3) * 4 + 1;
    char *dst    = (char *)zalloc((size_t)dstlen);

    if (!dst)
        return NULL;
    EVP_EncodeBlock((unsigned char *)dst, src, srclen);
    return dst;
}

/* ------------------------------------------------------------------ */
/*  Task 1.1 – Session initialisation handshake                        */
/* ------------------------------------------------------------------ */

/**/
static void
sdi_session_init(void)
{
    struct sockaddr_un addr;
    struct stat        st;
    int                sockfd = -1;
    uid_t              uid    = getuid();
    const char        *sock_path;

    EVP_PKEY_CTX *kgen_ctx   = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    EVP_PKEY     *our_key    = NULL;
    EVP_PKEY     *agt_key    = NULL;

    unsigned char our_pub[SDI_X25519_KEY_LEN];
    unsigned char agt_pub[SDI_X25519_KEY_LEN];
    unsigned char shared[SDI_X25519_KEY_LEN];
    unsigned char wire_msg[SDI_SESSION_ID_LEN + SDI_X25519_KEY_LEN];

    size_t        outlen;

    sdi_session_active = 0;

    /*
     * Allow SDI_SOCKET_PATH env var to override the compiled-in default.
     * This is used by the test suite to redirect to a test socket without
     * requiring root or modifying the system socket path.
     */
    sock_path = getenv("SDI_SOCKET_PATH");
    if (!sock_path || !*sock_path)
        sock_path = SDI_SOCKET_PATH;

    /* ---------------------------------------------------------------
     * 1. Verify the socket exists, is a socket, and belongs to us.
     *    This guards against an unprivileged third party placing a
     *    rogue socket at the well-known path.
     * --------------------------------------------------------------- */
    if (stat(sock_path, &st) != 0)
        goto cleanup;

    if (!S_ISSOCK(st.st_mode))
        goto cleanup;

    /* Socket must be owned by the calling user. */
    if (st.st_uid != uid)
        goto cleanup;

    /* Socket permissions must exclude writes/reads by group and other. */
    if (st.st_mode & (S_IRWXG | S_IRWXO))
        goto cleanup;

    /* ---------------------------------------------------------------
     * 2. Connect.
     * --------------------------------------------------------------- */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0)
        goto cleanup;

    /* Apply a 5-second timeout on I/O so a silent agent can't block forever. */
    {
        struct timeval tv = { 5, 0 };
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto cleanup;

    /* ---------------------------------------------------------------
     * 3. Generate a random session_id and an ephemeral X25519 keypair.
     * --------------------------------------------------------------- */
    if (RAND_bytes(sdi_session_id, SDI_SESSION_ID_LEN) != 1)
        goto cleanup;

    kgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kgen_ctx || EVP_PKEY_keygen_init(kgen_ctx) <= 0)
        goto cleanup;
    if (EVP_PKEY_keygen(kgen_ctx, &our_key) <= 0)
        goto cleanup;

    outlen = SDI_X25519_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(our_key, our_pub, &outlen) <= 0)
        goto cleanup;

    /* ---------------------------------------------------------------
     * 4. Send [ session_id (16 B) | our_public_key (32 B) ] to the
     *    agent to register this shell instance.
     * --------------------------------------------------------------- */
    memcpy(wire_msg,                        sdi_session_id, SDI_SESSION_ID_LEN);
    memcpy(wire_msg + SDI_SESSION_ID_LEN,   our_pub,        SDI_X25519_KEY_LEN);

    if (write_all(sockfd, wire_msg, sizeof(wire_msg)) !=
            (ssize_t)sizeof(wire_msg))
        goto cleanup;

    /* ---------------------------------------------------------------
     * 5. Read the agent's ephemeral X25519 public key (32 B).
     * --------------------------------------------------------------- */
    if (read_all(sockfd, agt_pub, SDI_X25519_KEY_LEN) !=
            (ssize_t)SDI_X25519_KEY_LEN)
        goto cleanup;

    /* ---------------------------------------------------------------
     * 6. ECDH: compute the raw X25519 shared secret.
     * --------------------------------------------------------------- */
    agt_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                          agt_pub, SDI_X25519_KEY_LEN);
    if (!agt_key)
        goto cleanup;

    derive_ctx = EVP_PKEY_CTX_new(our_key, NULL);
    if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0)
        goto cleanup;
    if (EVP_PKEY_derive_set_peer(derive_ctx, agt_key) <= 0)
        goto cleanup;

    outlen = SDI_X25519_KEY_LEN;
    if (EVP_PKEY_derive(derive_ctx, shared, &outlen) <= 0)
        goto cleanup;

    /* ---------------------------------------------------------------
     * 7. Derive the final 256-bit session_key using HKDF-SHA256.
     *    Salt  = session_id  (ties key material to this session)
     *    IKM   = shared      (raw ECDH output)
     *    Info  = "sdi-session-key"
     * --------------------------------------------------------------- */
    if (!hkdf_sha256(shared,          outlen,
                     sdi_session_id,  SDI_SESSION_ID_LEN,
                     (const unsigned char *)"sdi-session-key", 15,
                     sdi_session_key, SDI_SESSION_KEY_LEN))
        goto cleanup;

    sdi_session_counter = 0;  /* reset counter on every new session */

    /* Clear the 5-second handshake timeout — the socket is now kept open
     * indefinitely for OSC relay (RFC §3.6, Option B). */
    {
        struct timeval zero = { 0, 0 };
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));
    }

    sdi_session_active = 1;

cleanup:
    OPENSSL_cleanse(shared,    sizeof(shared));
    OPENSSL_cleanse(our_pub,   sizeof(our_pub));
    OPENSSL_cleanse(wire_msg,  sizeof(wire_msg));

    if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
    if (agt_key)    EVP_PKEY_free(agt_key);
    if (our_key)    EVP_PKEY_free(our_key);
    if (kgen_ctx)   EVP_PKEY_CTX_free(kgen_ctx);

    if (sockfd >= 0) {
        if (sdi_session_active)
            sdi_sockfd = sockfd;  /* keep open — relay will use it */
        else
            close(sockfd);        /* handshake failed — discard    */
    }

    if (!sdi_session_active) {
        /* Wipe partial state so it is never left in a half-initialised form. */
        OPENSSL_cleanse(sdi_session_id,  sizeof(sdi_session_id));
        OPENSSL_cleanse(sdi_session_key, sizeof(sdi_session_key));
    }
}

/* ------------------------------------------------------------------ */
/*  Task 1.2 – bsh-inject builtin                                      */
/* ------------------------------------------------------------------ */

/**/
static int
bin_bsh_inject(char *nam, char **args, UNUSED(Options ops), UNUSED(int func))
{
    const char    *type_val    = NULL;
    const char    *context_val = NULL;
    int            emit_stdout = 0;  /* --emit-stdout: write OSC to fd 1 instead of /dev/tty */

    unsigned char  nonce[SDI_NONCE_LEN];
    unsigned char  tag[SDI_TAG_LEN];
    unsigned char *ciphertext  = NULL;
    size_t         cipher_alloc = 0;

    unsigned char  counter_bytes[8];  /* 8-byte big-endian counter (RFC §3.5) */
    char          *b64_counter = NULL;
    char          *b64_nonce   = NULL;
    char          *b64_ct      = NULL;
    char          *b64_tag     = NULL;
    char          *b64_context = NULL;
    char           sid_hex[SDI_SESSION_ID_LEN * 2 + 1];

    unsigned char *plaintext   = NULL;
    size_t         plainlen    = 0;
    size_t         bufcap      = SDI_BUF_INIT;

    EVP_CIPHER_CTX *ctx        = NULL;
    int             outlen     = 0;
    int             tmplen     = 0;
    int             ret        = 1;
    int             i;

    /* -----------------------------------------------------------
     * Parse long options (--type, --context).
     *
     * BSH's option framework handles single-character flags; long
     * options are parsed manually here.
     * ----------------------------------------------------------- */
    while (*args && (*args)[0] == '-' && (*args)[1] == '-' && (*args)[2]) {
        if (strcmp(*args, "--type") == 0) {
            ++args;
            if (!*args) {
                zerrnam(nam, "missing argument to --type");
                return 1;
            }
            type_val = *args++;
        } else if (strcmp(*args, "--context") == 0) {
            ++args;
            if (!*args) {
                zerrnam(nam, "missing argument to --context");
                return 1;
            }
            context_val = *args++;
        } else if (strcmp(*args, "--emit-stdout") == 0) {
            ++args;
            emit_stdout = 1;
        } else if (strcmp(*args, "--") == 0) {
            ++args;
            break;
        } else {
            zerrnam(nam, "unknown option: %s", *args);
            return 1;
        }
    }

    /* Reject stray positional arguments. */
    if (*args) {
        zerrnam(nam, "unexpected argument: %s", *args);
        return 1;
    }

    /* Lazy initialisation: attempt the handshake now if not yet active.
     * This covers non-interactive shells (bsh -c) where boot_() skipped it. */
    if (!sdi_session_active)
        sdi_session_init();

    /* Socket was lost (e.g. agent restarted, or previous ack failure closed it)
     * but session state is stale-active.  Re-initialise so we reconnect. */
    if (sdi_session_active && sdi_sockfd < 0) {
        sdi_session_active = 0;
        OPENSSL_cleanse(sdi_session_key, sizeof(sdi_session_key));
        OPENSSL_cleanse(sdi_session_id,  sizeof(sdi_session_id));
        sdi_session_counter = 0;
        sdi_session_init();
    }

    if (!sdi_session_active) {
        zerrnam(nam, "no active SDI session (is the Desktop Agent running?)");
        return 1;
    }

    /* -----------------------------------------------------------
     * Snapshot the current per-session counter and encode it as an
     * 8-byte big-endian unsigned integer (RFC §3.5).
     * The counter is incremented only after a successful emit.
     * ----------------------------------------------------------- */
    {
        uint64_t c = sdi_session_counter;
        counter_bytes[0] = (unsigned char)((c >> 56) & 0xFF);
        counter_bytes[1] = (unsigned char)((c >> 48) & 0xFF);
        counter_bytes[2] = (unsigned char)((c >> 40) & 0xFF);
        counter_bytes[3] = (unsigned char)((c >> 32) & 0xFF);
        counter_bytes[4] = (unsigned char)((c >> 24) & 0xFF);
        counter_bytes[5] = (unsigned char)((c >> 16) & 0xFF);
        counter_bytes[6] = (unsigned char)((c >>  8) & 0xFF);
        counter_bytes[7] = (unsigned char)( c        & 0xFF);
    }

    /* -----------------------------------------------------------
     * Read the entire stdin payload into a dynamically grown buffer.
     * ----------------------------------------------------------- */
    plaintext = (unsigned char *)zalloc(bufcap);
    if (!plaintext)
        return 1;

    while (1) {
        ssize_t n = read(STDIN_FILENO, plaintext + plainlen,
                         bufcap - plainlen);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            zerrnam(nam, "read: %s", strerror(errno));
            goto done;
        }
        if (n == 0)
            break;  /* EOF */

        plainlen += (size_t)n;

        if (plainlen >= bufcap) {
            unsigned char *tmp;
            if (bufcap > SDI_BUF_MAX / 2) {
                zerrnam(nam, "input payload exceeds maximum size");
                goto done;
            }
            bufcap *= 2;
            tmp = (unsigned char *)zrealloc(plaintext, bufcap);
            if (!tmp) {
                zerrnam(nam, "out of memory");
                goto done;
            }
            plaintext = tmp;
        }
    }

    /* -----------------------------------------------------------
     * Generate a cryptographically secure 12-byte nonce.
     * ----------------------------------------------------------- */
    if (RAND_bytes(nonce, SDI_NONCE_LEN) != 1) {
        zerrnam(nam, "RAND_bytes failed");
        goto done;
    }

    /* -----------------------------------------------------------
     * AES-256-GCM encrypt.
     *
     * The --type and --context values (if supplied) are fed as
     * Additional Authenticated Data (AAD) so they are verified on
     * decryption without being included in the ciphertext.
     * ----------------------------------------------------------- */
    cipher_alloc = plainlen + (size_t)EVP_MAX_BLOCK_LENGTH;
    ciphertext   = (unsigned char *)zalloc(cipher_alloc);
    if (!ciphertext)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto done;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            SDI_NONCE_LEN, NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, sdi_session_key, nonce) != 1)
        goto done;

    /* Feed length-prefixed AAD (RFC §3.4).
     * Format: LE32(len) || bytes, for each of: counter, type, context.
     * LE32(0) is emitted even when a field is absent/empty. */
    {
        unsigned char len_buf[4];
        size_t type_len = type_val    ? strlen(type_val)    : 0;
        size_t ctx_len  = context_val ? strlen(context_val) : 0;

#define SDI_FEED_LE32(n) do { \
    uint32_t _v = (uint32_t)(n); \
    len_buf[0] = (unsigned char)(_v        & 0xFF); \
    len_buf[1] = (unsigned char)((_v >>  8) & 0xFF); \
    len_buf[2] = (unsigned char)((_v >> 16) & 0xFF); \
    len_buf[3] = (unsigned char)((_v >> 24) & 0xFF); \
    if (EVP_EncryptUpdate(ctx, NULL, &tmplen, len_buf, 4) != 1) goto done; \
} while (0)

        /* counter — always 8 bytes */
        SDI_FEED_LE32(8);
        if (EVP_EncryptUpdate(ctx, NULL, &tmplen, counter_bytes, 8) != 1)
            goto done;

        /* type */
        SDI_FEED_LE32(type_len);
        if (type_len > 0 &&
            EVP_EncryptUpdate(ctx, NULL, &tmplen,
                              (const unsigned char *)type_val,
                              (int)type_len) != 1)
            goto done;

        /* context (raw bytes, not base64-encoded) */
        SDI_FEED_LE32(ctx_len);
        if (ctx_len > 0 &&
            EVP_EncryptUpdate(ctx, NULL, &tmplen,
                              (const unsigned char *)context_val,
                              (int)ctx_len) != 1)
            goto done;

#undef SDI_FEED_LE32
    }

    /* Encrypt the payload. */
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen,
                          plaintext, (int)plainlen) != 1)
        goto done;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1)
        goto done;

    outlen += tmplen;

    /* Extract the 16-byte GCM authentication tag. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            SDI_TAG_LEN, tag) != 1)
        goto done;

    /* -----------------------------------------------------------
     * Base64-encode the three binary components.
     * ----------------------------------------------------------- */
    b64_counter = sdi_b64enc(counter_bytes, 8);
    b64_nonce   = sdi_b64enc(nonce, SDI_NONCE_LEN);
    b64_ct      = sdi_b64enc(ciphertext, outlen);
    b64_tag     = sdi_b64enc(tag, SDI_TAG_LEN);

    if (context_val && *context_val)
        b64_context = sdi_b64enc((const unsigned char *)context_val,
                                 strlen(context_val));

    if (!b64_counter || !b64_nonce || !b64_ct || !b64_tag)
        goto done;

    /* -----------------------------------------------------------
     * Encode session_id as lowercase hex for the OSC payload.
     * ----------------------------------------------------------- */
    for (i = 0; i < SDI_SESSION_ID_LEN; i++)
        snprintf(sid_hex + i * 2, 3, "%02x", sdi_session_id[i]);
    sid_hex[SDI_SESSION_ID_LEN * 2] = '\0';

    /* -----------------------------------------------------------
     * Build the OSC 7777 string once, write it to /dev/tty, then
     * relay the exact same bytes to SDIAgent over the persistent
     * registration socket (RFC §3.6, Option B).
     *
     * Protocol after ECDH:
     *   bsh → agent:  0x02 | LE32(len) | OSC bytes
     *   agent → bsh:  0x01 (ok) | 0x00 (fail)
     *
     * Counter is incremented only on confirmed delivery (RFC §3.5).
     * --emit-stdout is retained as a testing escape hatch only.
     * ----------------------------------------------------------- */
    {
        char *osc_buf;
        int   osc_len;

        osc_len = snprintf(NULL, 0, "\033]7777;%s;%s;%s;%s;%s;%s;%s\007",
                           sid_hex,
                           b64_counter ? b64_counter : "",
                           type_val    ? type_val    : "",
                           b64_context ? b64_context : "",
                           b64_nonce, b64_ct, b64_tag);
        if (osc_len <= 0)
            goto done;

        osc_buf = (char *)zalloc((size_t)osc_len + 1);
        if (!osc_buf)
            goto done;

        snprintf(osc_buf, (size_t)osc_len + 1,
                 "\033]7777;%s;%s;%s;%s;%s;%s;%s\007",
                 sid_hex,
                 b64_counter ? b64_counter : "",
                 type_val    ? type_val    : "",
                 b64_context ? b64_context : "",
                 b64_nonce, b64_ct, b64_tag);

        /* Write to /dev/tty so the terminal emulator sees the sequence.
         * With --emit-stdout (testing only) write to fd 1 instead.     */
        if (!emit_stdout) {
            int tty_fd = open("/dev/tty", O_WRONLY | O_NOCTTY);
            if (tty_fd >= 0) {
                write_all(tty_fd, osc_buf, (size_t)osc_len);
                fsync(tty_fd);
                close(tty_fd);
            }
        } else {
            write_all(STDOUT_FILENO, osc_buf, (size_t)osc_len);
            fsync(STDOUT_FILENO);
        }

        /* Relay to SDIAgent via the persistent socket (RFC §3.6).
         * Fail closed: any error or non-0x01 ack is treated as failure. */
        if (sdi_sockfd >= 0) {
            unsigned char op   = 0x02;
            uint32_t      slen = (uint32_t)osc_len;
            unsigned char lbuf[4];
            unsigned char ack  = 0;

            lbuf[0] = (unsigned char)( slen        & 0xFF);
            lbuf[1] = (unsigned char)((slen >>  8) & 0xFF);
            lbuf[2] = (unsigned char)((slen >> 16) & 0xFF);
            lbuf[3] = (unsigned char)((slen >> 24) & 0xFF);

            if (write_all(sdi_sockfd, &op,    1)                == 1  &&
                write_all(sdi_sockfd, lbuf,   4)                == 4  &&
                write_all(sdi_sockfd, osc_buf, (size_t)osc_len) == (ssize_t)osc_len &&
                read_all (sdi_sockfd, &ack,    1)                == 1  &&
                ack == 0x01) {
                /* Confirmed delivery — advance the counter (RFC §3.5). */
                sdi_session_counter++;
                ret = 0;
            } else {
                close(sdi_sockfd);
                sdi_sockfd = -1;
                zerrnam(nam, "SDIAgent did not confirm delivery");
            }
        } else if (emit_stdout) {
            /* Testing path: no socket required, just count success. */
            sdi_session_counter++;
            ret = 0;
        } else {
            zerrnam(nam, "no active SDIAgent socket (is the Desktop Agent running?)");
        }

        zsfree(osc_buf);
    }

done:
    /* Wipe sensitive intermediate values before releasing memory. */
    OPENSSL_cleanse(counter_bytes, sizeof(counter_bytes));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag,   sizeof(tag));

    if (ctx)
        EVP_CIPHER_CTX_free(ctx);

    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, cipher_alloc);
        zfree(ciphertext, (int)cipher_alloc);
    }
    if (plaintext) {
        OPENSSL_cleanse(plaintext, bufcap);
        zfree(plaintext, (int)bufcap);
    }

    if (b64_counter) zsfree(b64_counter);
    if (b64_nonce)   zsfree(b64_nonce);
    if (b64_ct)      zsfree(b64_ct);
    if (b64_tag)     zsfree(b64_tag);
    if (b64_context) zsfree(b64_context);

    return ret;
}

/* ------------------------------------------------------------------ */
/*  Module tables                                                       */
/* ------------------------------------------------------------------ */

static struct builtin bintab[] = {
    BUILTIN("bsh-inject", 0, bin_bsh_inject, 0, -1, 0, NULL, NULL),
};

static struct features module_features = {
    bintab, sizeof(bintab)/sizeof(*bintab),
    NULL, 0,
    NULL, 0,
    NULL, 0,
    0
};

/* ------------------------------------------------------------------ */
/*  Module lifecycle                                                    */
/* ------------------------------------------------------------------ */

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
    /*
     * Only attempt the handshake in interactive sessions where a TTY
     * is attached – the same condition under which the shell displays
     * a prompt.
     */
    if (interact)
        sdi_session_init();
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
    /* Notify SDIAgent of clean shutdown, then close the persistent socket. */
    if (sdi_sockfd >= 0) {
        unsigned char op = 0x03;  /* UNREGISTER */
        write(sdi_sockfd, &op, 1);  /* best-effort — ignore errors */
        close(sdi_sockfd);
        sdi_sockfd = -1;
    }
    /* Securely erase key material before the module is unloaded. */
    OPENSSL_cleanse(sdi_session_key, sizeof(sdi_session_key));
    OPENSSL_cleanse(sdi_session_id,  sizeof(sdi_session_id));
    sdi_session_active = 0;
    return 0;
}
