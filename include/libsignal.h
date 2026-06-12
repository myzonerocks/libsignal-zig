/**
 * libsignal-zig — Signal Protocol in pure Zig, with a C-compatible API.
 *
 * Memory contract
 * ---------------
 * Any pointer written to an *_out parameter is heap-allocated with malloc.
 * The caller is responsible for freeing it with free(). The library never
 * retains these pointers after returning.
 *
 * Error codes
 * -----------
 *  0   LIBSIGNAL_OK
 * -1   LIBSIGNAL_ERR_INVALID_KEY
 * -2   LIBSIGNAL_ERR_INVALID_SIGNATURE
 * -3   LIBSIGNAL_ERR_INVALID_MESSAGE
 * -4   LIBSIGNAL_ERR_UNTRUSTED_IDENTITY
 * -5   LIBSIGNAL_ERR_DUPLICATE_MESSAGE
 * -6   LIBSIGNAL_ERR_NOT_FOUND
 * -7   LIBSIGNAL_ERR_INTERNAL
 */
#ifndef LIBSIGNAL_H
#define LIBSIGNAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ──────────────────────────────────────────────────────────────── */

#define LIBSIGNAL_OK                    0
#define LIBSIGNAL_ERR_INVALID_KEY      -1
#define LIBSIGNAL_ERR_INVALID_SIGNATURE -2
#define LIBSIGNAL_ERR_INVALID_MESSAGE  -3
#define LIBSIGNAL_ERR_UNTRUSTED        -4
#define LIBSIGNAL_ERR_DUPLICATE        -5
#define LIBSIGNAL_ERR_NOT_FOUND        -6
#define LIBSIGNAL_ERR_INTERNAL         -7

/* Message types returned by libsignal_encrypt */
#define LIBSIGNAL_MSG_WHISPER   2   /* regular Double Ratchet message */
#define LIBSIGNAL_MSG_PREKEY    3   /* session-initiating PreKeySignalMessage */

/* Key sizes */
#define LIBSIGNAL_EC_PUBLIC_KEY_LEN     33  /* 0x05 || 32-byte X25519 */
#define LIBSIGNAL_EC_PRIVATE_KEY_LEN    32
#define LIBSIGNAL_SIGNATURE_LEN         64

/* ML-KEM-1024 (Kyber) sizes */
#define LIBSIGNAL_KYBER1024_PK_LEN    1568
#define LIBSIGNAL_KYBER1024_SK_LEN    3168
#define LIBSIGNAL_KYBER1024_CT_LEN    1568
#define LIBSIGNAL_KYBER1024_SS_LEN      32

/* ── Low-level EC operations ────────────────────────────────────────────────── */

/**
 * Generate an X25519 key pair.
 * pub_out receives the 33-byte serialized public key (0x05 prefix).
 * priv_out receives the 32-byte private key (pre-clamped).
 */
int libsignal_ec_keypair_generate(
    uint8_t pub_out[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    uint8_t priv_out[LIBSIGNAL_EC_PRIVATE_KEY_LEN]);

/**
 * Perform X25519 Diffie-Hellman.
 * their_pub: 33-byte serialized public key. shared_out: 32-byte shared secret.
 */
int libsignal_ec_dh(
    const uint8_t their_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t our_priv[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
    uint8_t shared_out[LIBSIGNAL_EC_PRIVATE_KEY_LEN]);

/**
 * Sign msg (msg_len bytes) with XEdDSA using the given X25519 private key.
 * sig_out receives the 64-byte signature.
 */
int libsignal_xeddsa_sign(
    const uint8_t priv[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
    const uint8_t *msg, size_t msg_len,
    uint8_t sig_out[LIBSIGNAL_SIGNATURE_LEN]);

/**
 * Verify an XEdDSA signature. Returns 0 if valid, -2 if invalid.
 */
int libsignal_xeddsa_verify(
    const uint8_t pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[LIBSIGNAL_SIGNATURE_LEN]);

/* ── ML-KEM-1024 (post-quantum key encapsulation) ───────────────────────────── */

/** Generate an ML-KEM-1024 key pair. */
int libsignal_kyber1024_keypair_generate(
    uint8_t pub_out[LIBSIGNAL_KYBER1024_PK_LEN],
    uint8_t sec_out[LIBSIGNAL_KYBER1024_SK_LEN]);

/**
 * Encapsulate: generate a shared secret and the ciphertext to send to the
 * key holder. ct_out and ss_out are caller-provided output buffers.
 */
int libsignal_kyber1024_encaps(
    const uint8_t pub[LIBSIGNAL_KYBER1024_PK_LEN],
    uint8_t ct_out[LIBSIGNAL_KYBER1024_CT_LEN],
    uint8_t ss_out[LIBSIGNAL_KYBER1024_SS_LEN]);

/** Decapsulate: recover the shared secret from a received ciphertext. */
int libsignal_kyber1024_decaps(
    const uint8_t sec[LIBSIGNAL_KYBER1024_SK_LEN],
    const uint8_t ct[LIBSIGNAL_KYBER1024_CT_LEN],
    uint8_t ss_out[LIBSIGNAL_KYBER1024_SS_LEN]);

/* ── Session protocol ───────────────────────────────────────────────────────── */

/**
 * Store callbacks.
 *
 * ud is the userdata pointer passed through unchanged.
 *
 * Session store load: on success writes a malloc'd buffer to *out/*out_len.
 *   Returns 0 on success, -6 if the session does not exist, other negative on
 *   error. The library frees *out with free() after use.
 *
 * Session store store: the data pointer is valid only for the duration of the
 *   call; copy it if you need to retain it.
 */
typedef struct {
    void *ud;
    int (*load)(void *ud, const char *name, uint32_t device_id,
                uint8_t **out, size_t *out_len);
    int (*store)(void *ud, const char *name, uint32_t device_id,
                 const uint8_t *data, size_t len);
} libsignal_session_store_t;

/**
 * Identity store callbacks.
 *
 * get_keypair: write the 33-byte public key and 32-byte private key to the
 *   provided buffers. Returns 0 on success.
 *
 * is_trusted: return 1 if the identity should be trusted, 0 if not.
 *   direction: 0 = sending, 1 = receiving.
 */
typedef struct {
    void *ud;
    int (*get_keypair)(void *ud,
                       uint8_t pub_out[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
                       uint8_t priv_out[LIBSIGNAL_EC_PRIVATE_KEY_LEN]);
    int (*get_registration_id)(void *ud, uint32_t *out);
    int (*save_identity)(void *ud, const char *name, uint32_t device_id,
                         const uint8_t pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN]);
    int (*is_trusted)(void *ud, const char *name, uint32_t device_id,
                      const uint8_t pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
                      int direction);
} libsignal_identity_store_t;

/**
 * Pre-key store callbacks.
 * load: write the key pair to the provided buffers. Return -6 if not found.
 * remove: called after a one-time pre-key is consumed.
 */
typedef struct {
    void *ud;
    int (*load)(void *ud, uint32_t id,
                uint8_t pub_out[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
                uint8_t priv_out[LIBSIGNAL_EC_PRIVATE_KEY_LEN]);
    int (*remove)(void *ud, uint32_t id);
} libsignal_pre_key_store_t;

/** Signed pre-key store callbacks. */
typedef struct {
    void *ud;
    int (*load)(void *ud, uint32_t id,
                uint8_t pub_out[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
                uint8_t priv_out[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
                uint8_t sig_out[LIBSIGNAL_SIGNATURE_LEN],
                uint64_t *timestamp_out);
} libsignal_signed_pre_key_store_t;

/** Kyber pre-key store callbacks. Pass NULL to libsignal_ctx_new to use X3DH only. */
typedef struct {
    void *ud;
    int (*load)(void *ud, uint32_t id,
                uint8_t pub_out[LIBSIGNAL_KYBER1024_PK_LEN],
                uint8_t sec_out[LIBSIGNAL_KYBER1024_SK_LEN],
                uint8_t sig_out[LIBSIGNAL_SIGNATURE_LEN]);
    int (*mark_used)(void *ud, uint32_t id);
} libsignal_kyber_pre_key_store_t;

/**
 * Opaque session context. One context per (local identity, remote peer) pair.
 * Thread safety: a context must not be used concurrently from multiple threads.
 */
typedef struct libsignal_ctx libsignal_ctx_t;

/**
 * Create a session context.
 *
 * remote_name: null-terminated peer identifier.
 * remote_device_id: peer device number.
 * kyber_store: pass NULL for X3DH-only (no post-quantum ratchet).
 *
 * Returns NULL on allocation failure.
 */
libsignal_ctx_t *libsignal_ctx_new(
    const char *remote_name,
    uint32_t remote_device_id,
    libsignal_session_store_t session_store,
    libsignal_identity_store_t identity_store,
    libsignal_pre_key_store_t pre_key_store,
    libsignal_signed_pre_key_store_t signed_pre_key_store,
    const libsignal_kyber_pre_key_store_t *kyber_store);

/** Free a session context. Safe to call with NULL. */
void libsignal_ctx_free(libsignal_ctx_t *ctx);

/**
 * Process a peer's pre-key bundle to establish a session.
 *
 * pre_key_id / pre_key_pub: pass 0 / NULL if the bundle has no one-time pre-key.
 * kyber_pre_key_id / kyber_pub / kyber_sig: pass 0 / NULL / NULL for X3DH only.
 */
int libsignal_process_prekey_bundle(
    libsignal_ctx_t *ctx,
    uint32_t registration_id,
    uint32_t pre_key_id,
    const uint8_t *pre_key_pub,
    uint32_t signed_pre_key_id,
    const uint8_t signed_pre_key_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t signed_pre_key_sig[LIBSIGNAL_SIGNATURE_LEN],
    const uint8_t identity_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    uint32_t kyber_pre_key_id,
    const uint8_t *kyber_pub,
    const uint8_t *kyber_sig);

/**
 * Encrypt plaintext.
 *
 * On success: *ct_out points to a malloc'd buffer of *ct_len_out bytes.
 * *msg_type_out is set to LIBSIGNAL_MSG_PREKEY (3) for the session-initiating
 * message and LIBSIGNAL_MSG_WHISPER (2) for subsequent messages.
 * The caller must free(*ct_out).
 */
int libsignal_encrypt(
    libsignal_ctx_t *ctx,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t **ct_out, size_t *ct_len_out,
    int *msg_type_out);

/**
 * Decrypt a session-initiating PreKeySignalMessage (msg_type == LIBSIGNAL_MSG_PREKEY).
 * On success: *pt_out points to a malloc'd buffer of *pt_len_out bytes.
 * The caller must free(*pt_out).
 */
int libsignal_decrypt_prekey(
    libsignal_ctx_t *ctx,
    const uint8_t *ct, size_t ct_len,
    uint8_t **pt_out, size_t *pt_len_out);

/**
 * Decrypt a regular SignalMessage (msg_type == LIBSIGNAL_MSG_WHISPER).
 * On success: *pt_out points to a malloc'd buffer of *pt_len_out bytes.
 * The caller must free(*pt_out).
 */
int libsignal_decrypt(
    libsignal_ctx_t *ctx,
    const uint8_t *ct, size_t ct_len,
    uint8_t **pt_out, size_t *pt_len_out);

#ifdef __cplusplus
}
#endif
#endif /* LIBSIGNAL_H */
