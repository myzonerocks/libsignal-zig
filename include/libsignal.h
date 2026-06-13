/**
 * libsignal-zig — Signal Protocol in Zig, with a C-compatible API.
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

/* ── Group messaging (Sender Key) ───────────────────────────────────────────── */

/**
 * Sender key store callbacks — keyed by (sender_name, device_id, distribution_id[16]).
 *
 * load: writes a malloc'd buffer to *out/*out_len. Returns -6 if not found.
 * store: data is valid only for the duration of the call; copy if needed.
 */
typedef struct {
    void *ud;
    int (*store)(void *ud, const char *name, uint32_t device_id,
                 const uint8_t distribution_id[16],
                 const uint8_t *data, size_t len);
    int (*load)(void *ud, const char *name, uint32_t device_id,
                const uint8_t distribution_id[16],
                uint8_t **out, size_t *out_len);
} libsignal_sender_key_store_t;

/**
 * Create (or retrieve existing) sender key session and return a serialized
 * SenderKeyDistributionMessage that must be sent to all group members.
 *
 * distribution_id: 16-byte group session UUID.
 * skdm_out / skdm_len_out: heap-allocated SKDM bytes; caller must free().
 */
int libsignal_group_create_session(
    const char *sender_name,
    uint32_t sender_device_id,
    const uint8_t distribution_id[16],
    libsignal_sender_key_store_t sk_store,
    uint8_t **skdm_out,
    size_t *skdm_len_out);

/**
 * Process a received SenderKeyDistributionMessage from a group member.
 * skdm_bytes: serialized SKDM previously obtained via libsignal_group_create_session.
 */
int libsignal_group_process_session(
    const char *sender_name,
    uint32_t sender_device_id,
    const uint8_t *skdm_bytes,
    size_t skdm_len,
    libsignal_sender_key_store_t sk_store);

/**
 * Encrypt a group message. Returns a serialized SenderKeyMessage.
 * ct_out / ct_len_out: heap-allocated ciphertext; caller must free().
 */
int libsignal_group_encrypt(
    const char *sender_name,
    uint32_t sender_device_id,
    const uint8_t distribution_id[16],
    const uint8_t *plaintext,
    size_t plaintext_len,
    libsignal_sender_key_store_t sk_store,
    uint8_t **ct_out,
    size_t *ct_len_out);

/**
 * Decrypt a group SenderKeyMessage. Returns the plaintext.
 * pt_out / pt_len_out: heap-allocated plaintext; caller must free().
 */
int libsignal_group_decrypt(
    const char *sender_name,
    uint32_t sender_device_id,
    const uint8_t distribution_id[16],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    libsignal_sender_key_store_t sk_store,
    uint8_t **pt_out,
    size_t *pt_len_out);

/* ── Sealed sender V1 ────────────────────────────────────────────────────────── */

/**
 * Build and serialize a ServerCertificate.
 *
 * key_id: server key identifier.
 * key_pub: 33-byte server signing public key.
 * trust_root_priv: 32-byte trust-root private key used to sign the certificate.
 * out / out_len: heap-allocated serialized certificate; caller must free().
 */
int libsignal_server_cert_serialize(
    uint32_t key_id,
    const uint8_t key_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t trust_root_priv[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
    uint8_t **out,
    size_t *out_len);

/**
 * Build and serialize a SenderCertificate.
 *
 * sender_uuid_z: null-terminated sender UUID string.
 * sender_e164_z: null-terminated E.164 phone string, or NULL if absent.
 * sender_device_id: sender's device ID.
 * sender_key_pub: 33-byte sender's EC public key.
 * expiration: Unix timestamp (seconds) when the certificate expires.
 * server_cert_bytes / server_cert_len: serialized ServerCertificate.
 * server_key_priv: 32-byte server signing private key.
 * out / out_len: heap-allocated serialized SenderCertificate; caller must free().
 */
int libsignal_sender_cert_serialize(
    const char *sender_uuid_z,
    const char *sender_e164_z,
    uint32_t sender_device_id,
    const uint8_t sender_key_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    uint64_t expiration,
    const uint8_t *server_cert_bytes,
    size_t server_cert_len,
    const uint8_t server_key_priv[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
    uint8_t **out,
    size_t *out_len);

/**
 * V1 sealed sender encrypt.
 *
 * recipient_pub: 33-byte recipient EC public key.
 * sender_cert_bytes / sender_cert_len: serialized SenderCertificate.
 * msg_type: content type byte (0 = plaintext, 1 = ciphertext, 2 = key_exchange, 3 = prekey_bundle).
 * content_hint: content hint byte (0 = default, 1 = resendable, 2 = implicit).
 * group_id_z: null-terminated group ID, or NULL.
 * plaintext / plaintext_len: message body.
 * out / out_len: heap-allocated sealed-sender envelope; caller must free().
 */
int libsignal_sealed_sender_encrypt(
    const uint8_t recipient_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t *sender_cert_bytes,
    size_t sender_cert_len,
    uint8_t msg_type,
    uint8_t content_hint,
    const char *group_id_z,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **out,
    size_t *out_len);

/**
 * V1 sealed sender decrypt.
 *
 * data / data_len: received sealed-sender envelope.
 * our_priv: 32-byte recipient private key.
 *
 * Outputs (all heap-allocated; caller must free non-null values):
 *   sender_uuid_out / sender_uuid_len_out: sender UUID string (not null-terminated).
 *   sender_e164_out / sender_e164_len_out: sender E.164 (NULL if absent).
 *   sender_device_id_out: sender device ID.
 *   content_type_out: content type byte.
 *   contents_out / contents_len_out: decrypted message body.
 */
int libsignal_sealed_sender_decrypt(
    const uint8_t *data,
    size_t data_len,
    const uint8_t our_priv[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
    uint8_t **sender_uuid_out,
    size_t *sender_uuid_len_out,
    uint8_t **sender_e164_out,
    size_t *sender_e164_len_out,
    uint32_t *sender_device_id_out,
    uint8_t *content_type_out,
    uint8_t **contents_out,
    size_t *contents_len_out);

/* ── Sealed sender V2 (multi-recipient AES-256-GCM-SIV) ────────────────────── */

/**
 * Per-recipient descriptor for V2 sealed sender.
 *
 * service_id_fixed: 17-byte fixed-width ServiceId (type_byte || uuid[16]).
 *   type_byte 0x00 = ACI, 0x02 = PNI.
 * device_id: recipient device number (1 byte, fits in uint8_t).
 * identity_pub: 33-byte recipient identity public key.
 */
typedef struct {
    uint8_t service_id_fixed[17];
    uint8_t device_id;
    uint8_t identity_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN];
} libsignal_sealed_sender_v2_recipient_t;

/**
 * V2 sealed sender encrypt (multi-recipient).
 *
 * message / message_len: cleartext to encrypt.
 * sender_priv: 32-byte sender ephemeral private key.
 * sender_pub: 33-byte matching public key.
 * recipients / recipient_count: array of per-recipient descriptors.
 * excluded_sids / excluded_count: array of 17-byte ServiceIds to mark as excluded, or NULL/0.
 * out / out_len: heap-allocated sent-message envelope; caller must free().
 */
int libsignal_sealed_sender_encrypt_v2(
    const uint8_t *message,
    size_t message_len,
    const uint8_t sender_priv[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
    const uint8_t sender_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const libsignal_sealed_sender_v2_recipient_t *recipients,
    size_t recipient_count,
    const uint8_t (*excluded_sids)[17],
    size_t excluded_count,
    uint8_t **out,
    size_t *out_len);

/**
 * V2 sealed sender server dispatch.
 *
 * Converts a multi-recipient "sent message" (0x23 format produced by
 * libsignal_sealed_sender_encrypt_v2) into a per-device "received message"
 * (0x22 format expected by libsignal_sealed_sender_decrypt_v2).
 *
 * This models the Signal server's per-recipient dispatch step. In production
 * the server performs this transformation before delivering to each device.
 *
 * sent / sent_len: the sent-message envelope (0x23 format).
 * service_id_fixed: 17-byte ServiceId identifying the target recipient.
 * device_id: target device number.
 * out / out_len: heap-allocated received-message envelope; caller must free().
 */
int libsignal_sealed_sender_v2_dispatch(
    const uint8_t *sent,
    size_t sent_len,
    const uint8_t service_id_fixed[17],
    uint8_t device_id,
    uint8_t **out,
    size_t *out_len);

/**
 * V2 sealed sender decrypt.
 *
 * received / received_len: per-device envelope (0x22 format) from
 *   libsignal_sealed_sender_v2_dispatch.
 * our_priv: 32-byte recipient private key.
 * our_pub: 33-byte matching public key.
 * sender_pub: 33-byte sender public key (used for ECDH in the per-recipient layer).
 * out / out_len: heap-allocated plaintext; caller must free().
 */
int libsignal_sealed_sender_decrypt_v2(
    const uint8_t *received,
    size_t received_len,
    const uint8_t our_priv[LIBSIGNAL_EC_PRIVATE_KEY_LEN],
    const uint8_t our_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t sender_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    uint8_t **out,
    size_t *out_len);

/* ── Fingerprint ─────────────────────────────────────────────────────────────── */

/**
 * Compute a displayable + scannable fingerprint for two identity keys.
 *
 * local_pub / remote_pub: 33-byte identity public keys.
 * local_stable_id / remote_stable_id: stable identifier bytes (phone number, UUID, etc.).
 * displayable_out: caller-provided [60]uint8 buffer filled with a 60-digit decimal string.
 * scannable_out / scannable_len_out: heap-allocated serialized ScannableFingerprint; caller must free().
 */
int libsignal_fingerprint_compute(
    const uint8_t local_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t *local_stable_id,
    size_t local_stable_id_len,
    const uint8_t remote_pub[LIBSIGNAL_EC_PUBLIC_KEY_LEN],
    const uint8_t *remote_stable_id,
    size_t remote_stable_id_len,
    uint8_t displayable_out[60],
    uint8_t **scannable_out,
    size_t *scannable_len_out);

/**
 * Compare two serialized ScannableFingerprints for equality.
 * match_out: set to 1 if they match, 0 otherwise.
 */
int libsignal_fingerprint_compare(
    const uint8_t *local_scannable,
    size_t local_len,
    const uint8_t *their_scannable,
    size_t their_len,
    int *match_out);

/* ── Username ─────────────────────────────────────────────────────────────────── */

/**
 * Compute the 32-byte username hash for a username string (e.g. "alice.42").
 * hash_out: caller-provided [32]uint8 buffer.
 */
int libsignal_username_hash(
    const char *username_z,
    uint8_t hash_out[32]);

/**
 * Generate a 128-byte zero-knowledge proof that the caller knows the username
 * whose hash was produced by libsignal_username_hash.
 *
 * username_z: null-terminated username string.
 * randomness: 32 bytes of caller-supplied entropy (use a CSPRNG).
 * proof_out: caller-provided [128]uint8 buffer.
 */
int libsignal_username_proof(
    const char *username_z,
    const uint8_t randomness[32],
    uint8_t proof_out[128]);

/**
 * Verify a 128-byte ZK proof against a previously computed username hash.
 * valid_out: set to 1 if valid, 0 otherwise.
 */
int libsignal_username_verify(
    const uint8_t username_hash[32],
    const uint8_t proof[128],
    int *valid_out);

/* ── Account keys ─────────────────────────────────────────────────────────────── */

/**
 * Generate a fresh 64-character AccountEntropyPool.
 * pool_out: caller-provided [64]uint8 buffer filled with ASCII base-32 characters.
 */
void libsignal_account_entropy_pool_generate(uint8_t pool_out[64]);

/**
 * Validate a 64-character AccountEntropyPool string.
 * Returns 0 if valid, -3 if the format is invalid.
 */
int libsignal_account_entropy_pool_parse(const uint8_t pool_str[64]);

/**
 * Derive the 32-byte SVR (Secure Value Recovery) master key from an entropy pool.
 * pool_str: 64-byte ASCII entropy pool string.
 * key_out: caller-provided [32]uint8 output buffer.
 */
int libsignal_account_entropy_derive_svr_key(
    const uint8_t pool_str[64],
    uint8_t key_out[32]);

/**
 * Derive the 32-byte backup key from an entropy pool.
 * pool_str: 64-byte ASCII entropy pool string.
 * key_out: caller-provided [32]uint8 output buffer.
 */
int libsignal_account_entropy_derive_backup_key(
    const uint8_t pool_str[64],
    uint8_t key_out[32]);

/**
 * Derive the 32-byte media encryption key from a backup key.
 * backup_key: 32-byte backup key (e.g. from libsignal_account_entropy_derive_backup_key).
 * key_out: caller-provided [32]uint8 output buffer.
 */
void libsignal_backup_key_derive_media_key(
    const uint8_t backup_key[32],
    uint8_t key_out[32]);

#ifdef __cplusplus
}
#endif
#endif /* LIBSIGNAL_H */
