/**
 * signal_ffi.h — C API for libsignal-zig
 *
 * ── Error convention ─────────────────────────────────────────────────────────
 *
 * Every signal_ function returns NULL on success, or a caller-owned
 * *SignalFfiError on failure. The caller must free errors with
 * signal_error_free(). Inspect them with signal_error_get_type() to get a
 * SignalErrorCode and signal_error_get_message() to get a human-readable
 * description.
 *
 * ── Memory contract ──────────────────────────────────────────────────────────
 *
 * SignalOwnedBuffer: the library allocated `base`; caller must free with
 *   signal_free_buffer(buf.base, buf.length) when done.
 *
 * C strings written to char ** or const char ** outputs: free with
 *   signal_free_string(). Do not use free() directly.
 *
 * Opaque objects (SignalPrivateKey, SignalSessionRecord, …): created by the
 *   library and owned by the caller. Each type has a matching _destroy()
 *   function. Destroy once and do not use after.
 *
 * SignalBorrowedBuffer / SignalBorrowedMutableBuffer: the caller owns the
 *   backing memory. The library does not retain a reference after the call
 *   returns.
 *
 * ── Pointer wrapper types ────────────────────────────────────────────────────
 *
 * Signal{Mut,Const}Pointer<T> are single-field structs wrapping a T pointer.
 * They are passed and returned by value. Callers set .raw to the object
 * pointer; the library writes .raw on output parameters.
 *
 *   SignalMutPointerSignalPrivateKey out = {NULL};
 *   SignalFfiError *e = signal_privatekey_generate(&out);
 *   // out.raw is now a heap-allocated SignalPrivateKey
 *   signal_privatekey_destroy(out);
 */

#pragma once
#ifndef SIGNAL_FFI_H
#define SIGNAL_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ── Opaque types ──────────────────────────────────────────────────────────────

typedef struct SignalFfiError         SignalFfiError;
typedef struct SignalPrivateKey       SignalPrivateKey;
typedef struct SignalPublicKey        SignalPublicKey;
typedef struct SignalKyberKeyPair     SignalKyberKeyPair;
typedef struct SignalKyberPublicKey   SignalKyberPublicKey;
typedef struct SignalKyberSecretKey   SignalKyberSecretKey;
typedef struct SignalKyberPreKeyRecord  SignalKyberPreKeyRecord;
typedef struct SignalProtocolAddress  SignalProtocolAddress;
typedef struct SignalPreKeyRecord     SignalPreKeyRecord;
typedef struct SignalSignedPreKeyRecord SignalSignedPreKeyRecord;
typedef struct SignalSenderKeyRecord  SignalSenderKeyRecord;
typedef struct SignalSessionRecord    SignalSessionRecord;
typedef struct SignalMessage           SignalMessage;
typedef struct SignalPreKeySignalMessage SignalPreKeySignalMessage;
typedef struct SignalSenderKeyMessage  SignalSenderKeyMessage;
typedef struct SignalSenderKeyDistributionMessage SignalSenderKeyDistributionMessage;
typedef struct SignalPlaintextContent  SignalPlaintextContent;
typedef struct SignalDecryptionErrorMessage SignalDecryptionErrorMessage;
typedef struct SignalCiphertextMessage SignalCiphertextMessage;
typedef struct SignalPreKeyBundle      SignalPreKeyBundle;
typedef struct SignalServerCertificate SignalServerCertificate;
typedef struct SignalSenderCertificate SignalSenderCertificate;
typedef struct SignalUnidentifiedSenderMessageContent SignalUnidentifiedSenderMessageContent;
typedef struct SignalAes256Ctr32       SignalAes256Ctr32;
typedef struct SignalAes256GcmEncryption SignalAes256GcmEncryption;
typedef struct SignalAes256GcmDecryption SignalAes256GcmDecryption;
typedef struct SignalAes256GcmSiv      SignalAes256GcmSiv;
typedef struct SignalIncrementalMac    SignalIncrementalMac;
typedef struct SignalValidatingMac     SignalValidatingMac;
typedef struct SignalFingerprint       SignalFingerprint;
typedef struct SignalAccountEntropyPool SignalAccountEntropyPool;
typedef struct SignalBackupKey         SignalBackupKey;
typedef struct SignalPinHash           SignalPinHash;
typedef struct SignalServerSecretParams SignalServerSecretParams;
typedef struct SignalServerPublicParams SignalServerPublicParams;
typedef struct SignalMessageBackupValidationOutcome SignalMessageBackupValidationOutcome;
typedef struct SignalOnlineBackupValidator SignalOnlineBackupValidator;
typedef struct SignalTokioAsyncContext SignalTokioAsyncContext;
typedef struct SignalConnectionManager SignalConnectionManager;
typedef struct SignalSgxClientState    SignalSgxClientState;
typedef struct SignalRegistrationService SignalRegistrationService;

// ── Buffer types ──────────────────────────────────────────────────────────────

/** Caller-owned buffer; free with signal_free_buffer(). */
typedef struct {
    uint8_t *base;
    size_t   length;
} SignalOwnedBuffer;

/** Borrowed read-only view; caller retains ownership. */
typedef struct {
    const uint8_t *base;
    size_t         length;
} SignalBorrowedBuffer;

/** Borrowed mutable view; caller retains ownership. */
typedef struct {
    uint8_t *base;
    size_t   length;
} SignalBorrowedMutableBuffer;

/** Array of byte strings (borrowed). */
typedef struct {
    const uint8_t *bytes;
    const size_t  *lengths;
    size_t         count;
} SignalBytestringArray;

// ── Pointer wrapper types ─────────────────────────────────────────────────────

#define SIGNAL_DECLARE_POINTER(T) \
    typedef struct { T *raw; }        SignalMutPointer##T; \
    typedef struct { const T *raw; }  SignalConstPointer##T

SIGNAL_DECLARE_POINTER(SignalPrivateKey);
SIGNAL_DECLARE_POINTER(SignalPublicKey);
SIGNAL_DECLARE_POINTER(SignalKyberKeyPair);
SIGNAL_DECLARE_POINTER(SignalKyberPublicKey);
SIGNAL_DECLARE_POINTER(SignalKyberSecretKey);
SIGNAL_DECLARE_POINTER(SignalKyberPreKeyRecord);
SIGNAL_DECLARE_POINTER(SignalProtocolAddress);
SIGNAL_DECLARE_POINTER(SignalPreKeyRecord);
SIGNAL_DECLARE_POINTER(SignalSignedPreKeyRecord);
SIGNAL_DECLARE_POINTER(SignalSenderKeyRecord);
SIGNAL_DECLARE_POINTER(SignalSessionRecord);
SIGNAL_DECLARE_POINTER(SignalMessage);
SIGNAL_DECLARE_POINTER(SignalPreKeySignalMessage);
SIGNAL_DECLARE_POINTER(SignalSenderKeyMessage);
SIGNAL_DECLARE_POINTER(SignalSenderKeyDistributionMessage);
SIGNAL_DECLARE_POINTER(SignalPlaintextContent);
SIGNAL_DECLARE_POINTER(SignalDecryptionErrorMessage);
SIGNAL_DECLARE_POINTER(SignalCiphertextMessage);
SIGNAL_DECLARE_POINTER(SignalPreKeyBundle);
SIGNAL_DECLARE_POINTER(SignalServerCertificate);
SIGNAL_DECLARE_POINTER(SignalSenderCertificate);
SIGNAL_DECLARE_POINTER(SignalUnidentifiedSenderMessageContent);
SIGNAL_DECLARE_POINTER(SignalAes256Ctr32);
SIGNAL_DECLARE_POINTER(SignalAes256GcmEncryption);
SIGNAL_DECLARE_POINTER(SignalAes256GcmDecryption);
SIGNAL_DECLARE_POINTER(SignalAes256GcmSiv);
SIGNAL_DECLARE_POINTER(SignalIncrementalMac);
SIGNAL_DECLARE_POINTER(SignalValidatingMac);
SIGNAL_DECLARE_POINTER(SignalFingerprint);
SIGNAL_DECLARE_POINTER(SignalAccountEntropyPool);
SIGNAL_DECLARE_POINTER(SignalBackupKey);
SIGNAL_DECLARE_POINTER(SignalPinHash);
SIGNAL_DECLARE_POINTER(SignalServerSecretParams);
SIGNAL_DECLARE_POINTER(SignalServerPublicParams);
SIGNAL_DECLARE_POINTER(SignalMessageBackupValidationOutcome);
SIGNAL_DECLARE_POINTER(SignalOnlineBackupValidator);
SIGNAL_DECLARE_POINTER(SignalTokioAsyncContext);
SIGNAL_DECLARE_POINTER(SignalConnectionManager);
SIGNAL_DECLARE_POINTER(SignalSgxClientState);
SIGNAL_DECLARE_POINTER(SignalRegistrationService);

// ── Store callback structs ────────────────────────────────────────────────────

typedef struct {
    void *ctx;
    SignalFfiError *(*load_session)(SignalMutPointerSignalSessionRecord *out, const SignalProtocolAddress *addr, void *ctx);
    SignalFfiError *(*store_session)(const SignalProtocolAddress *addr, SignalConstPointerSignalSessionRecord record, void *ctx);
    void (*destroy)(void *ctx);
} SignalSessionStore;

typedef struct {
    void *ctx;
    SignalFfiError *(*get_identity_key_pair)(SignalMutPointerSignalPublicKey *out_pub, SignalMutPointerSignalPrivateKey *out_priv, void *ctx);
    SignalFfiError *(*get_local_registration_id)(uint32_t *out, void *ctx);
    SignalFfiError *(*save_identity)(const SignalProtocolAddress *addr, SignalConstPointerSignalPublicKey key, void *ctx);
    SignalFfiError *(*is_trusted_identity)(bool *out, const SignalProtocolAddress *addr, SignalConstPointerSignalPublicKey key, uint32_t direction, void *ctx);
    SignalFfiError *(*get_identity)(SignalMutPointerSignalPublicKey *out, const SignalProtocolAddress *addr, void *ctx);
    void (*destroy)(void *ctx);
} SignalIdentityKeyStore;

typedef struct {
    void *ctx;
    SignalFfiError *(*load_pre_key)(SignalMutPointerSignalPreKeyRecord *out, uint32_t id, void *ctx);
    SignalFfiError *(*store_pre_key)(uint32_t id, SignalMutPointerSignalPreKeyRecord record, void *ctx);
    SignalFfiError *(*remove_pre_key)(uint32_t id, void *ctx);
    void (*destroy)(void *ctx);
} SignalPreKeyStore;

typedef struct {
    void *ctx;
    SignalFfiError *(*load_signed_pre_key)(SignalMutPointerSignalSignedPreKeyRecord *out, uint32_t id, void *ctx);
    SignalFfiError *(*store_signed_pre_key)(uint32_t id, SignalMutPointerSignalSignedPreKeyRecord record, void *ctx);
    void (*destroy)(void *ctx);
} SignalSignedPreKeyStore;

typedef struct {
    void *ctx;
    SignalFfiError *(*load_kyber_pre_key)(SignalMutPointerSignalKyberPreKeyRecord *out, uint32_t id, void *ctx);
    SignalFfiError *(*store_kyber_pre_key)(uint32_t id, SignalMutPointerSignalKyberPreKeyRecord record, void *ctx);
    SignalFfiError *(*mark_kyber_pre_key_used)(uint32_t id, void *ctx);
    void (*destroy)(void *ctx);
} SignalKyberPreKeyStore;

typedef struct {
    void *ctx;
    SignalFfiError *(*store_sender_key)(const SignalProtocolAddress *sender, const uint8_t distribution_id[16], SignalConstPointerSignalSenderKeyRecord record, void *ctx);
    SignalFfiError *(*load_sender_key)(SignalMutPointerSignalSenderKeyRecord *out, const SignalProtocolAddress *sender, const uint8_t distribution_id[16], void *ctx);
    void (*destroy)(void *ctx);
} SignalSenderKeyStore;

/** Per-recipient info for SSv2 multi-recipient encryption. */
typedef struct {
    uint8_t                    service_id_fixed_width[17];
    uint8_t                    device_id;
    const SignalPublicKey     *identity_key_ptr;
} SignalSealedSenderV2Recipient;

// ── Error codes ───────────────────────────────────────────────────────────────

typedef enum {
    SIGNAL_ERROR_CODE_UNKNOWN_ERROR             = 1,
    SIGNAL_ERROR_CODE_INVALID_STATE             = 2,
    SIGNAL_ERROR_CODE_INTERNAL_ERROR            = 3,
    SIGNAL_ERROR_CODE_NULL_PARAMETER            = 4,
    SIGNAL_ERROR_CODE_INVALID_ARGUMENT          = 5,
    SIGNAL_ERROR_CODE_INVALID_TYPE              = 6,
    SIGNAL_ERROR_CODE_INVALID_UTF8_STRING       = 7,
    SIGNAL_ERROR_CODE_PROTOCOL_ERROR            = 10,
    SIGNAL_ERROR_CODE_LEGACY_CIPHERTEXT_VERSION = 11,
    SIGNAL_ERROR_CODE_UNKNOWN_CIPHERTEXT_VERSION = 12,
    SIGNAL_ERROR_CODE_UNRECOGNIZED_MESSAGE_VERSION = 13,
    SIGNAL_ERROR_CODE_INVALID_MESSAGE           = 14,
    SIGNAL_ERROR_CODE_INVALID_PADDING           = 15,
    SIGNAL_ERROR_CODE_FINGERPRINT_VERSION_MISMATCH = 20,
    SIGNAL_ERROR_CODE_FINGERPRINT_PARSING_ERROR = 21,
    SIGNAL_ERROR_CODE_SESSION_NOT_FOUND         = 40,
    SIGNAL_ERROR_CODE_INVALID_SESSION           = 41,
    SIGNAL_ERROR_CODE_INVALID_REGISTRATION_ID   = 42,
    SIGNAL_ERROR_CODE_INVALID_KEY_IDENTIFIER    = 50,
    SIGNAL_ERROR_CODE_INVALID_KEY               = 51,
    SIGNAL_ERROR_CODE_INVALID_SIGNATURE         = 52,
    SIGNAL_ERROR_CODE_INVALID_MAC               = 53,
    SIGNAL_ERROR_CODE_UNTRUSTED_IDENTITY        = 60,
    SIGNAL_ERROR_CODE_DUPLICATED_MESSAGE        = 70,
    SIGNAL_ERROR_CODE_VERIFICATION_FAILED       = 80,
    SIGNAL_ERROR_CODE_UNRECOGNIZED_ADDRESS      = 90,
    SIGNAL_ERROR_CODE_NETWORK_ERROR             = 100,
    SIGNAL_ERROR_CODE_NETWORK_PROTOCOL_ERROR    = 101,
    SIGNAL_ERROR_CODE_REQUEST_FAILED            = 102,
    SIGNAL_ERROR_CODE_REQUEST_TIMED_OUT         = 103,
    SIGNAL_ERROR_CODE_CONNECTION_TIMEOUT        = 104,
    SIGNAL_ERROR_CODE_SERVER_REJECTED           = 110,
    SIGNAL_ERROR_CODE_UNAUTHORIZED              = 111,
    SIGNAL_ERROR_CODE_RATE_LIMITED_ERROR        = 120,
    SIGNAL_ERROR_CODE_CDSI_RESOURCE_EXHAUSTED   = 130,
    SIGNAL_ERROR_CODE_REGISTRATION_LOCK         = 140,
    SIGNAL_ERROR_CODE_RATE_LIMIT_CHALLENGE      = 150,
    SIGNAL_ERROR_CODE_REGISTRATION_ERROR_NOT_DELIVERABLE = 160,
    SIGNAL_ERROR_CODE_MISMATCHED_DEVICES_ERROR  = 170,
} SignalErrorCode;

// ── Error inspection and memory deallocation ──────────────────────────────────
//
// Call signal_error_get_type() and signal_error_get_message() to inspect an
// error, then signal_error_free() to release it. Never pass a SignalFfiError *
// to free() directly.

void signal_error_free(SignalFfiError *e);
SignalFfiError *signal_error_get_type(uint32_t *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_message(const char **out, const SignalFfiError *e);
SignalFfiError *signal_error_get_address(SignalOwnedBuffer *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_uuid(SignalOwnedBuffer *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_retry_after_seconds(uint32_t *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_tries_remaining(uint32_t *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_our_fingerprint_version(uint32_t *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_their_fingerprint_version(uint32_t *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_invalid_protocol_address(SignalOwnedBuffer *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_unknown_fields(SignalOwnedBuffer *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_registration_lock(SignalOwnedBuffer *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_rate_limit_challenge(SignalOwnedBuffer *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_registration_error_not_deliverable(SignalOwnedBuffer *out, const SignalFfiError *e);
SignalFfiError *signal_error_get_mismatched_device_errors(SignalOwnedBuffer *out, const SignalFfiError *e);

void signal_free_buffer(uint8_t *buf, size_t len);
void signal_free_string(char *s);
void signal_free_list_of_strings(char **strs, size_t len);
void signal_bytestring_array_free(SignalBytestringArray arr);

typedef void (*SignalFfiLoggerCallback)(uint32_t level, const char *file, uint32_t line, const char *message, void *ctx);
SignalFfiError *signal_init_logger(uint32_t max_level, SignalFfiLoggerCallback callback, void *ctx);
SignalFfiError *signal_print_ptr(char **out, const void *ptr);
SignalFfiError *signal_hex_encode(char **out, SignalBorrowedBuffer bytes);

// ── Elliptic curve keys (X25519 / XEdDSA) ────────────────────────────────────
//
// SignalPrivateKey: 32-byte X25519 scalar.
// SignalPublicKey:  33-byte (0x05 prefix || 32-byte compressed X-coordinate).
//
// Key agreement: signal_privatekey_agree() → 32-byte shared secret (raw ECDH).
// Signing:       signal_privatekey_sign() → 64-byte XEdDSA signature.
// Verification:  signal_publickey_verify() → bool.
//
// IdentityKeyPair helpers serialize/deserialize a (pub, priv) pair together
// and provide cross-identity signing for alternate identity attestation.

SignalFfiError *signal_privatekey_generate(SignalMutPointerSignalPrivateKey *out);
SignalFfiError *signal_privatekey_clone(SignalMutPointerSignalPrivateKey *out, SignalConstPointerSignalPrivateKey key);
SignalFfiError *signal_privatekey_destroy(SignalMutPointerSignalPrivateKey p);
SignalFfiError *signal_privatekey_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalPrivateKey key);
SignalFfiError *signal_privatekey_deserialize(SignalMutPointerSignalPrivateKey *out, SignalBorrowedBuffer data);
SignalFfiError *signal_privatekey_agree(SignalOwnedBuffer *out, SignalConstPointerSignalPrivateKey key, SignalConstPointerSignalPublicKey their_key);
SignalFfiError *signal_privatekey_sign(SignalOwnedBuffer *out, SignalConstPointerSignalPrivateKey key, SignalBorrowedBuffer message);
SignalFfiError *signal_privatekey_get_public_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPrivateKey key);
SignalFfiError *signal_privatekey_hpke_open(SignalOwnedBuffer *out, SignalConstPointerSignalPrivateKey key, SignalBorrowedBuffer ciphertext, SignalBorrowedBuffer aad);

SignalFfiError *signal_publickey_clone(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPublicKey key);
SignalFfiError *signal_publickey_destroy(SignalMutPointerSignalPublicKey p);
SignalFfiError *signal_publickey_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalPublicKey key);
SignalFfiError *signal_publickey_deserialize(SignalMutPointerSignalPublicKey *out, SignalBorrowedBuffer data);
SignalFfiError *signal_publickey_equals(bool *out, SignalConstPointerSignalPublicKey a, SignalConstPointerSignalPublicKey b);
SignalFfiError *signal_publickey_verify(bool *out, SignalConstPointerSignalPublicKey key, SignalBorrowedBuffer message, SignalBorrowedBuffer signature);
SignalFfiError *signal_publickey_get_public_key_bytes(SignalOwnedBuffer *out, SignalConstPointerSignalPublicKey key);
SignalFfiError *signal_publickey_hpke_seal(SignalOwnedBuffer *out, SignalConstPointerSignalPublicKey key, SignalBorrowedBuffer plaintext, SignalBorrowedBuffer aad);

SignalFfiError *signal_identitykeypair_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalPublicKey public_key, SignalConstPointerSignalPrivateKey private_key);
SignalFfiError *signal_identitykeypair_deserialize(SignalMutPointerSignalPrivateKey *out_private, SignalMutPointerSignalPublicKey *out_public, SignalBorrowedBuffer data);
SignalFfiError *signal_identitykeypair_sign_alternate_identity(SignalOwnedBuffer *out, SignalConstPointerSignalPublicKey public_key, SignalConstPointerSignalPrivateKey private_key, SignalConstPointerSignalPublicKey other_identity);
SignalFfiError *signal_identitykey_verify_alternate_identity(bool *out, SignalConstPointerSignalPublicKey public_key, SignalConstPointerSignalPublicKey other_identity, SignalBorrowedBuffer signature);

// ── Post-quantum keys (ML-KEM-1024 / Kyber) ──────────────────────────────────
//
// SignalKyberKeyPair:       1568-byte public key + 3168-byte secret key.
// SignalKyberPublicKey:     1568 bytes (used in key encapsulation by the initiator).
// SignalKyberSecretKey:     3168 bytes (used for decapsulation by the responder).
// SignalKyberPreKeyRecord:  wraps a key pair with id, timestamp, and identity
//                           signature; used in PQXDH pre-key bundles.

SignalFfiError *signal_kyber_key_pair_generate(SignalMutPointerSignalKyberKeyPair *out);
SignalFfiError *signal_kyber_key_pair_clone(SignalMutPointerSignalKyberKeyPair *out, SignalConstPointerSignalKyberKeyPair pair);
SignalFfiError *signal_kyber_key_pair_destroy(SignalMutPointerSignalKyberKeyPair p);
SignalFfiError *signal_kyber_key_pair_get_public_key(SignalMutPointerSignalKyberPublicKey *out, SignalConstPointerSignalKyberKeyPair pair);
SignalFfiError *signal_kyber_key_pair_get_secret_key(SignalMutPointerSignalKyberSecretKey *out, SignalConstPointerSignalKyberKeyPair pair);

SignalFfiError *signal_kyber_public_key_clone(SignalMutPointerSignalKyberPublicKey *out, SignalConstPointerSignalKyberPublicKey key);
SignalFfiError *signal_kyber_public_key_destroy(SignalMutPointerSignalKyberPublicKey p);
SignalFfiError *signal_kyber_public_key_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalKyberPublicKey key);
SignalFfiError *signal_kyber_public_key_deserialize(SignalMutPointerSignalKyberPublicKey *out, SignalBorrowedBuffer data);
SignalFfiError *signal_kyber_public_key_equals(bool *out, SignalConstPointerSignalKyberPublicKey a, SignalConstPointerSignalKyberPublicKey b);

SignalFfiError *signal_kyber_secret_key_clone(SignalMutPointerSignalKyberSecretKey *out, SignalConstPointerSignalKyberSecretKey key);
SignalFfiError *signal_kyber_secret_key_destroy(SignalMutPointerSignalKyberSecretKey p);
SignalFfiError *signal_kyber_secret_key_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalKyberSecretKey key);
SignalFfiError *signal_kyber_secret_key_deserialize(SignalMutPointerSignalKyberSecretKey *out, SignalBorrowedBuffer data);

SignalFfiError *signal_kyber_pre_key_record_new(SignalMutPointerSignalKyberPreKeyRecord *out, uint32_t id, uint64_t timestamp, SignalConstPointerSignalKyberKeyPair key_pair, SignalBorrowedBuffer signature);
SignalFfiError *signal_kyber_pre_key_record_clone(SignalMutPointerSignalKyberPreKeyRecord *out, SignalConstPointerSignalKyberPreKeyRecord record);
SignalFfiError *signal_kyber_pre_key_record_destroy(SignalMutPointerSignalKyberPreKeyRecord p);
SignalFfiError *signal_kyber_pre_key_record_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalKyberPreKeyRecord record);
SignalFfiError *signal_kyber_pre_key_record_deserialize(SignalMutPointerSignalKyberPreKeyRecord *out, SignalBorrowedBuffer data);
SignalFfiError *signal_kyber_pre_key_record_get_id(uint32_t *out, SignalConstPointerSignalKyberPreKeyRecord record);
SignalFfiError *signal_kyber_pre_key_record_get_timestamp(uint64_t *out, SignalConstPointerSignalKyberPreKeyRecord record);
SignalFfiError *signal_kyber_pre_key_record_get_public_key(SignalMutPointerSignalKyberPublicKey *out, SignalConstPointerSignalKyberPreKeyRecord record);
SignalFfiError *signal_kyber_pre_key_record_get_secret_key(SignalMutPointerSignalKyberSecretKey *out, SignalConstPointerSignalKyberPreKeyRecord record);
SignalFfiError *signal_kyber_pre_key_record_get_key_pair(SignalMutPointerSignalKyberKeyPair *out, SignalConstPointerSignalKyberPreKeyRecord record);
SignalFfiError *signal_kyber_pre_key_record_get_signature(SignalOwnedBuffer *out, SignalConstPointerSignalKyberPreKeyRecord record);

// ── Symmetric encryption and MAC primitives ───────────────────────────────────
//
// AES-256-CTR: streaming cipher; call _process() to encrypt/decrypt in-place.
// AES-256-GCM: AEAD; call _update() with chunks, then _compute_tag()/_verify_tag().
// AES-256-GCM-SIV: nonce-misuse-resistant AEAD; single-call encrypt/decrypt.
// HKDF-SHA256: signal_hkdf_derive() writes directly into a caller-supplied buffer.
// IncrementalMac: chunked HMAC-SHA256 for large attachments; use with ValidatingMac
//   on the receiving side. signal_incremental_mac_calculate_chunk_size() returns
//   the chunk size for a given total payload length.

SignalFfiError *signal_aes256_ctr32_new(SignalMutPointerSignalAes256Ctr32 *out, SignalBorrowedBuffer key, SignalBorrowedBuffer nonce, uint32_t initial_ctr);
SignalFfiError *signal_aes256_ctr32_destroy(SignalMutPointerSignalAes256Ctr32 p);
SignalFfiError *signal_aes256_ctr32_process(SignalMutPointerSignalAes256Ctr32 ctr, SignalBorrowedMutableBuffer data, uint32_t offset, uint32_t length);

SignalFfiError *signal_aes256_gcm_encryption_new(SignalMutPointerSignalAes256GcmEncryption *out, SignalBorrowedBuffer key, SignalBorrowedBuffer nonce, SignalBorrowedBuffer associated_data);
SignalFfiError *signal_aes256_gcm_encryption_destroy(SignalMutPointerSignalAes256GcmEncryption p);
SignalFfiError *signal_aes256_gcm_encryption_update(SignalMutPointerSignalAes256GcmEncryption gcm, SignalBorrowedMutableBuffer data, uint32_t offset, uint32_t length);
SignalFfiError *signal_aes256_gcm_encryption_compute_tag(SignalOwnedBuffer *out, SignalMutPointerSignalAes256GcmEncryption gcm);

SignalFfiError *signal_aes256_gcm_decryption_new(SignalMutPointerSignalAes256GcmDecryption *out, SignalBorrowedBuffer key, SignalBorrowedBuffer nonce, SignalBorrowedBuffer associated_data);
SignalFfiError *signal_aes256_gcm_decryption_destroy(SignalMutPointerSignalAes256GcmDecryption p);
SignalFfiError *signal_aes256_gcm_decryption_update(SignalMutPointerSignalAes256GcmDecryption gcm, SignalBorrowedMutableBuffer data, uint32_t offset, uint32_t length);
SignalFfiError *signal_aes256_gcm_decryption_verify_tag(bool *out, SignalMutPointerSignalAes256GcmDecryption gcm, SignalBorrowedBuffer tag);

SignalFfiError *signal_aes256_gcm_siv_new(SignalMutPointerSignalAes256GcmSiv *out, SignalBorrowedBuffer key);
SignalFfiError *signal_aes256_gcm_siv_destroy(SignalMutPointerSignalAes256GcmSiv p);
SignalFfiError *signal_aes256_gcm_siv_encrypt(SignalOwnedBuffer *out, SignalConstPointerSignalAes256GcmSiv obj, SignalBorrowedBuffer plaintext, SignalBorrowedBuffer nonce, SignalBorrowedBuffer associated_data);
SignalFfiError *signal_aes256_gcm_siv_decrypt(SignalOwnedBuffer *out, SignalConstPointerSignalAes256GcmSiv obj, SignalBorrowedBuffer ciphertext, SignalBorrowedBuffer nonce, SignalBorrowedBuffer associated_data);

SignalFfiError *signal_hkdf_derive(SignalBorrowedMutableBuffer output, SignalBorrowedBuffer ikm, SignalBorrowedBuffer label, SignalBorrowedBuffer salt);

SignalFfiError *signal_incremental_mac_calculate_chunk_size(uint32_t *out, uint32_t data_size);
SignalFfiError *signal_incremental_mac_initialize(SignalMutPointerSignalIncrementalMac *out, SignalBorrowedBuffer key, uint32_t chunk_size);
SignalFfiError *signal_incremental_mac_update(SignalOwnedBuffer *out, SignalMutPointerSignalIncrementalMac mac, SignalBorrowedBuffer bytes, uint32_t offset, uint32_t length);
SignalFfiError *signal_incremental_mac_finalize(SignalOwnedBuffer *out, SignalMutPointerSignalIncrementalMac mac);
SignalFfiError *signal_incremental_mac_destroy(SignalMutPointerSignalIncrementalMac p);

SignalFfiError *signal_validating_mac_initialize(SignalMutPointerSignalValidatingMac *out, SignalBorrowedBuffer key, uint32_t chunk_size, SignalBorrowedBuffer digests);
SignalFfiError *signal_validating_mac_update(int32_t *out, SignalMutPointerSignalValidatingMac mac, SignalBorrowedBuffer bytes, uint32_t offset, uint32_t length);
SignalFfiError *signal_validating_mac_finalize(int32_t *out, SignalMutPointerSignalValidatingMac mac);
SignalFfiError *signal_validating_mac_destroy(SignalMutPointerSignalValidatingMac p);

// ── Protocol address ──────────────────────────────────────────────────────────
//
// SignalProtocolAddress identifies a specific device: (name: string, device_id: u32).
// Passed to store callbacks and session protocol functions. The name is a
// UTF-8 string (typically a UUID or phone number).

SignalFfiError *signal_address_new(SignalMutPointerSignalProtocolAddress *out, const char *name, uint32_t device_id);
SignalFfiError *signal_address_clone(SignalMutPointerSignalProtocolAddress *out, SignalConstPointerSignalProtocolAddress obj);
SignalFfiError *signal_address_destroy(SignalMutPointerSignalProtocolAddress p);
SignalFfiError *signal_address_get_name(const char **out, SignalConstPointerSignalProtocolAddress obj);
SignalFfiError *signal_address_get_device_id(uint32_t *out, SignalConstPointerSignalProtocolAddress obj);

// ── Key records: one-time pre-key, signed pre-key, sender key ─────────────────
//
// PreKeyRecord:       id + EC key pair. Consumed once when a session is initiated.
// SignedPreKeyRecord: id + EC key pair + identity signature + timestamp.
//                     Rotate periodically; the current one appears in every bundle.
// KyberPreKeyRecord:  id + ML-KEM-1024 key pair + identity signature + timestamp.
//                     Used for PQXDH forward secrecy.
// SenderKeyRecord:    group sender key state; stored per (sender, distribution_id).

SignalFfiError *signal_pre_key_record_new(SignalMutPointerSignalPreKeyRecord *out, uint32_t id, SignalConstPointerSignalPublicKey public_key, SignalConstPointerSignalPrivateKey private_key);
SignalFfiError *signal_pre_key_record_clone(SignalMutPointerSignalPreKeyRecord *out, SignalConstPointerSignalPreKeyRecord record);
SignalFfiError *signal_pre_key_record_destroy(SignalMutPointerSignalPreKeyRecord p);
SignalFfiError *signal_pre_key_record_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalPreKeyRecord record);
SignalFfiError *signal_pre_key_record_deserialize(SignalMutPointerSignalPreKeyRecord *out, SignalBorrowedBuffer data);
SignalFfiError *signal_pre_key_record_get_id(uint32_t *out, SignalConstPointerSignalPreKeyRecord record);
SignalFfiError *signal_pre_key_record_get_public_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPreKeyRecord record);
SignalFfiError *signal_pre_key_record_get_private_key(SignalMutPointerSignalPrivateKey *out, SignalConstPointerSignalPreKeyRecord record);

SignalFfiError *signal_signed_pre_key_record_new(SignalMutPointerSignalSignedPreKeyRecord *out, uint32_t id, uint64_t timestamp, SignalConstPointerSignalPublicKey public_key, SignalConstPointerSignalPrivateKey private_key, SignalBorrowedBuffer signature);
SignalFfiError *signal_signed_pre_key_record_clone(SignalMutPointerSignalSignedPreKeyRecord *out, SignalConstPointerSignalSignedPreKeyRecord record);
SignalFfiError *signal_signed_pre_key_record_destroy(SignalMutPointerSignalSignedPreKeyRecord p);
SignalFfiError *signal_signed_pre_key_record_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalSignedPreKeyRecord record);
SignalFfiError *signal_signed_pre_key_record_deserialize(SignalMutPointerSignalSignedPreKeyRecord *out, SignalBorrowedBuffer data);
SignalFfiError *signal_signed_pre_key_record_get_id(uint32_t *out, SignalConstPointerSignalSignedPreKeyRecord record);
SignalFfiError *signal_signed_pre_key_record_get_timestamp(uint64_t *out, SignalConstPointerSignalSignedPreKeyRecord record);
SignalFfiError *signal_signed_pre_key_record_get_public_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalSignedPreKeyRecord record);
SignalFfiError *signal_signed_pre_key_record_get_private_key(SignalMutPointerSignalPrivateKey *out, SignalConstPointerSignalSignedPreKeyRecord record);
SignalFfiError *signal_signed_pre_key_record_get_signature(SignalOwnedBuffer *out, SignalConstPointerSignalSignedPreKeyRecord record);

SignalFfiError *signal_sender_key_record_clone(SignalMutPointerSignalSenderKeyRecord *out, SignalConstPointerSignalSenderKeyRecord record);
SignalFfiError *signal_sender_key_record_destroy(SignalMutPointerSignalSenderKeyRecord p);
SignalFfiError *signal_sender_key_record_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalSenderKeyRecord record);
SignalFfiError *signal_sender_key_record_deserialize(SignalMutPointerSignalSenderKeyRecord *out, SignalBorrowedBuffer data);

// ── Session record ────────────────────────────────────────────────────────────
//
// Opaque Double Ratchet session state. Serialize to bytes to persist in a
// database; deserialize to restore. The store callbacks receive and return
// SignalSessionRecord objects directly — serialize/deserialize within callbacks
// to keep raw bytes in storage.

SignalFfiError *signal_session_record_new(SignalMutPointerSignalSessionRecord *out);
SignalFfiError *signal_session_record_clone(SignalMutPointerSignalSessionRecord *out, SignalConstPointerSignalSessionRecord record);
SignalFfiError *signal_session_record_destroy(SignalMutPointerSignalSessionRecord p);
SignalFfiError *signal_session_record_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalSessionRecord record);
SignalFfiError *signal_session_record_deserialize(SignalMutPointerSignalSessionRecord *out, SignalBorrowedBuffer data);
SignalFfiError *signal_session_record_get_local_registration_id(uint32_t *out, SignalConstPointerSignalSessionRecord record);
SignalFfiError *signal_session_record_get_remote_registration_id(uint32_t *out, SignalConstPointerSignalSessionRecord record);
SignalFfiError *signal_session_record_has_usable_sender_chain(bool *out, SignalConstPointerSignalSessionRecord record);
SignalFfiError *signal_session_record_current_ratchet_key_matches(bool *out, SignalConstPointerSignalSessionRecord record, SignalConstPointerSignalPublicKey key);
SignalFfiError *signal_session_record_archive_current_state(SignalMutPointerSignalSessionRecord record);

// ── Signal message types ──────────────────────────────────────────────────────
//
// SignalMessage (type=2, "whisper"):  regular Double Ratchet message. Contains
//   sender ratchet key, counter, and encrypted body. Verify MAC before use.
//
// SignalPreKeySignalMessage (type=3): session-initiating message. Wraps a
//   SignalMessage plus the base key, identity key, and pre-key identifiers
//   needed for X3DH / PQXDH key agreement.
//
// SignalSenderKeyMessage (type=7):    group message; encrypted with a sender key
//   ratchet. Authenticated with a 64-byte XEdDSA signature.
//
// SignalSenderKeyDistributionMessage: sent out-of-band to group members to
//   establish or advance the sender key ratchet.
//
// SignalCiphertextMessage: a type-tagged wrapper produced by signal_encrypt_message().
//   Check the type with signal_ciphertext_message_type() before deserializing.
//
// SignalPlaintextContent:          unencrypted content (resend / error recovery path).
// SignalDecryptionErrorMessage:    tells the sender that a message could not be
//   decrypted; triggers a session reset on the sender's side.

SignalFfiError *signal_message_new(SignalMutPointerSignalMessage *out, uint8_t message_version, SignalBorrowedBuffer mac_key, SignalConstPointerSignalPublicKey sender_ratchet_key, uint32_t counter, uint32_t previous_counter, SignalBorrowedBuffer ciphertext, SignalConstPointerSignalPublicKey sender_identity_key, SignalConstPointerSignalPublicKey receiver_identity_key);
SignalFfiError *signal_message_clone(SignalMutPointerSignalMessage *out, SignalConstPointerSignalMessage obj);
SignalFfiError *signal_message_destroy(SignalMutPointerSignalMessage p);
SignalFfiError *signal_message_deserialize(SignalMutPointerSignalMessage *out, SignalBorrowedBuffer data);
SignalFfiError *signal_message_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalMessage obj);
SignalFfiError *signal_message_get_sender_ratchet_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalMessage obj);
SignalFfiError *signal_message_get_counter(uint32_t *out, SignalConstPointerSignalMessage obj);
SignalFfiError *signal_message_get_message_version(uint32_t *out, SignalConstPointerSignalMessage obj);
SignalFfiError *signal_message_get_body(SignalOwnedBuffer *out, SignalConstPointerSignalMessage obj);
SignalFfiError *signal_message_get_serialized(SignalOwnedBuffer *out, SignalConstPointerSignalMessage obj);
SignalFfiError *signal_message_get_pq_ratchet(SignalOwnedBuffer *out, SignalConstPointerSignalMessage obj);

SignalFfiError *signal_pre_key_signal_message_new(SignalMutPointerSignalPreKeySignalMessage *out, uint8_t message_version, uint32_t registration_id, const uint32_t *pre_key_id, bool pre_key_id_valid, uint32_t signed_pre_key_id, SignalConstPointerSignalPublicKey base_key, SignalConstPointerSignalPublicKey identity_key, SignalBorrowedBuffer signal_message);
SignalFfiError *signal_pre_key_signal_message_clone(SignalMutPointerSignalPreKeySignalMessage *out, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_destroy(SignalMutPointerSignalPreKeySignalMessage p);
SignalFfiError *signal_pre_key_signal_message_deserialize(SignalMutPointerSignalPreKeySignalMessage *out, SignalBorrowedBuffer data);
SignalFfiError *signal_pre_key_signal_message_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_get_version(uint32_t *out, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_get_registration_id(uint32_t *out, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_get_pre_key_id(uint32_t *out, bool *out_valid, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_get_signed_pre_key_id(uint32_t *out, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_get_base_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_get_identity_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPreKeySignalMessage obj);
SignalFfiError *signal_pre_key_signal_message_get_signal_message(SignalMutPointerSignalMessage *out, SignalConstPointerSignalPreKeySignalMessage obj);

SignalFfiError *signal_sender_key_message_new(SignalMutPointerSignalSenderKeyMessage *out, uint8_t message_version, const uint8_t distribution_id[16], uint32_t chain_id, uint32_t iteration, SignalBorrowedBuffer ciphertext, SignalConstPointerSignalPrivateKey pk);
SignalFfiError *signal_sender_key_message_clone(SignalMutPointerSignalSenderKeyMessage *out, SignalConstPointerSignalSenderKeyMessage obj);
SignalFfiError *signal_sender_key_message_destroy(SignalMutPointerSignalSenderKeyMessage p);
SignalFfiError *signal_sender_key_message_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalSenderKeyMessage obj);
SignalFfiError *signal_sender_key_message_deserialize(SignalMutPointerSignalSenderKeyMessage *out, SignalBorrowedBuffer data);
SignalFfiError *signal_sender_key_message_get_distribution_id(uint8_t out[16], SignalConstPointerSignalSenderKeyMessage obj);
SignalFfiError *signal_sender_key_message_get_chain_id(uint32_t *out, SignalConstPointerSignalSenderKeyMessage obj);
SignalFfiError *signal_sender_key_message_get_iteration(uint32_t *out, SignalConstPointerSignalSenderKeyMessage obj);
SignalFfiError *signal_sender_key_message_get_cipher_text(SignalOwnedBuffer *out, SignalConstPointerSignalSenderKeyMessage obj);
SignalFfiError *signal_sender_key_message_verify_signature(bool *out, SignalConstPointerSignalSenderKeyMessage obj, SignalConstPointerSignalPublicKey key);

SignalFfiError *signal_sender_key_distribution_message_new(SignalMutPointerSignalSenderKeyDistributionMessage *out, const uint8_t distribution_id[16], uint32_t chain_id, uint32_t iteration, SignalBorrowedBuffer chain_key, SignalConstPointerSignalPublicKey signing_key);
SignalFfiError *signal_sender_key_distribution_message_clone(SignalMutPointerSignalSenderKeyDistributionMessage *out, SignalConstPointerSignalSenderKeyDistributionMessage obj);
SignalFfiError *signal_sender_key_distribution_message_destroy(SignalMutPointerSignalSenderKeyDistributionMessage p);
SignalFfiError *signal_sender_key_distribution_message_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalSenderKeyDistributionMessage obj);
SignalFfiError *signal_sender_key_distribution_message_deserialize(SignalMutPointerSignalSenderKeyDistributionMessage *out, SignalBorrowedBuffer data);
SignalFfiError *signal_sender_key_distribution_message_get_distribution_id(uint8_t out[16], SignalConstPointerSignalSenderKeyDistributionMessage obj);
SignalFfiError *signal_sender_key_distribution_message_get_chain_id(uint32_t *out, SignalConstPointerSignalSenderKeyDistributionMessage obj);
SignalFfiError *signal_sender_key_distribution_message_get_iteration(uint32_t *out, SignalConstPointerSignalSenderKeyDistributionMessage obj);
SignalFfiError *signal_sender_key_distribution_message_get_chain_key(SignalOwnedBuffer *out, SignalConstPointerSignalSenderKeyDistributionMessage obj);
SignalFfiError *signal_sender_key_distribution_message_get_signature_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalSenderKeyDistributionMessage obj);

SignalFfiError *signal_ciphertext_message_destroy(SignalMutPointerSignalCiphertextMessage p);
SignalFfiError *signal_ciphertext_message_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalCiphertextMessage obj);
SignalFfiError *signal_ciphertext_message_type(uint8_t *out, SignalConstPointerSignalCiphertextMessage obj);

SignalFfiError *signal_plaintext_content_clone(SignalMutPointerSignalPlaintextContent *out, SignalConstPointerSignalPlaintextContent obj);
SignalFfiError *signal_plaintext_content_destroy(SignalMutPointerSignalPlaintextContent p);
SignalFfiError *signal_plaintext_content_deserialize(SignalMutPointerSignalPlaintextContent *out, SignalBorrowedBuffer data);
SignalFfiError *signal_plaintext_content_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalPlaintextContent obj);
SignalFfiError *signal_plaintext_content_get_body(SignalOwnedBuffer *out, SignalConstPointerSignalPlaintextContent obj);

SignalFfiError *signal_decryption_error_message_clone(SignalMutPointerSignalDecryptionErrorMessage *out, SignalConstPointerSignalDecryptionErrorMessage obj);
SignalFfiError *signal_decryption_error_message_destroy(SignalMutPointerSignalDecryptionErrorMessage p);
SignalFfiError *signal_decryption_error_message_deserialize(SignalMutPointerSignalDecryptionErrorMessage *out, SignalBorrowedBuffer data);
SignalFfiError *signal_decryption_error_message_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalDecryptionErrorMessage obj);
SignalFfiError *signal_decryption_error_message_for_original_message(SignalMutPointerSignalDecryptionErrorMessage *out, SignalBorrowedBuffer original_bytes, uint32_t original_type, uint64_t original_timestamp, uint32_t sender_device_id);
SignalFfiError *signal_decryption_error_message_get_timestamp(uint64_t *out, SignalConstPointerSignalDecryptionErrorMessage obj);
SignalFfiError *signal_decryption_error_message_get_device_id(uint32_t *out, SignalConstPointerSignalDecryptionErrorMessage obj);
SignalFfiError *signal_decryption_error_message_get_ratchet_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalDecryptionErrorMessage obj);

// ── Pre-key bundle ────────────────────────────────────────────────────────────
//
// Fetched from the server before initiating a session. Contains the remote
// party's registration ID, device ID, one-time pre-key (optional), signed
// pre-key + signature, identity key, and optional Kyber pre-key + signature.
// Pass to signal_process_prekey_bundle() to run X3DH / PQXDH and create the
// initial session state.

SignalFfiError *signal_pre_key_bundle_new(SignalMutPointerSignalPreKeyBundle *out, uint32_t registration_id, uint32_t device_id, uint32_t pre_key_id, bool pre_key_id_valid, SignalConstPointerSignalPublicKey pre_key_public, uint32_t signed_pre_key_id, SignalConstPointerSignalPublicKey signed_pre_key_public, SignalBorrowedBuffer signed_pre_key_signature, SignalConstPointerSignalPublicKey identity_key, uint32_t kyber_pre_key_id, bool kyber_pre_key_id_valid, SignalConstPointerSignalKyberPublicKey kyber_pre_key_public, SignalBorrowedBuffer kyber_pre_key_signature);
SignalFfiError *signal_pre_key_bundle_clone(SignalMutPointerSignalPreKeyBundle *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_destroy(SignalMutPointerSignalPreKeyBundle p);
SignalFfiError *signal_pre_key_bundle_get_registration_id(uint32_t *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_device_id(uint32_t *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_pre_key_id(uint32_t *out, bool *out_valid, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_pre_key_public(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_signed_pre_key_id(uint32_t *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_signed_pre_key_public(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_signed_pre_key_signature(SignalOwnedBuffer *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_identity_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_kyber_pre_key_id(uint32_t *out, bool *out_valid, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_kyber_pre_key_public(SignalMutPointerSignalKyberPublicKey *out, SignalConstPointerSignalPreKeyBundle obj);
SignalFfiError *signal_pre_key_bundle_get_kyber_pre_key_signature(SignalOwnedBuffer *out, SignalConstPointerSignalPreKeyBundle obj);

// ── Store interfaces and session protocol ─────────────────────────────────────
//
// Implement the six store structs above (SignalSessionStore, SignalIdentityKeyStore,
// SignalPreKeyStore, SignalSignedPreKeyStore, SignalKyberPreKeyStore,
// SignalSenderKeyStore). Each has a void *ctx userdata pointer and function
// pointer fields for each operation. Set unused callbacks to NULL.
//
// Session lifecycle:
//   1. Fetch the remote party's PreKeyBundle from the server.
//   2. signal_process_prekey_bundle() — runs X3DH/PQXDH, stores session.
//   3. signal_encrypt_message() — encrypts plaintext; returns a CiphertextMessage.
//      First message is a PreKeySignalMessage (type=3); subsequent ones are
//      SignalMessage (type=2, "whisper").
//   4. signal_decrypt_pre_key_message() / signal_decrypt_message() — decrypts.
//
// Group messaging:
//   1. signal_sender_key_distribution_message_create() — create and distribute SKDM.
//   2. signal_process_sender_key_distribution_message() — each recipient processes.
//   3. signal_group_encrypt_message() / signal_group_decrypt_message() — encrypt/decrypt.

SignalFfiError *signal_process_prekey_bundle(SignalConstPointerSignalPreKeyBundle bundle, SignalConstPointerSignalProtocolAddress remote_address, const SignalSessionStore *session_store, const SignalIdentityKeyStore *identity_store, const SignalPreKeyStore *pre_key_store, const SignalSignedPreKeyStore *signed_pre_key_store, const SignalKyberPreKeyStore *kyber_pre_key_store);
SignalFfiError *signal_encrypt_message(SignalMutPointerSignalCiphertextMessage *out, SignalBorrowedBuffer plaintext, SignalConstPointerSignalProtocolAddress remote_address, const SignalSessionStore *session_store, const SignalIdentityKeyStore *identity_store, const SignalPreKeyStore *pre_key_store, const SignalSignedPreKeyStore *signed_pre_key_store);
SignalFfiError *signal_decrypt_message(SignalOwnedBuffer *out, SignalConstPointerSignalMessage message, SignalConstPointerSignalProtocolAddress remote_address, const SignalSessionStore *session_store, const SignalIdentityKeyStore *identity_store);
SignalFfiError *signal_decrypt_pre_key_message(SignalOwnedBuffer *out, SignalConstPointerSignalPreKeySignalMessage message, SignalConstPointerSignalProtocolAddress remote_address, const SignalSessionStore *session_store, const SignalIdentityKeyStore *identity_store, const SignalPreKeyStore *pre_key_store, const SignalSignedPreKeyStore *signed_pre_key_store, const SignalKyberPreKeyStore *kyber_pre_key_store);
SignalFfiError *signal_sender_key_distribution_message_create(SignalMutPointerSignalSenderKeyDistributionMessage *out, SignalConstPointerSignalProtocolAddress sender, SignalBorrowedBuffer distribution_id, const SignalSenderKeyStore *store);
SignalFfiError *signal_process_sender_key_distribution_message(SignalConstPointerSignalProtocolAddress sender, SignalConstPointerSignalSenderKeyDistributionMessage message, const SignalSenderKeyStore *store);
SignalFfiError *signal_group_encrypt_message(SignalOwnedBuffer *out, SignalConstPointerSignalProtocolAddress sender, SignalBorrowedBuffer distribution_id, SignalBorrowedBuffer plaintext, const SignalSenderKeyStore *store);
SignalFfiError *signal_group_decrypt_message(SignalOwnedBuffer *out, SignalConstPointerSignalProtocolAddress sender, SignalBorrowedBuffer distribution_id, SignalBorrowedBuffer ciphertext, const SignalSenderKeyStore *store);

// ── Sealed sender (anonymous messaging) ──────────────────────────────────────
//
// Sealed sender hides the sender's identity from the Signal server.
//
// V1 (single recipient):
//   Build a ServerCertificate (trust-root-signed server key), then a
//   SenderCertificate (server-signed sender identity + ephemeral key).
//   Wrap the content in an UnidentifiedSenderMessageContent and pass to
//   signal_sealed_session_cipher_encrypt(). The recipient decrypts with
//   signal_sealed_session_cipher_decrypt_to_usmc() to recover the content
//   and verified sender identity.
//
// V2 (multi-recipient, AES-256-GCM-SIV):
//   signal_sealed_sender_multi_recipient_encrypt() encrypts once for N
//   recipients. The server calls signal_sealed_sender_multi_recipient_
//   message_for_single_recipient() to produce per-device envelopes.
//   Each device decrypts with signal_sealed_sender_decrypt_v2().

SignalFfiError *signal_server_certificate_new(SignalMutPointerSignalServerCertificate *out, uint32_t key_id, SignalConstPointerSignalPublicKey server_public_key, SignalConstPointerSignalPrivateKey trust_root_private_key);
SignalFfiError *signal_server_certificate_clone(SignalMutPointerSignalServerCertificate *out, SignalConstPointerSignalServerCertificate obj);
SignalFfiError *signal_server_certificate_destroy(SignalMutPointerSignalServerCertificate p);
SignalFfiError *signal_server_certificate_deserialize(SignalMutPointerSignalServerCertificate *out, SignalBorrowedBuffer data);
SignalFfiError *signal_server_certificate_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalServerCertificate obj);
SignalFfiError *signal_server_certificate_get_key_id(uint32_t *out, SignalConstPointerSignalServerCertificate obj);
SignalFfiError *signal_server_certificate_get_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalServerCertificate obj);

SignalFfiError *signal_sender_certificate_new(SignalMutPointerSignalSenderCertificate *out, const char *sender_uuid, const char *sender_e164, uint32_t sender_device_id, SignalConstPointerSignalPublicKey sender_key, uint64_t expiration, SignalConstPointerSignalServerCertificate server_cert, SignalConstPointerSignalPrivateKey server_private_key);
SignalFfiError *signal_sender_certificate_clone(SignalMutPointerSignalSenderCertificate *out, SignalConstPointerSignalSenderCertificate obj);
SignalFfiError *signal_sender_certificate_destroy(SignalMutPointerSignalSenderCertificate p);
SignalFfiError *signal_sender_certificate_deserialize(SignalMutPointerSignalSenderCertificate *out, SignalBorrowedBuffer data);
SignalFfiError *signal_sender_certificate_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalSenderCertificate obj);
SignalFfiError *signal_sender_certificate_validate(bool *out, SignalConstPointerSignalSenderCertificate obj, SignalConstPointerSignalPublicKey trust_root, uint64_t current_time);
SignalFfiError *signal_sender_certificate_get_sender_uuid(const char **out, SignalConstPointerSignalSenderCertificate obj);
SignalFfiError *signal_sender_certificate_get_sender_e164(const char **out, SignalConstPointerSignalSenderCertificate obj);
SignalFfiError *signal_sender_certificate_get_sender_device_id(uint32_t *out, SignalConstPointerSignalSenderCertificate obj);
SignalFfiError *signal_sender_certificate_get_expiration(uint64_t *out, SignalConstPointerSignalSenderCertificate obj);
SignalFfiError *signal_sender_certificate_get_key(SignalMutPointerSignalPublicKey *out, SignalConstPointerSignalSenderCertificate obj);
SignalFfiError *signal_sender_certificate_get_server_certificate(SignalMutPointerSignalServerCertificate *out, SignalConstPointerSignalSenderCertificate obj);

SignalFfiError *signal_unidentified_sender_message_content_new(SignalMutPointerSignalUnidentifiedSenderMessageContent *out, uint8_t message_type, SignalConstPointerSignalSenderCertificate sender_cert, uint8_t content_hint, SignalBorrowedBuffer group_id, SignalBorrowedBuffer contents);
SignalFfiError *signal_unidentified_sender_message_content_clone(SignalMutPointerSignalUnidentifiedSenderMessageContent *out, SignalConstPointerSignalUnidentifiedSenderMessageContent obj);
SignalFfiError *signal_unidentified_sender_message_content_destroy(SignalMutPointerSignalUnidentifiedSenderMessageContent p);
SignalFfiError *signal_unidentified_sender_message_content_deserialize(SignalMutPointerSignalUnidentifiedSenderMessageContent *out, SignalBorrowedBuffer data);
SignalFfiError *signal_unidentified_sender_message_content_serialize(SignalOwnedBuffer *out, SignalConstPointerSignalUnidentifiedSenderMessageContent obj);
SignalFfiError *signal_unidentified_sender_message_content_get_msg_type(uint8_t *out, SignalConstPointerSignalUnidentifiedSenderMessageContent obj);
SignalFfiError *signal_unidentified_sender_message_content_get_content_hint(uint8_t *out, SignalConstPointerSignalUnidentifiedSenderMessageContent obj);
SignalFfiError *signal_unidentified_sender_message_content_get_group_id(SignalOwnedBuffer *out, SignalConstPointerSignalUnidentifiedSenderMessageContent obj);
SignalFfiError *signal_unidentified_sender_message_content_get_contents(SignalOwnedBuffer *out, SignalConstPointerSignalUnidentifiedSenderMessageContent obj);
SignalFfiError *signal_unidentified_sender_message_content_get_sender_cert(SignalMutPointerSignalSenderCertificate *out, SignalConstPointerSignalUnidentifiedSenderMessageContent obj);

SignalFfiError *signal_sealed_session_cipher_encrypt(SignalOwnedBuffer *out, SignalConstPointerSignalPublicKey recipient_identity, SignalConstPointerSignalUnidentifiedSenderMessageContent usmc);
SignalFfiError *signal_sealed_session_cipher_decrypt_to_usmc(SignalMutPointerSignalUnidentifiedSenderMessageContent *out, SignalBorrowedBuffer ciphertext, SignalConstPointerSignalPrivateKey our_identity_private_key);
SignalFfiError *signal_sealed_sender_multi_recipient_encrypt(SignalOwnedBuffer *out, SignalBorrowedBuffer message, SignalConstPointerSignalPrivateKey sender_identity_private_key, const SignalSealedSenderV2Recipient *recipients_ptr, size_t recipients_len, const uint8_t (*excluded_ids_ptr)[17], size_t excluded_ids_len);
SignalFfiError *signal_sealed_sender_multi_recipient_message_for_single_recipient(SignalOwnedBuffer *out, SignalBorrowedBuffer multi_recipient_message, const uint8_t service_id_fixed_width[17], uint8_t device_id);
SignalFfiError *signal_sealed_sender_decrypt_v2(SignalOwnedBuffer *out, SignalBorrowedBuffer received, SignalConstPointerSignalPrivateKey our_identity_private_key, SignalConstPointerSignalPublicKey sender_identity_key);

// ── Safety numbers, ServiceIds, usernames, and account keys ──────────────────
//
// Fingerprint: 60-digit displayable safety number + serializable scannable form.
//   signal_fingerprint_compare() compares scannable encodings from both ends;
//   they must be swapped (local ↔ remote) to produce matching values.
//
// ServiceId: 17-byte fixed-width encoding: type_byte || UUID[16].
//   type_byte 0x00 = ACI (Account Identity), 0x02 = PNI (Phone Number Identity).
//   Conversions between string ("ACI:…"), binary (variable-length), and
//   fixed-width forms.
//
// Username: Ristretto255-based ZK commitment scheme.
//   signal_username_hash() — compute 32-byte commitment from "nick.discriminator".
//   signal_username_proof() — generate 128-byte ZK proof of knowledge.
//   signal_username_verify() — verify proof against a hash.
//
// AccountEntropyPool: 64-character base-32 string encoding 256 bits of entropy.
//   Derive SVR key (32 bytes) and backup key (32 bytes) from the pool.
// BackupKey: 32-byte key; derive media encryption key for attachment backups.

SignalFfiError *signal_fingerprint_new(SignalMutPointerSignalFingerprint *out, uint32_t iterations, uint32_t version, SignalBorrowedBuffer local_identifier, SignalConstPointerSignalPublicKey local_key, SignalBorrowedBuffer remote_identifier, SignalConstPointerSignalPublicKey remote_key);
SignalFfiError *signal_fingerprint_clone(SignalMutPointerSignalFingerprint *out, SignalConstPointerSignalFingerprint obj);
SignalFfiError *signal_fingerprint_destroy(SignalMutPointerSignalFingerprint p);
SignalFfiError *signal_fingerprint_display_string(char **out, SignalConstPointerSignalFingerprint obj);
SignalFfiError *signal_fingerprint_scannable_encoding(SignalOwnedBuffer *out, SignalConstPointerSignalFingerprint obj);
SignalFfiError *signal_fingerprint_compare(bool *out, SignalConstPointerSignalFingerprint obj, SignalBorrowedBuffer their_scannable);

SignalFfiError *signal_service_id_parse_from_service_id_string(uint8_t out[17], const char *input);
SignalFfiError *signal_service_id_service_id_string(char **out, const uint8_t bytes[17]);
SignalFfiError *signal_service_id_service_id_binary(SignalOwnedBuffer *out, const uint8_t bytes[17]);
SignalFfiError *signal_service_id_parse_from_service_id_binary(uint8_t out[17], SignalBorrowedBuffer bytes);

SignalFfiError *signal_username_hash(uint8_t out[32], const char *username);
SignalFfiError *signal_username_hash_from_parts(uint8_t out[32], const char *nickname, uint64_t discriminator);
SignalFfiError *signal_username_proof(SignalOwnedBuffer *out, const char *username);
SignalFfiError *signal_username_verify(bool *out, const uint8_t username_hash[32], SignalBorrowedBuffer proof);

SignalFfiError *signal_account_entropy_pool_generate(SignalMutPointerSignalAccountEntropyPool *out);
SignalFfiError *signal_account_entropy_pool_parse(SignalMutPointerSignalAccountEntropyPool *out, const char *input);
SignalFfiError *signal_account_entropy_pool_destroy(SignalMutPointerSignalAccountEntropyPool p);
SignalFfiError *signal_account_entropy_pool_as_string(const char **out, SignalConstPointerSignalAccountEntropyPool obj);
SignalFfiError *signal_account_entropy_pool_derive_svr_key(uint8_t out[32], SignalConstPointerSignalAccountEntropyPool obj);
SignalFfiError *signal_account_entropy_pool_derive_backup_key(uint8_t out[32], SignalConstPointerSignalAccountEntropyPool obj);

SignalFfiError *signal_backup_key_from_account_entropy_pool(SignalMutPointerSignalBackupKey *out, SignalConstPointerSignalAccountEntropyPool pool);
SignalFfiError *signal_backup_key_from_bytes(SignalMutPointerSignalBackupKey *out, SignalBorrowedBuffer bytes);
SignalFfiError *signal_backup_key_destroy(SignalMutPointerSignalBackupKey p);
SignalFfiError *signal_backup_key_get_bytes(SignalOwnedBuffer *out, SignalConstPointerSignalBackupKey obj);
SignalFfiError *signal_backup_key_derive_media_encryption_key(uint8_t out[32], SignalConstPointerSignalBackupKey obj);

// ── Stub implementations (not yet functional) ─────────────────────────────────
//
// The following functions are declared for ABI compatibility but return
// SIGNAL_ERROR_CODE_INTERNAL_ERROR until the underlying crypto or network
// layer is wired up:
//
//   PIN hash (Argon2-based local PIN verification)
//   Device transfer certificate generation
//   ZK credentials / zkgroup (ServerSecretParams, ServerPublicParams)
//   Message backup validation (OnlineBackupValidator)
//   Media sanitization (MP4, WebP)
//   Async Tokio context
//   Network/Chat connection manager
//   SVR / CDSI client (SGX remote attestation)
//   Registration service
//   Key transparency audit
//
// signal_signal_media_check_available() returns NULL (success) unconditionally.

SignalFfiError *signal_pin_hash_from_salt(SignalMutPointerSignalPinHash *out, SignalBorrowedBuffer pin, SignalBorrowedBuffer salt);
SignalFfiError *signal_pin_hash_clone(SignalMutPointerSignalPinHash *out, SignalConstPointerSignalPinHash obj);
SignalFfiError *signal_pin_hash_destroy(SignalMutPointerSignalPinHash p);
SignalFfiError *signal_pin_hash_access_key(SignalOwnedBuffer *out, SignalConstPointerSignalPinHash obj);
SignalFfiError *signal_pin_hash_encryption_key(SignalOwnedBuffer *out, SignalConstPointerSignalPinHash obj);
SignalFfiError *signal_pin_local_hash(char **out, SignalBorrowedBuffer pin);
SignalFfiError *signal_pin_verify_local_hash(bool *out, const char *encoded_hash, SignalBorrowedBuffer pin);
SignalFfiError *signal_device_transfer_generate_private_key(SignalOwnedBuffer *out);
SignalFfiError *signal_device_transfer_generate_certificate(SignalOwnedBuffer *out, SignalBorrowedBuffer private_key, const char *name, uint32_t days_to_expire);

SignalFfiError *signal_server_secret_params_generate_deterministic(SignalMutPointerSignalServerSecretParams *out, SignalBorrowedBuffer randomness);
SignalFfiError *signal_server_secret_params_destroy(SignalMutPointerSignalServerSecretParams p);
SignalFfiError *signal_server_public_params_destroy(SignalMutPointerSignalServerPublicParams p);
SignalFfiError *signal_server_secret_params_get_public_params(SignalMutPointerSignalServerPublicParams *out, SignalConstPointerSignalServerSecretParams obj);

SignalFfiError *signal_message_backup_validation_outcome_destroy(SignalMutPointerSignalMessageBackupValidationOutcome p);
SignalFfiError *signal_message_backup_validation_outcome_get_error_message(const char **out, const SignalMessageBackupValidationOutcome *obj);
SignalFfiError *signal_message_backup_validation_outcome_get_unknown_fields(SignalOwnedBuffer *out, const SignalMessageBackupValidationOutcome *obj);
SignalFfiError *signal_online_backup_validator_new(SignalMutPointerSignalOnlineBackupValidator *out, SignalBorrowedBuffer backup_info_frame, uint8_t purpose);
SignalFfiError *signal_online_backup_validator_add_frame(SignalMutPointerSignalMessageBackupValidationOutcome *out, SignalOnlineBackupValidator *validator, SignalBorrowedBuffer frame);
SignalFfiError *signal_online_backup_validator_finalize(SignalMutPointerSignalMessageBackupValidationOutcome *out, SignalOnlineBackupValidator *validator);
SignalFfiError *signal_online_backup_validator_destroy(SignalMutPointerSignalOnlineBackupValidator p);

SignalFfiError *signal_mp4_sanitizer_sanitize(SignalOwnedBuffer *out, SignalBorrowedBuffer input, uint64_t len);
SignalFfiError *signal_webp_sanitizer_sanitize(SignalOwnedBuffer *out, SignalBorrowedBuffer input);
SignalFfiError *signal_signal_media_check_available(void);

SignalFfiError *signal_tokio_async_context_new(SignalMutPointerSignalTokioAsyncContext *out);
SignalFfiError *signal_tokio_async_context_destroy(SignalMutPointerSignalTokioAsyncContext p);
SignalFfiError *signal_tokio_async_context_cancel(SignalTokioAsyncContext *ctx);

SignalFfiError *signal_connection_manager_new(SignalMutPointerSignalConnectionManager *out, uint8_t environment, const char *user_agent);
SignalFfiError *signal_connection_manager_destroy(SignalMutPointerSignalConnectionManager p);

SignalFfiError *signal_sgx_client_state_destroy(SignalMutPointerSignalSgxClientState p);
SignalFfiError *signal_registration_service_destroy(SignalMutPointerSignalRegistrationService p);
SignalFfiError *signal_key_transparency_check(SignalOwnedBuffer *out, SignalBorrowedBuffer key);

#ifdef __cplusplus
}
#endif

#endif /* SIGNAL_FFI_H */
