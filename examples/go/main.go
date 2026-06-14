// examples/go/main.go — signal_ffi.h round-trip exerciser (Go + cgo)
//
// The C store infrastructure (kv_t, all callbacks, test functions) lives in the
// cgo block so the C compiler handles the signal_ffi.h opaque types directly.
// Go's main() calls each C test function and prints results.
//
// Build and run:  go run main.go
package main

/*
#cgo CFLAGS:  -I${SRCDIR}/../../include -std=c11
#cgo LDFLAGS: -L${SRCDIR}/../../zig-out/lib -lsignal_ffi -Wl,-rpath,${SRCDIR}/../../zig-out/lib

#include "signal_ffi.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

// ── Error helper ─────────────────────────────────────────────────────────────

static void die(SignalFfiError *e, const char *label) {
    const char *msg = NULL;
    signal_error_get_message(&msg, e);
    fprintf(stderr, "[FAIL] %s: %s\n", label, msg ? msg : "(no message)");
    signal_error_free(e);
    abort();
}
#define MUST(call) do { SignalFfiError *_e = (call); if (_e) die(_e, #call); } while(0)

// ── Generic key-value store ───────────────────────────────────────────────────

#define KV_MAX 128
typedef struct { char key[512]; uint8_t *data; size_t len; } kv_row_t;
typedef struct { kv_row_t rows[KV_MAX]; int n; } kv_t;

static void kv_put(kv_t *s, const char *k, const uint8_t *d, size_t l) {
    for (int i = 0; i < s->n; i++) {
        if (strcmp(s->rows[i].key, k) == 0) {
            free(s->rows[i].data);
            s->rows[i].data = malloc(l); memcpy(s->rows[i].data, d, l);
            s->rows[i].len  = l; return;
        }
    }
    if (s->n >= KV_MAX) { fputs("[FAIL] kv_put: store full\n", stderr); abort(); }
    strncpy(s->rows[s->n].key, k, 511);
    s->rows[s->n].data = malloc(l); memcpy(s->rows[s->n].data, d, l);
    s->rows[s->n].len  = l; s->n++;
}
static int kv_get(kv_t *s, const char *k, uint8_t **d, size_t *l) {
    for (int i = 0; i < s->n; i++) {
        if (strcmp(s->rows[i].key, k) == 0) {
            *l = s->rows[i].len; *d = malloc(*l);
            memcpy(*d, s->rows[i].data, *l); return 1;
        }
    }
    return 0;
}
static void kv_free(kv_t *s) {
    for (int i = 0; i < s->n; i++) free(s->rows[i].data);
    memset(s, 0, sizeof *s);
}

static void addr_to_key(char *buf, size_t sz, const SignalProtocolAddress *addr) {
    const char *name = NULL; uint32_t dev = 0;
    SignalConstPointerSignalProtocolAddress ca = {addr};
    MUST(signal_address_get_name(&name, ca));
    MUST(signal_address_get_device_id(&dev, ca));
    snprintf(buf, sz, "%s:%u", name, dev);
}

// ── Session store ─────────────────────────────────────────────────────────────

static SignalFfiError *sess_load(SignalMutPointerSignalSessionRecord *out,
                                  const SignalProtocolAddress *addr, void *ud) {
    char k[512]; addr_to_key(k, sizeof k, addr);
    uint8_t *data; size_t len;
    if (!kv_get((kv_t *)ud, k, &data, &len)) { out->raw = NULL; return NULL; }
    SignalBorrowedBuffer buf = {data, len};
    SignalFfiError *e = signal_session_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *sess_store_fn(const SignalProtocolAddress *addr,
                                      SignalConstPointerSignalSessionRecord rec,
                                      void *ud) {
    char k[512]; addr_to_key(k, sizeof k, addr);
    SignalOwnedBuffer b = {0};
    SignalFfiError *e = signal_session_record_serialize(&b, rec);
    if (e) return e;
    kv_put((kv_t *)ud, k, b.base, b.length);
    signal_free_buffer(b.base, b.length); return NULL;
}
static SignalSessionStore make_sess(kv_t *kv) {
    return (SignalSessionStore){kv, sess_load, sess_store_fn, NULL};
}

// ── Identity store ────────────────────────────────────────────────────────────

typedef struct {
    uint8_t  priv_bytes[32];
    uint32_t reg_id;
    kv_t     trusted;
} id_state_t;

static SignalFfiError *id_get_kp(SignalMutPointerSignalPublicKey *out_pub,
                                  SignalMutPointerSignalPrivateKey *out_priv,
                                  void *ud) {
    id_state_t *s = ud;
    SignalBorrowedBuffer pb = {s->priv_bytes, 32};
    SignalFfiError *e = signal_privatekey_deserialize(out_priv, pb);
    if (e) return e;
    return signal_privatekey_get_public_key(out_pub,
               (SignalConstPointerSignalPrivateKey){out_priv->raw});
}
static SignalFfiError *id_get_reg(uint32_t *out, void *ud) {
    *out = ((id_state_t *)ud)->reg_id; return NULL;
}
static SignalFfiError *id_save(const SignalProtocolAddress *addr,
                                SignalConstPointerSignalPublicKey key, void *ud) {
    id_state_t *s = ud;
    char k[512]; addr_to_key(k, sizeof k, addr);
    SignalOwnedBuffer b = {0};
    SignalFfiError *e = signal_publickey_serialize(&b, key);
    if (e) return e;
    kv_put(&s->trusted, k, b.base, b.length);
    signal_free_buffer(b.base, b.length); return NULL;
}
static SignalFfiError *id_trusted(bool *out, const SignalProtocolAddress *addr,
                                   SignalConstPointerSignalPublicKey key,
                                   uint32_t dir, void *ud) {
    (void)addr; (void)key; (void)dir; (void)ud; *out = true; return NULL;
}
static SignalFfiError *id_get(SignalMutPointerSignalPublicKey *out,
                               const SignalProtocolAddress *addr, void *ud) {
    id_state_t *s = ud;
    char k[512]; addr_to_key(k, sizeof k, addr);
    uint8_t *data; size_t len;
    if (!kv_get(&s->trusted, k, &data, &len)) { out->raw = NULL; return NULL; }
    SignalBorrowedBuffer buf = {data, len};
    SignalFfiError *e = signal_publickey_deserialize(out, buf);
    free(data); return e;
}
static SignalIdentityKeyStore make_id(id_state_t *s) {
    return (SignalIdentityKeyStore){s, id_get_kp, id_get_reg, id_save, id_trusted, id_get, NULL};
}

// ── Pre-key store ─────────────────────────────────────────────────────────────

static SignalFfiError *pk_load(SignalMutPointerSignalPreKeyRecord *out,
                                uint32_t id, void *ud) {
    char k[32]; snprintf(k, sizeof k, "%u", id);
    uint8_t *data; size_t len;
    if (!kv_get((kv_t *)ud, k, &data, &len)) { out->raw = NULL; return NULL; }
    SignalBorrowedBuffer buf = {data, len};
    SignalFfiError *e = signal_pre_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *pk_store_fn(uint32_t id,
                                    SignalMutPointerSignalPreKeyRecord rec,
                                    void *ud) {
    char k[32]; snprintf(k, sizeof k, "%u", id);
    SignalOwnedBuffer b = {0};
    SignalFfiError *e = signal_pre_key_record_serialize(&b,
                            (SignalConstPointerSignalPreKeyRecord){rec.raw});
    if (e) return e;
    kv_put((kv_t *)ud, k, b.base, b.length);
    signal_free_buffer(b.base, b.length); return NULL;
}
static SignalFfiError *pk_remove(uint32_t id, void *ud) {
    (void)id; (void)ud; return NULL;
}
static SignalPreKeyStore make_pk(kv_t *kv) {
    return (SignalPreKeyStore){kv, pk_load, pk_store_fn, pk_remove, NULL};
}

// ── Signed pre-key store ──────────────────────────────────────────────────────

static SignalFfiError *spk_load(SignalMutPointerSignalSignedPreKeyRecord *out,
                                 uint32_t id, void *ud) {
    char k[32]; snprintf(k, sizeof k, "%u", id);
    uint8_t *data; size_t len;
    if (!kv_get((kv_t *)ud, k, &data, &len)) { out->raw = NULL; return NULL; }
    SignalBorrowedBuffer buf = {data, len};
    SignalFfiError *e = signal_signed_pre_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *spk_store_fn(uint32_t id,
                                     SignalMutPointerSignalSignedPreKeyRecord rec,
                                     void *ud) {
    char k[32]; snprintf(k, sizeof k, "%u", id);
    SignalOwnedBuffer b = {0};
    SignalFfiError *e = signal_signed_pre_key_record_serialize(&b,
                            (SignalConstPointerSignalSignedPreKeyRecord){rec.raw});
    if (e) return e;
    kv_put((kv_t *)ud, k, b.base, b.length);
    signal_free_buffer(b.base, b.length); return NULL;
}
static SignalSignedPreKeyStore make_spk(kv_t *kv) {
    return (SignalSignedPreKeyStore){kv, spk_load, spk_store_fn, NULL};
}

// ── Kyber pre-key store ───────────────────────────────────────────────────────

static SignalFfiError *kpk_load(SignalMutPointerSignalKyberPreKeyRecord *out,
                                 uint32_t id, void *ud) {
    char k[32]; snprintf(k, sizeof k, "%u", id);
    uint8_t *data; size_t len;
    if (!kv_get((kv_t *)ud, k, &data, &len)) { out->raw = NULL; return NULL; }
    SignalBorrowedBuffer buf = {data, len};
    SignalFfiError *e = signal_kyber_pre_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *kpk_store_fn(uint32_t id,
                                     SignalMutPointerSignalKyberPreKeyRecord rec,
                                     void *ud) {
    char k[32]; snprintf(k, sizeof k, "%u", id);
    SignalOwnedBuffer b = {0};
    SignalFfiError *e = signal_kyber_pre_key_record_serialize(&b,
                            (SignalConstPointerSignalKyberPreKeyRecord){rec.raw});
    if (e) return e;
    kv_put((kv_t *)ud, k, b.base, b.length);
    signal_free_buffer(b.base, b.length); return NULL;
}
static SignalFfiError *kpk_mark_used(uint32_t id, void *ud) {
    (void)id; (void)ud; return NULL;
}
static SignalKyberPreKeyStore make_kpk(kv_t *kv) {
    return (SignalKyberPreKeyStore){kv, kpk_load, kpk_store_fn, kpk_mark_used, NULL};
}

// ── Sender key store ──────────────────────────────────────────────────────────

static void sk_key(char *buf, size_t sz,
                    const SignalProtocolAddress *sender, const uint8_t dist_id[16]) {
    const char *name = NULL; uint32_t dev = 0;
    SignalConstPointerSignalProtocolAddress ca = {sender};
    MUST(signal_address_get_name(&name, ca));
    MUST(signal_address_get_device_id(&dev, ca));
    int n = snprintf(buf, sz, "%s:%u:", name, dev);
    for (int i = 0; i < 16; i++) n += snprintf(buf + n, sz - n, "%02x", dist_id[i]);
}
static SignalFfiError *sk_store_fn(const SignalProtocolAddress *sender,
                                    const uint8_t dist_id[16],
                                    SignalConstPointerSignalSenderKeyRecord rec,
                                    void *ud) {
    char k[600]; sk_key(k, sizeof k, sender, dist_id);
    SignalOwnedBuffer b = {0};
    SignalFfiError *e = signal_sender_key_record_serialize(&b, rec);
    if (e) return e;
    kv_put((kv_t *)ud, k, b.base, b.length);
    signal_free_buffer(b.base, b.length); return NULL;
}
static SignalFfiError *sk_load_fn(SignalMutPointerSignalSenderKeyRecord *out,
                                   const SignalProtocolAddress *sender,
                                   const uint8_t dist_id[16], void *ud) {
    char k[600]; sk_key(k, sizeof k, sender, dist_id);
    uint8_t *data; size_t len;
    if (!kv_get((kv_t *)ud, k, &data, &len)) { out->raw = NULL; return NULL; }
    SignalBorrowedBuffer buf = {data, len};
    SignalFfiError *e = signal_sender_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalSenderKeyStore make_sk(kv_t *kv) {
    return (SignalSenderKeyStore){kv, sk_store_fn, sk_load_fn, NULL};
}

// ── sign_bytes helper ─────────────────────────────────────────────────────────

static SignalOwnedBuffer sign_bytes(const uint8_t priv32[32],
                                     const uint8_t *data, size_t len) {
    SignalMutPointerSignalPrivateKey pk = {NULL};
    MUST(signal_privatekey_deserialize(&pk, (SignalBorrowedBuffer){priv32, 32}));
    SignalOwnedBuffer sig = {0};
    MUST(signal_privatekey_sign(&sig, (SignalConstPointerSignalPrivateKey){pk.raw},
                                 (SignalBorrowedBuffer){data, len}));
    signal_privatekey_destroy(pk);
    return sig;
}

// ── Bob setup (identity + OPK + SPK + KPK → stores) ─────────────────────────

typedef struct {
    uint8_t  id_priv[32];
    uint32_t reg_id;
    uint32_t opk_id, spk_id, kpk_id;
} bob_keys_t;

static void setup_bob(bob_keys_t *out,
                       kv_t *pk_store, kv_t *spk_store, kv_t *kpk_store) {
    SignalMutPointerSignalPrivateKey id_priv = {NULL};
    MUST(signal_privatekey_generate(&id_priv));
    SignalOwnedBuffer id_bytes = {0};
    MUST(signal_privatekey_serialize(&id_bytes,
                                      (SignalConstPointerSignalPrivateKey){id_priv.raw}));
    memcpy(out->id_priv, id_bytes.base, 32);
    signal_free_buffer(id_bytes.base, id_bytes.length);
    out->reg_id = 2002;

    out->opk_id = 1;
    SignalMutPointerSignalPrivateKey opk_priv = {NULL};
    MUST(signal_privatekey_generate(&opk_priv));
    SignalMutPointerSignalPublicKey opk_pub = {NULL};
    MUST(signal_privatekey_get_public_key(&opk_pub,
             (SignalConstPointerSignalPrivateKey){opk_priv.raw}));
    SignalMutPointerSignalPreKeyRecord opk_rec = {NULL};
    MUST(signal_pre_key_record_new(&opk_rec, out->opk_id,
             (SignalConstPointerSignalPublicKey){opk_pub.raw},
             (SignalConstPointerSignalPrivateKey){opk_priv.raw}));
    signal_privatekey_destroy(opk_priv); signal_publickey_destroy(opk_pub);
    MUST(pk_store_fn(out->opk_id, opk_rec, pk_store));
    signal_pre_key_record_destroy(opk_rec);

    out->spk_id = 1;
    SignalMutPointerSignalPrivateKey spk_priv = {NULL};
    MUST(signal_privatekey_generate(&spk_priv));
    SignalMutPointerSignalPublicKey spk_pub = {NULL};
    MUST(signal_privatekey_get_public_key(&spk_pub,
             (SignalConstPointerSignalPrivateKey){spk_priv.raw}));
    SignalOwnedBuffer spk_pub_b = {0};
    MUST(signal_publickey_serialize(&spk_pub_b,
             (SignalConstPointerSignalPublicKey){spk_pub.raw}));
    SignalOwnedBuffer spk_sig = sign_bytes(out->id_priv,
                                            spk_pub_b.base, spk_pub_b.length);
    signal_free_buffer(spk_pub_b.base, spk_pub_b.length);
    SignalMutPointerSignalSignedPreKeyRecord spk_rec = {NULL};
    MUST(signal_signed_pre_key_record_new(&spk_rec, out->spk_id, 1700000000,
             (SignalConstPointerSignalPublicKey){spk_pub.raw},
             (SignalConstPointerSignalPrivateKey){spk_priv.raw},
             (SignalBorrowedBuffer){spk_sig.base, spk_sig.length}));
    signal_free_buffer(spk_sig.base, spk_sig.length);
    signal_privatekey_destroy(spk_priv); signal_publickey_destroy(spk_pub);
    MUST(spk_store_fn(out->spk_id, spk_rec, spk_store));
    signal_signed_pre_key_record_destroy(spk_rec);

    out->kpk_id = 1;
    SignalMutPointerSignalKyberKeyPair kpk = {NULL};
    MUST(signal_kyber_key_pair_generate(&kpk));
    SignalMutPointerSignalKyberPublicKey kpk_pub = {NULL};
    MUST(signal_kyber_key_pair_get_public_key(&kpk_pub,
             (SignalConstPointerSignalKyberKeyPair){kpk.raw}));
    SignalOwnedBuffer kpk_pub_b = {0};
    MUST(signal_kyber_public_key_serialize(&kpk_pub_b,
             (SignalConstPointerSignalKyberPublicKey){kpk_pub.raw}));
    SignalOwnedBuffer kpk_sig = sign_bytes(out->id_priv,
                                            kpk_pub_b.base, kpk_pub_b.length);
    signal_free_buffer(kpk_pub_b.base, kpk_pub_b.length);
    signal_kyber_public_key_destroy(kpk_pub);
    SignalMutPointerSignalKyberPreKeyRecord kpk_rec = {NULL};
    MUST(signal_kyber_pre_key_record_new(&kpk_rec, out->kpk_id, 1700000000,
             (SignalConstPointerSignalKyberKeyPair){kpk.raw},
             (SignalBorrowedBuffer){kpk_sig.base, kpk_sig.length}));
    signal_free_buffer(kpk_sig.base, kpk_sig.length);
    signal_kyber_key_pair_destroy(kpk);
    MUST(kpk_store_fn(out->kpk_id, kpk_rec, kpk_store));
    signal_kyber_pre_key_record_destroy(kpk_rec);

    signal_privatekey_destroy(id_priv);
}

// ── Test functions ────────────────────────────────────────────────────────────

static void run_test_ec_keys(void) {
    SignalMutPointerSignalPrivateKey pa = {NULL}, pb = {NULL};
    MUST(signal_privatekey_generate(&pa));
    MUST(signal_privatekey_generate(&pb));
    SignalMutPointerSignalPublicKey qa = {NULL}, qb = {NULL};
    MUST(signal_privatekey_get_public_key(&qa, (SignalConstPointerSignalPrivateKey){pa.raw}));
    MUST(signal_privatekey_get_public_key(&qb, (SignalConstPointerSignalPrivateKey){pb.raw}));

    SignalOwnedBuffer dh_a = {0}, dh_b = {0};
    MUST(signal_privatekey_agree(&dh_a, (SignalConstPointerSignalPrivateKey){pa.raw},
                                         (SignalConstPointerSignalPublicKey){qb.raw}));
    MUST(signal_privatekey_agree(&dh_b, (SignalConstPointerSignalPrivateKey){pb.raw},
                                         (SignalConstPointerSignalPublicKey){qa.raw}));
    if (dh_a.length != 32 || memcmp(dh_a.base, dh_b.base, 32) != 0) {
        fputs("[FAIL] DH secrets differ\n", stderr); abort();
    }
    signal_free_buffer(dh_a.base, dh_a.length);
    signal_free_buffer(dh_b.base, dh_b.length);

    const uint8_t msg[] = "hello signal";
    SignalOwnedBuffer sig = {0};
    MUST(signal_privatekey_sign(&sig, (SignalConstPointerSignalPrivateKey){pa.raw},
                                 (SignalBorrowedBuffer){msg, sizeof msg - 1}));
    bool ok = false;
    MUST(signal_publickey_verify(&ok, (SignalConstPointerSignalPublicKey){qa.raw},
                                  (SignalBorrowedBuffer){msg, sizeof msg - 1},
                                  (SignalBorrowedBuffer){sig.base, sig.length}));
    if (!ok) { fputs("[FAIL] XEdDSA verify failed\n", stderr); abort(); }
    signal_free_buffer(sig.base, sig.length);
    signal_privatekey_destroy(pa); signal_privatekey_destroy(pb);
    signal_publickey_destroy(qa);  signal_publickey_destroy(qb);
    printf("EC + XEdDSA                   PASS\n");
}

static void run_test_kyber_keys(void) {
    SignalMutPointerSignalKyberKeyPair kp = {NULL};
    MUST(signal_kyber_key_pair_generate(&kp));
    SignalMutPointerSignalKyberPublicKey pub = {NULL};
    SignalMutPointerSignalKyberSecretKey sec = {NULL};
    MUST(signal_kyber_key_pair_get_public_key(&pub, (SignalConstPointerSignalKyberKeyPair){kp.raw}));
    MUST(signal_kyber_key_pair_get_secret_key(&sec, (SignalConstPointerSignalKyberKeyPair){kp.raw}));
    SignalOwnedBuffer pub_b = {0}, sec_b = {0};
    MUST(signal_kyber_public_key_serialize(&pub_b, (SignalConstPointerSignalKyberPublicKey){pub.raw}));
    MUST(signal_kyber_secret_key_serialize(&sec_b, (SignalConstPointerSignalKyberSecretKey){sec.raw}));
    if (pub_b.length != 1568 || sec_b.length != 3168) {
        fprintf(stderr, "[FAIL] Kyber sizes: pub=%zu sec=%zu\n", pub_b.length, sec_b.length); abort();
    }
    signal_free_buffer(pub_b.base, pub_b.length);
    signal_free_buffer(sec_b.base, sec_b.length);
    signal_kyber_key_pair_destroy(kp);
    signal_kyber_public_key_destroy(pub);
    signal_kyber_secret_key_destroy(sec);
    printf("ML-KEM-1024 (Kyber)           PASS\n");
}

static void run_test_session(void) {
    uint8_t alice_id_priv[32];
    {
        SignalMutPointerSignalPrivateKey p = {NULL};
        MUST(signal_privatekey_generate(&p));
        SignalOwnedBuffer b = {0};
        MUST(signal_privatekey_serialize(&b, (SignalConstPointerSignalPrivateKey){p.raw}));
        memcpy(alice_id_priv, b.base, 32);
        signal_free_buffer(b.base, b.length);
        signal_privatekey_destroy(p);
    }

    kv_t bob_sess = {0}, bob_pk = {0}, bob_spk = {0}, bob_kpk = {0};
    bob_keys_t bob; setup_bob(&bob, &bob_pk, &bob_spk, &bob_kpk);

    SignalMutPointerSignalPreKeyRecord opk_r = {NULL};
    MUST(pk_load(&opk_r, bob.opk_id, &bob_pk));
    SignalMutPointerSignalPublicKey opk_pub = {NULL};
    MUST(signal_pre_key_record_get_public_key(&opk_pub,
             (SignalConstPointerSignalPreKeyRecord){opk_r.raw}));
    signal_pre_key_record_destroy(opk_r);

    SignalMutPointerSignalSignedPreKeyRecord spk_r = {NULL};
    MUST(spk_load(&spk_r, bob.spk_id, &bob_spk));
    SignalMutPointerSignalPublicKey spk_pub = {NULL};
    MUST(signal_signed_pre_key_record_get_public_key(&spk_pub,
             (SignalConstPointerSignalSignedPreKeyRecord){spk_r.raw}));
    SignalOwnedBuffer spk_sig = {0};
    MUST(signal_signed_pre_key_record_get_signature(&spk_sig,
             (SignalConstPointerSignalSignedPreKeyRecord){spk_r.raw}));
    signal_signed_pre_key_record_destroy(spk_r);

    SignalMutPointerSignalKyberPreKeyRecord kpk_r = {NULL};
    MUST(kpk_load(&kpk_r, bob.kpk_id, &bob_kpk));
    SignalMutPointerSignalKyberPublicKey kpk_pub = {NULL};
    MUST(signal_kyber_pre_key_record_get_public_key(&kpk_pub,
             (SignalConstPointerSignalKyberPreKeyRecord){kpk_r.raw}));
    SignalOwnedBuffer kpk_sig = {0};
    MUST(signal_kyber_pre_key_record_get_signature(&kpk_sig,
             (SignalConstPointerSignalKyberPreKeyRecord){kpk_r.raw}));
    signal_kyber_pre_key_record_destroy(kpk_r);

    SignalMutPointerSignalPrivateKey bob_id_priv_obj = {NULL};
    MUST(signal_privatekey_deserialize(&bob_id_priv_obj,
             (SignalBorrowedBuffer){bob.id_priv, 32}));
    SignalMutPointerSignalPublicKey bob_id_pub = {NULL};
    MUST(signal_privatekey_get_public_key(&bob_id_pub,
             (SignalConstPointerSignalPrivateKey){bob_id_priv_obj.raw}));
    signal_privatekey_destroy(bob_id_priv_obj);

    SignalMutPointerSignalPreKeyBundle bundle = {NULL};
    MUST(signal_pre_key_bundle_new(&bundle,
             bob.reg_id, 1,
             bob.opk_id, true, (SignalConstPointerSignalPublicKey){opk_pub.raw},
             bob.spk_id, (SignalConstPointerSignalPublicKey){spk_pub.raw},
             (SignalBorrowedBuffer){spk_sig.base, spk_sig.length},
             (SignalConstPointerSignalPublicKey){bob_id_pub.raw},
             bob.kpk_id, true, (SignalConstPointerSignalKyberPublicKey){kpk_pub.raw},
             (SignalBorrowedBuffer){kpk_sig.base, kpk_sig.length}));
    signal_publickey_destroy(opk_pub); signal_publickey_destroy(spk_pub);
    signal_free_buffer(spk_sig.base, spk_sig.length);
    signal_kyber_public_key_destroy(kpk_pub);
    signal_free_buffer(kpk_sig.base, kpk_sig.length);
    signal_publickey_destroy(bob_id_pub);

    kv_t alice_sess = {0}, alice_pk = {0}, alice_spk = {0}, alice_kpk = {0};
    id_state_t alice_id = {0}; memcpy(alice_id.priv_bytes, alice_id_priv, 32); alice_id.reg_id = 1001;
    id_state_t bob_id_s = {0}; memcpy(bob_id_s.priv_bytes, bob.id_priv, 32); bob_id_s.reg_id = bob.reg_id;

    SignalMutPointerSignalProtocolAddress bob_addr = {NULL};
    MUST(signal_address_new(&bob_addr, "bob", 1));
    SignalMutPointerSignalProtocolAddress alice_addr = {NULL};
    MUST(signal_address_new(&alice_addr, "alice", 1));

    SignalSessionStore      a_ss  = make_sess(&alice_sess);
    SignalIdentityKeyStore  a_is  = make_id(&alice_id);
    SignalPreKeyStore       a_pks = make_pk(&alice_pk);
    SignalSignedPreKeyStore a_sks = make_spk(&alice_spk);
    SignalKyberPreKeyStore  a_kks = make_kpk(&alice_kpk);

    MUST(signal_process_prekey_bundle(
             (SignalConstPointerSignalPreKeyBundle){bundle.raw},
             (SignalConstPointerSignalProtocolAddress){bob_addr.raw},
             &a_ss, &a_is, &a_pks, &a_sks, &a_kks));
    signal_pre_key_bundle_destroy(bundle);

    const uint8_t pt1[] = "hello bob";
    SignalMutPointerSignalCiphertextMessage ct1 = {NULL};
    MUST(signal_encrypt_message(&ct1, (SignalBorrowedBuffer){pt1, sizeof pt1 - 1},
             (SignalConstPointerSignalProtocolAddress){bob_addr.raw},
             &a_ss, &a_is, &a_pks, &a_sks));
    SignalOwnedBuffer ct1_b = {0};
    MUST(signal_ciphertext_message_serialize(&ct1_b,
             (SignalConstPointerSignalCiphertextMessage){ct1.raw}));
    signal_ciphertext_message_destroy(ct1);

    SignalMutPointerSignalPreKeySignalMessage pksm = {NULL};
    MUST(signal_pre_key_signal_message_deserialize(&pksm,
             (SignalBorrowedBuffer){ct1_b.base, ct1_b.length}));
    signal_free_buffer(ct1_b.base, ct1_b.length);

    SignalSessionStore      b_ss  = make_sess(&bob_sess);
    SignalIdentityKeyStore  b_is  = make_id(&bob_id_s);
    SignalPreKeyStore       b_pks = make_pk(&bob_pk);
    SignalSignedPreKeyStore b_sks = make_spk(&bob_spk);
    SignalKyberPreKeyStore  b_kks = make_kpk(&bob_kpk);

    SignalOwnedBuffer dec1 = {0};
    MUST(signal_decrypt_pre_key_message(&dec1,
             (SignalConstPointerSignalPreKeySignalMessage){pksm.raw},
             (SignalConstPointerSignalProtocolAddress){alice_addr.raw},
             &b_ss, &b_is, &b_pks, &b_sks, &b_kks));
    signal_pre_key_signal_message_destroy(pksm);

    if (dec1.length != sizeof pt1 - 1 || memcmp(dec1.base, pt1, dec1.length) != 0) {
        fputs("[FAIL] pre-key plaintext mismatch\n", stderr); abort();
    }
    signal_free_buffer(dec1.base, dec1.length);

    const uint8_t pt2[] = "hey alice";
    SignalMutPointerSignalCiphertextMessage ct2 = {NULL};
    MUST(signal_encrypt_message(&ct2, (SignalBorrowedBuffer){pt2, sizeof pt2 - 1},
             (SignalConstPointerSignalProtocolAddress){alice_addr.raw},
             &b_ss, &b_is, &b_pks, &b_sks));
    SignalOwnedBuffer ct2_b = {0};
    MUST(signal_ciphertext_message_serialize(&ct2_b,
             (SignalConstPointerSignalCiphertextMessage){ct2.raw}));
    signal_ciphertext_message_destroy(ct2);

    SignalMutPointerSignalMessage whisper = {NULL};
    MUST(signal_message_deserialize(&whisper,
             (SignalBorrowedBuffer){ct2_b.base, ct2_b.length}));
    signal_free_buffer(ct2_b.base, ct2_b.length);

    SignalOwnedBuffer dec2 = {0};
    MUST(signal_decrypt_message(&dec2,
             (SignalConstPointerSignalMessage){whisper.raw},
             (SignalConstPointerSignalProtocolAddress){bob_addr.raw},
             &a_ss, &a_is));
    signal_message_destroy(whisper);

    if (dec2.length != sizeof pt2 - 1 || memcmp(dec2.base, pt2, dec2.length) != 0) {
        fputs("[FAIL] whisper plaintext mismatch\n", stderr); abort();
    }
    signal_free_buffer(dec2.base, dec2.length);

    signal_address_destroy(bob_addr); signal_address_destroy(alice_addr);
    kv_free(&alice_sess); kv_free(&alice_pk); kv_free(&alice_spk); kv_free(&alice_kpk);
    kv_free(&alice_id.trusted);
    kv_free(&bob_sess);   kv_free(&bob_pk);   kv_free(&bob_spk);   kv_free(&bob_kpk);
    kv_free(&bob_id_s.trusted);
    printf("X3DH + PQXDH + Double Ratchet PASS\n");
}

static void run_test_group(void) {
    static const uint8_t dist_id[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };
    kv_t alice_sk = {0}, bob_sk = {0};
    SignalSenderKeyStore a_store = make_sk(&alice_sk);
    SignalSenderKeyStore b_store = make_sk(&bob_sk);

    SignalMutPointerSignalProtocolAddress alice_addr = {NULL};
    MUST(signal_address_new(&alice_addr, "alice", 1));
    SignalConstPointerSignalProtocolAddress ca = {alice_addr.raw};

    SignalMutPointerSignalSenderKeyDistributionMessage skdm = {NULL};
    MUST(signal_sender_key_distribution_message_create(&skdm, ca,
             (SignalBorrowedBuffer){dist_id, 16}, &a_store));
    MUST(signal_process_sender_key_distribution_message(ca,
             (SignalConstPointerSignalSenderKeyDistributionMessage){skdm.raw}, &b_store));
    signal_sender_key_distribution_message_destroy(skdm);

    const uint8_t msg[] = "group hello";
    SignalOwnedBuffer enc = {0};
    MUST(signal_group_encrypt_message(&enc, ca, (SignalBorrowedBuffer){dist_id, 16},
             (SignalBorrowedBuffer){msg, sizeof msg - 1}, &a_store));

    SignalOwnedBuffer dec = {0};
    MUST(signal_group_decrypt_message(&dec, ca,
             (SignalBorrowedBuffer){dist_id, 16},
             (SignalBorrowedBuffer){enc.base, enc.length}, &b_store));
    signal_free_buffer(enc.base, enc.length);

    if (dec.length != sizeof msg - 1 || memcmp(dec.base, msg, dec.length) != 0) {
        fputs("[FAIL] group plaintext mismatch\n", stderr); abort();
    }
    signal_free_buffer(dec.base, dec.length);
    signal_address_destroy(alice_addr);
    kv_free(&alice_sk); kv_free(&bob_sk);
    printf("Sender Keys (group)           PASS\n");
}

static void run_test_fingerprint(void) {
    SignalMutPointerSignalPrivateKey pa = {NULL}, pb = {NULL};
    MUST(signal_privatekey_generate(&pa));
    MUST(signal_privatekey_generate(&pb));
    SignalMutPointerSignalPublicKey qa = {NULL}, qb = {NULL};
    MUST(signal_privatekey_get_public_key(&qa, (SignalConstPointerSignalPrivateKey){pa.raw}));
    MUST(signal_privatekey_get_public_key(&qb, (SignalConstPointerSignalPrivateKey){pb.raw}));
    signal_privatekey_destroy(pa); signal_privatekey_destroy(pb);

    static const uint8_t alice_id[] = "+15551234567";
    static const uint8_t bob_id[]   = "+15559876543";
    SignalBorrowedBuffer aid = {alice_id, sizeof alice_id - 1};
    SignalBorrowedBuffer bid = {bob_id,   sizeof bob_id   - 1};

    SignalMutPointerSignalFingerprint fp_a = {NULL}, fp_b = {NULL};
    MUST(signal_fingerprint_new(&fp_a, 5200, 0, aid,
             (SignalConstPointerSignalPublicKey){qa.raw}, bid,
             (SignalConstPointerSignalPublicKey){qb.raw}));
    MUST(signal_fingerprint_new(&fp_b, 5200, 0, bid,
             (SignalConstPointerSignalPublicKey){qb.raw}, aid,
             (SignalConstPointerSignalPublicKey){qa.raw}));
    signal_publickey_destroy(qa); signal_publickey_destroy(qb);

    SignalOwnedBuffer scan_b = {0};
    MUST(signal_fingerprint_scannable_encoding(&scan_b,
             (SignalConstPointerSignalFingerprint){fp_b.raw}));

    bool match = false;
    MUST(signal_fingerprint_compare(&match,
             (SignalConstPointerSignalFingerprint){fp_a.raw},
             (SignalBorrowedBuffer){scan_b.base, scan_b.length}));
    if (!match) { fputs("[FAIL] fingerprint compare failed\n", stderr); abort(); }
    signal_free_buffer(scan_b.base, scan_b.length);
    signal_fingerprint_destroy(fp_a); signal_fingerprint_destroy(fp_b);
    printf("Fingerprints                  PASS\n");
}

static void run_test_username(void) {
    uint8_t hash[32];
    MUST(signal_username_hash(hash, "alice.42"));
    SignalOwnedBuffer proof = {0};
    MUST(signal_username_proof(&proof, "alice.42"));
    bool valid = false;
    MUST(signal_username_verify(&valid, hash,
             (SignalBorrowedBuffer){proof.base, proof.length}));
    if (!valid) { fputs("[FAIL] username proof invalid\n", stderr); abort(); }
    signal_free_buffer(proof.base, proof.length);
    printf("Username ZK proof             PASS\n");
}

static void run_test_account_keys(void) {
    SignalMutPointerSignalAccountEntropyPool pool = {NULL};
    MUST(signal_account_entropy_pool_generate(&pool));
    SignalConstPointerSignalAccountEntropyPool cp = {pool.raw};

    const char *s = NULL;
    MUST(signal_account_entropy_pool_as_string(&s, cp));
    printf("  Entropy pool: %.16s…\n", s);
    signal_free_string((char *)s);

    uint8_t svr[32], bk_bytes[32];
    MUST(signal_account_entropy_pool_derive_svr_key(svr, cp));
    MUST(signal_account_entropy_pool_derive_backup_key(bk_bytes, cp));
    signal_account_entropy_pool_destroy(pool);

    if (memcmp(svr, bk_bytes, 32) == 0) {
        fputs("[FAIL] svr_key == backup_key\n", stderr); abort();
    }
    SignalMutPointerSignalBackupKey bk = {NULL};
    MUST(signal_backup_key_from_bytes(&bk, (SignalBorrowedBuffer){bk_bytes, 32}));
    uint8_t media[32];
    MUST(signal_backup_key_derive_media_encryption_key(media,
             (SignalConstPointerSignalBackupKey){bk.raw}));
    signal_backup_key_destroy(bk);
    if (memcmp(bk_bytes, media, 32) == 0) {
        fputs("[FAIL] backup_key == media_key\n", stderr); abort();
    }
    printf("Account entropy pool          PASS\n");
}
*/
import "C"

import "fmt"

func main() {
	C.run_test_ec_keys()
	C.run_test_kyber_keys()
	C.run_test_session()
	C.run_test_group()
	C.run_test_fingerprint()
	C.run_test_username()
	C.run_test_account_keys()
	fmt.Println("\nAll signal_ffi tests PASSED.")
}
