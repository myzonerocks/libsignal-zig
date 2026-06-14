/*
 * examples/cpp/main.cpp — signal_ffi.h round-trip exerciser (C++17)
 *
 * Mirrors examples/c/main.c but uses C++ containers and RAII guards.
 * Compile and run:  make run
 */
#include "../../include/signal_ffi.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <map>
#include <string>
#include <vector>
#include <array>
#include <functional>

/* ── Error checking ───────────────────────────────────────────────────────── */

static void die(SignalFfiError *e, const char *label) {
    const char *msg = nullptr;
    signal_error_get_message(&msg, e);
    fprintf(stderr, "[FAIL] %s: %s\n", label, msg ? msg : "(no message)");
    signal_error_free(e);
    abort();
}
#define MUST(call) do { SignalFfiError *_e = (call); if (_e) die(_e, #call); } while(0)

/* ── Generic key-value store ─────────────────────────────────────────────── */

using KvStore = std::map<std::string, std::vector<uint8_t>>;

static void kv_put(KvStore &s, const std::string &k,
                   const uint8_t *d, size_t l) {
    s[k] = std::vector<uint8_t>(d, d + l);
}
static bool kv_get(const KvStore &s, const std::string &k,
                   uint8_t **d, size_t *l) {
    auto it = s.find(k);
    if (it == s.end()) return false;
    *l = it->second.size();
    *d = static_cast<uint8_t *>(malloc(*l));
    memcpy(*d, it->second.data(), *l);
    return true;
}

/* Build "name:dev" key from a SignalProtocolAddress opaque pointer */
static std::string addr_key(const SignalProtocolAddress *addr) {
    const char *name = nullptr;
    uint32_t dev = 0;
    SignalConstPointerSignalProtocolAddress ca = {addr};
    MUST(signal_address_get_name(&name, ca));
    MUST(signal_address_get_device_id(&dev, ca));
    return std::string(name) + ":" + std::to_string(dev);
}

/* ── Session store ───────────────────────────────────────────────────────── */

static SignalFfiError *sess_load(SignalMutPointerSignalSessionRecord *out,
                                  const SignalProtocolAddress *addr, void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    uint8_t *data; size_t len;
    if (!kv_get(*db, addr_key(addr), &data, &len)) { out->raw = nullptr; return nullptr; }
    SignalBorrowedBuffer buf = {data, len};
    auto *e = signal_session_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *sess_store_fn(const SignalProtocolAddress *addr,
                                      SignalConstPointerSignalSessionRecord rec,
                                      void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    SignalOwnedBuffer b = {};
    auto *e = signal_session_record_serialize(&b, rec);
    if (e) return e;
    kv_put(*db, addr_key(addr), b.base, b.length);
    signal_free_buffer(b.base, b.length); return nullptr;
}
static SignalSessionStore make_sess(KvStore *db) {
    return {db, sess_load, sess_store_fn, nullptr};
}

/* ── Identity store ──────────────────────────────────────────────────────── */

struct IdState {
    uint8_t  priv_bytes[32];
    uint32_t reg_id;
    KvStore  trusted;
};

static SignalFfiError *id_get_kp(SignalMutPointerSignalPublicKey *out_pub,
                                  SignalMutPointerSignalPrivateKey *out_priv,
                                  void *ud) {
    auto *s = static_cast<IdState *>(ud);
    SignalBorrowedBuffer pb = {s->priv_bytes, 32};
    auto *e = signal_privatekey_deserialize(out_priv, pb);
    if (e) return e;
    return signal_privatekey_get_public_key(out_pub,
               {out_priv->raw});
}
static SignalFfiError *id_get_reg(uint32_t *out, void *ud) {
    *out = static_cast<IdState *>(ud)->reg_id; return nullptr;
}
static SignalFfiError *id_save(const SignalProtocolAddress *addr,
                                SignalConstPointerSignalPublicKey key, void *ud) {
    auto *s = static_cast<IdState *>(ud);
    SignalOwnedBuffer b = {};
    auto *e = signal_publickey_serialize(&b, key);
    if (e) return e;
    kv_put(s->trusted, addr_key(addr), b.base, b.length);
    signal_free_buffer(b.base, b.length); return nullptr;
}
static SignalFfiError *id_trusted(bool *out, const SignalProtocolAddress *,
                                   SignalConstPointerSignalPublicKey,
                                   uint32_t, void *) {
    *out = true; return nullptr;
}
static SignalFfiError *id_get(SignalMutPointerSignalPublicKey *out,
                               const SignalProtocolAddress *addr, void *ud) {
    auto *s = static_cast<IdState *>(ud);
    uint8_t *data; size_t len;
    if (!kv_get(s->trusted, addr_key(addr), &data, &len)) {
        out->raw = nullptr; return nullptr;
    }
    SignalBorrowedBuffer buf = {data, len};
    auto *e = signal_publickey_deserialize(out, buf);
    free(data); return e;
}
static SignalIdentityKeyStore make_id(IdState *s) {
    return {s, id_get_kp, id_get_reg, id_save, id_trusted, id_get, nullptr};
}

/* ── Pre-key store ───────────────────────────────────────────────────────── */

static SignalFfiError *pk_load(SignalMutPointerSignalPreKeyRecord *out,
                                uint32_t id, void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    uint8_t *data; size_t len;
    std::string k = std::to_string(id);
    if (!kv_get(*db, k, &data, &len)) { out->raw = nullptr; return nullptr; }
    SignalBorrowedBuffer buf = {data, len};
    auto *e = signal_pre_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *pk_store_fn(uint32_t id,
                                    SignalMutPointerSignalPreKeyRecord rec,
                                    void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    SignalOwnedBuffer b = {};
    auto *e = signal_pre_key_record_serialize(&b,
                   SignalConstPointerSignalPreKeyRecord{rec.raw});
    if (e) return e;
    kv_put(*db, std::to_string(id), b.base, b.length);
    signal_free_buffer(b.base, b.length); return nullptr;
}
static SignalFfiError *pk_remove(uint32_t, void *) { return nullptr; }
static SignalPreKeyStore make_pk(KvStore *db) {
    return {db, pk_load, pk_store_fn, pk_remove, nullptr};
}

/* ── Signed pre-key store ────────────────────────────────────────────────── */

static SignalFfiError *spk_load(SignalMutPointerSignalSignedPreKeyRecord *out,
                                 uint32_t id, void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    uint8_t *data; size_t len;
    if (!kv_get(*db, std::to_string(id), &data, &len)) {
        out->raw = nullptr; return nullptr;
    }
    SignalBorrowedBuffer buf = {data, len};
    auto *e = signal_signed_pre_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *spk_store_fn(uint32_t id,
                                     SignalMutPointerSignalSignedPreKeyRecord rec,
                                     void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    SignalOwnedBuffer b = {};
    auto *e = signal_signed_pre_key_record_serialize(&b,
                   SignalConstPointerSignalSignedPreKeyRecord{rec.raw});
    if (e) return e;
    kv_put(*db, std::to_string(id), b.base, b.length);
    signal_free_buffer(b.base, b.length); return nullptr;
}
static SignalSignedPreKeyStore make_spk(KvStore *db) {
    return {db, spk_load, spk_store_fn, nullptr};
}

/* ── Kyber pre-key store ─────────────────────────────────────────────────── */

static SignalFfiError *kpk_load(SignalMutPointerSignalKyberPreKeyRecord *out,
                                 uint32_t id, void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    uint8_t *data; size_t len;
    if (!kv_get(*db, std::to_string(id), &data, &len)) {
        out->raw = nullptr; return nullptr;
    }
    SignalBorrowedBuffer buf = {data, len};
    auto *e = signal_kyber_pre_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalFfiError *kpk_store_fn(uint32_t id,
                                     SignalMutPointerSignalKyberPreKeyRecord rec,
                                     void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    SignalOwnedBuffer b = {};
    auto *e = signal_kyber_pre_key_record_serialize(&b,
                   SignalConstPointerSignalKyberPreKeyRecord{rec.raw});
    if (e) return e;
    kv_put(*db, std::to_string(id), b.base, b.length);
    signal_free_buffer(b.base, b.length); return nullptr;
}
static SignalFfiError *kpk_mark_used(uint32_t, void *) { return nullptr; }
static SignalKyberPreKeyStore make_kpk(KvStore *db) {
    return {db, kpk_load, kpk_store_fn, kpk_mark_used, nullptr};
}

/* ── Sender key store ────────────────────────────────────────────────────── */

static std::string sk_key(const SignalProtocolAddress *sender,
                           const uint8_t dist_id[16]) {
    char hex[33]; hex[32] = 0;
    for (int i = 0; i < 16; i++) snprintf(hex + 2*i, 3, "%02x", dist_id[i]);
    return addr_key(sender) + ":" + hex;
}
static SignalFfiError *sk_store_fn(const SignalProtocolAddress *sender,
                                    const uint8_t dist_id[16],
                                    SignalConstPointerSignalSenderKeyRecord rec,
                                    void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    SignalOwnedBuffer b = {};
    auto *e = signal_sender_key_record_serialize(&b, rec);
    if (e) return e;
    kv_put(*db, sk_key(sender, dist_id), b.base, b.length);
    signal_free_buffer(b.base, b.length); return nullptr;
}
static SignalFfiError *sk_load_fn(SignalMutPointerSignalSenderKeyRecord *out,
                                   const SignalProtocolAddress *sender,
                                   const uint8_t dist_id[16], void *ud) {
    auto *db = static_cast<KvStore *>(ud);
    uint8_t *data; size_t len;
    if (!kv_get(*db, sk_key(sender, dist_id), &data, &len)) {
        out->raw = nullptr; return nullptr;
    }
    SignalBorrowedBuffer buf = {data, len};
    auto *e = signal_sender_key_record_deserialize(out, buf);
    free(data); return e;
}
static SignalSenderKeyStore make_sk(KvStore *db) {
    return {db, sk_store_fn, sk_load_fn, nullptr};
}

/* ── sign_bytes helper ───────────────────────────────────────────────────── */

static SignalOwnedBuffer sign_bytes(const uint8_t priv32[32],
                                     const uint8_t *data, size_t len) {
    SignalMutPointerSignalPrivateKey pk = {nullptr};
    MUST(signal_privatekey_deserialize(&pk, {priv32, 32}));
    SignalOwnedBuffer sig = {};
    MUST(signal_privatekey_sign(&sig, {pk.raw}, {data, len}));
    signal_privatekey_destroy(pk);
    return sig;
}

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_ec_keys() {
    SignalMutPointerSignalPrivateKey pa = {}, pb = {};
    MUST(signal_privatekey_generate(&pa));
    MUST(signal_privatekey_generate(&pb));

    SignalMutPointerSignalPublicKey qa = {}, qb = {};
    MUST(signal_privatekey_get_public_key(&qa, {pa.raw}));
    MUST(signal_privatekey_get_public_key(&qb, {pb.raw}));

    SignalOwnedBuffer dh_a = {}, dh_b = {};
    MUST(signal_privatekey_agree(&dh_a, {pa.raw}, {qb.raw}));
    MUST(signal_privatekey_agree(&dh_b, {pb.raw}, {qa.raw}));
    if (dh_a.length != 32 || memcmp(dh_a.base, dh_b.base, 32) != 0) {
        fputs("[FAIL] DH secrets differ\n", stderr); abort();
    }
    signal_free_buffer(dh_a.base, dh_a.length);
    signal_free_buffer(dh_b.base, dh_b.length);

    const uint8_t msg[] = "hello signal";
    SignalOwnedBuffer sig = {};
    MUST(signal_privatekey_sign(&sig, {pa.raw}, {msg, sizeof msg - 1}));
    bool ok = false;
    MUST(signal_publickey_verify(&ok, {qa.raw}, {msg, sizeof msg - 1},
                                  {sig.base, sig.length}));
    if (!ok) { fputs("[FAIL] XEdDSA verify failed\n", stderr); abort(); }
    signal_free_buffer(sig.base, sig.length);

    signal_privatekey_destroy(pa); signal_privatekey_destroy(pb);
    signal_publickey_destroy(qa);  signal_publickey_destroy(qb);
    printf("EC + XEdDSA                   PASS\n");
}

static void test_kyber_keys() {
    SignalMutPointerSignalKyberKeyPair kp = {};
    MUST(signal_kyber_key_pair_generate(&kp));

    SignalMutPointerSignalKyberPublicKey pub = {};
    SignalMutPointerSignalKyberSecretKey sec = {};
    MUST(signal_kyber_key_pair_get_public_key(&pub, {kp.raw}));
    MUST(signal_kyber_key_pair_get_secret_key(&sec, {kp.raw}));

    SignalOwnedBuffer pub_b = {}, sec_b = {};
    MUST(signal_kyber_public_key_serialize(&pub_b, {pub.raw}));
    MUST(signal_kyber_secret_key_serialize(&sec_b, {sec.raw}));

    if (pub_b.length != 1568 || sec_b.length != 3168) {
        fprintf(stderr, "[FAIL] Kyber sizes: pub=%zu sec=%zu\n",
                pub_b.length, sec_b.length); abort();
    }
    signal_free_buffer(pub_b.base, pub_b.length);
    signal_free_buffer(sec_b.base, sec_b.length);
    signal_kyber_key_pair_destroy(kp);
    signal_kyber_public_key_destroy(pub);
    signal_kyber_secret_key_destroy(sec);
    printf("ML-KEM-1024 (Kyber)           PASS\n");
}

struct BobKeys {
    uint8_t  id_priv[32];
    uint32_t reg_id;
    uint32_t opk_id, spk_id, kpk_id;
};

static void setup_bob(BobKeys *out, KvStore *pk_db, KvStore *spk_db, KvStore *kpk_db) {
    SignalMutPointerSignalPrivateKey id_priv = {};
    MUST(signal_privatekey_generate(&id_priv));
    SignalOwnedBuffer id_bytes = {};
    MUST(signal_privatekey_serialize(&id_bytes, {id_priv.raw}));
    memcpy(out->id_priv, id_bytes.base, 32);
    signal_free_buffer(id_bytes.base, id_bytes.length);
    out->reg_id = 2002;

    /* one-time pre-key */
    out->opk_id = 1;
    SignalMutPointerSignalPrivateKey opk_priv = {};
    MUST(signal_privatekey_generate(&opk_priv));
    SignalMutPointerSignalPublicKey opk_pub = {};
    MUST(signal_privatekey_get_public_key(&opk_pub, {opk_priv.raw}));
    SignalMutPointerSignalPreKeyRecord opk_rec = {};
    MUST(signal_pre_key_record_new(&opk_rec, out->opk_id, {opk_pub.raw}, {opk_priv.raw}));
    signal_privatekey_destroy(opk_priv); signal_publickey_destroy(opk_pub);
    MUST(pk_store_fn(out->opk_id, opk_rec, pk_db));
    signal_pre_key_record_destroy(opk_rec);

    /* signed pre-key */
    out->spk_id = 1;
    SignalMutPointerSignalPrivateKey spk_priv = {};
    MUST(signal_privatekey_generate(&spk_priv));
    SignalMutPointerSignalPublicKey spk_pub = {};
    MUST(signal_privatekey_get_public_key(&spk_pub, {spk_priv.raw}));
    SignalOwnedBuffer spk_pub_b = {};
    MUST(signal_publickey_serialize(&spk_pub_b, {spk_pub.raw}));
    SignalOwnedBuffer spk_sig = sign_bytes(out->id_priv, spk_pub_b.base, spk_pub_b.length);
    signal_free_buffer(spk_pub_b.base, spk_pub_b.length);
    SignalMutPointerSignalSignedPreKeyRecord spk_rec = {};
    MUST(signal_signed_pre_key_record_new(&spk_rec, out->spk_id, 1700000000,
             {spk_pub.raw}, {spk_priv.raw}, {spk_sig.base, spk_sig.length}));
    signal_free_buffer(spk_sig.base, spk_sig.length);
    signal_privatekey_destroy(spk_priv); signal_publickey_destroy(spk_pub);
    MUST(spk_store_fn(out->spk_id, spk_rec, spk_db));
    signal_signed_pre_key_record_destroy(spk_rec);

    /* kyber pre-key */
    out->kpk_id = 1;
    SignalMutPointerSignalKyberKeyPair kpk = {};
    MUST(signal_kyber_key_pair_generate(&kpk));
    SignalMutPointerSignalKyberPublicKey kpk_pub = {};
    MUST(signal_kyber_key_pair_get_public_key(&kpk_pub, {kpk.raw}));
    SignalOwnedBuffer kpk_pub_b = {};
    MUST(signal_kyber_public_key_serialize(&kpk_pub_b, {kpk_pub.raw}));
    SignalOwnedBuffer kpk_sig = sign_bytes(out->id_priv, kpk_pub_b.base, kpk_pub_b.length);
    signal_free_buffer(kpk_pub_b.base, kpk_pub_b.length);
    signal_kyber_public_key_destroy(kpk_pub);
    SignalMutPointerSignalKyberPreKeyRecord kpk_rec = {};
    MUST(signal_kyber_pre_key_record_new(&kpk_rec, out->kpk_id, 1700000000,
             {kpk.raw}, {kpk_sig.base, kpk_sig.length}));
    signal_free_buffer(kpk_sig.base, kpk_sig.length);
    signal_kyber_key_pair_destroy(kpk);
    MUST(kpk_store_fn(out->kpk_id, kpk_rec, kpk_db));
    signal_kyber_pre_key_record_destroy(kpk_rec);

    signal_privatekey_destroy(id_priv);
}

static void test_session() {
    /* Alice identity */
    uint8_t alice_id_priv[32];
    {
        SignalMutPointerSignalPrivateKey p = {};
        MUST(signal_privatekey_generate(&p));
        SignalOwnedBuffer b = {};
        MUST(signal_privatekey_serialize(&b, {p.raw}));
        memcpy(alice_id_priv, b.base, 32);
        signal_free_buffer(b.base, b.length);
        signal_privatekey_destroy(p);
    }

    KvStore bob_sess, bob_pk, bob_spk, bob_kpk;
    BobKeys bob; setup_bob(&bob, &bob_pk, &bob_spk, &bob_kpk);

    /* reload public components for bundle */
    SignalMutPointerSignalPreKeyRecord opk_r = {};
    MUST(pk_load(&opk_r, bob.opk_id, &bob_pk));
    SignalMutPointerSignalPublicKey opk_pub = {};
    MUST(signal_pre_key_record_get_public_key(&opk_pub, {opk_r.raw}));
    signal_pre_key_record_destroy(opk_r);

    SignalMutPointerSignalSignedPreKeyRecord spk_r = {};
    MUST(spk_load(&spk_r, bob.spk_id, &bob_spk));
    SignalMutPointerSignalPublicKey spk_pub = {};
    MUST(signal_signed_pre_key_record_get_public_key(&spk_pub, {spk_r.raw}));
    SignalOwnedBuffer spk_sig = {};
    MUST(signal_signed_pre_key_record_get_signature(&spk_sig, {spk_r.raw}));
    signal_signed_pre_key_record_destroy(spk_r);

    SignalMutPointerSignalKyberPreKeyRecord kpk_r = {};
    MUST(kpk_load(&kpk_r, bob.kpk_id, &bob_kpk));
    SignalMutPointerSignalKyberPublicKey kpk_pub = {};
    MUST(signal_kyber_pre_key_record_get_public_key(&kpk_pub, {kpk_r.raw}));
    SignalOwnedBuffer kpk_sig = {};
    MUST(signal_kyber_pre_key_record_get_signature(&kpk_sig, {kpk_r.raw}));
    signal_kyber_pre_key_record_destroy(kpk_r);

    SignalMutPointerSignalPrivateKey bob_id_priv_obj = {};
    MUST(signal_privatekey_deserialize(&bob_id_priv_obj, {bob.id_priv, 32}));
    SignalMutPointerSignalPublicKey bob_id_pub = {};
    MUST(signal_privatekey_get_public_key(&bob_id_pub, {bob_id_priv_obj.raw}));
    signal_privatekey_destroy(bob_id_priv_obj);

    SignalMutPointerSignalPreKeyBundle bundle = {};
    MUST(signal_pre_key_bundle_new(&bundle,
             bob.reg_id, 1,
             bob.opk_id, true, {opk_pub.raw},
             bob.spk_id, {spk_pub.raw},
             {spk_sig.base, spk_sig.length},
             {bob_id_pub.raw},
             bob.kpk_id, true, {kpk_pub.raw},
             {kpk_sig.base, kpk_sig.length}));
    signal_publickey_destroy(opk_pub); signal_publickey_destroy(spk_pub);
    signal_free_buffer(spk_sig.base, spk_sig.length);
    signal_kyber_public_key_destroy(kpk_pub);
    signal_free_buffer(kpk_sig.base, kpk_sig.length);
    signal_publickey_destroy(bob_id_pub);

    KvStore alice_sess, alice_pk, alice_spk, alice_kpk;
    IdState alice_id = {}, bob_id = {};
    memcpy(alice_id.priv_bytes, alice_id_priv, 32); alice_id.reg_id = 1001;
    memcpy(bob_id.priv_bytes,   bob.id_priv,   32); bob_id.reg_id   = bob.reg_id;

    SignalMutPointerSignalProtocolAddress bob_addr = {}, alice_addr = {};
    MUST(signal_address_new(&bob_addr, "bob", 1));
    MUST(signal_address_new(&alice_addr, "alice", 1));

    auto a_ss  = make_sess(&alice_sess);
    auto a_is  = make_id(&alice_id);
    auto a_pks = make_pk(&alice_pk);
    auto a_sks = make_spk(&alice_spk);
    auto a_kks = make_kpk(&alice_kpk);

    MUST(signal_process_prekey_bundle(
             {bundle.raw}, {bob_addr.raw},
             &a_ss, &a_is, &a_pks, &a_sks, &a_kks));
    signal_pre_key_bundle_destroy(bundle);

    const uint8_t pt1[] = "hello bob";
    SignalMutPointerSignalCiphertextMessage ct1 = {};
    MUST(signal_encrypt_message(&ct1, {pt1, sizeof pt1 - 1}, {bob_addr.raw},
             &a_ss, &a_is, &a_pks, &a_sks));
    uint8_t ct1_type = 0;
    MUST(signal_ciphertext_message_type(&ct1_type, {ct1.raw}));
    SignalOwnedBuffer ct1_b = {};
    MUST(signal_ciphertext_message_serialize(&ct1_b, {ct1.raw}));
    signal_ciphertext_message_destroy(ct1);
    if (ct1_type != 3) {
        fprintf(stderr, "[FAIL] expected PreKey msg, got %d\n", ct1_type); abort();
    }

    SignalMutPointerSignalPreKeySignalMessage pksm = {};
    MUST(signal_pre_key_signal_message_deserialize(&pksm, {ct1_b.base, ct1_b.length}));
    signal_free_buffer(ct1_b.base, ct1_b.length);

    auto b_ss  = make_sess(&bob_sess);
    auto b_is  = make_id(&bob_id);
    auto b_pks = make_pk(&bob_pk);
    auto b_sks = make_spk(&bob_spk);
    auto b_kks = make_kpk(&bob_kpk);

    SignalOwnedBuffer dec1 = {};
    MUST(signal_decrypt_pre_key_message(&dec1, {pksm.raw}, {alice_addr.raw},
             &b_ss, &b_is, &b_pks, &b_sks, &b_kks));
    signal_pre_key_signal_message_destroy(pksm);

    if (dec1.length != sizeof pt1 - 1 || memcmp(dec1.base, pt1, dec1.length) != 0) {
        fputs("[FAIL] pre-key plaintext mismatch\n", stderr); abort();
    }
    signal_free_buffer(dec1.base, dec1.length);

    const uint8_t pt2[] = "hey alice";
    SignalMutPointerSignalCiphertextMessage ct2 = {};
    MUST(signal_encrypt_message(&ct2, {pt2, sizeof pt2 - 1}, {alice_addr.raw},
             &b_ss, &b_is, &b_pks, &b_sks));
    SignalOwnedBuffer ct2_b = {};
    MUST(signal_ciphertext_message_serialize(&ct2_b, {ct2.raw}));
    signal_ciphertext_message_destroy(ct2);

    SignalMutPointerSignalMessage whisper = {};
    MUST(signal_message_deserialize(&whisper, {ct2_b.base, ct2_b.length}));
    signal_free_buffer(ct2_b.base, ct2_b.length);

    SignalOwnedBuffer dec2 = {};
    MUST(signal_decrypt_message(&dec2, {whisper.raw}, {bob_addr.raw}, &a_ss, &a_is));
    signal_message_destroy(whisper);

    if (dec2.length != sizeof pt2 - 1 || memcmp(dec2.base, pt2, dec2.length) != 0) {
        fputs("[FAIL] whisper plaintext mismatch\n", stderr); abort();
    }
    signal_free_buffer(dec2.base, dec2.length);

    signal_address_destroy(bob_addr); signal_address_destroy(alice_addr);
    printf("X3DH + PQXDH + Double Ratchet PASS\n");
}

static void test_group() {
    static const uint8_t dist_id[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };
    KvStore alice_sk, bob_sk;
    auto a_store = make_sk(&alice_sk);
    auto b_store = make_sk(&bob_sk);

    SignalMutPointerSignalProtocolAddress alice_addr = {};
    MUST(signal_address_new(&alice_addr, "alice", 1));
    SignalConstPointerSignalProtocolAddress ca = {alice_addr.raw};

    SignalMutPointerSignalSenderKeyDistributionMessage skdm = {};
    MUST(signal_sender_key_distribution_message_create(&skdm, ca, {dist_id, 16}, &a_store));
    MUST(signal_process_sender_key_distribution_message(ca, {skdm.raw}, &b_store));
    signal_sender_key_distribution_message_destroy(skdm);

    const uint8_t msg[] = "group hello";
    SignalOwnedBuffer enc = {};
    MUST(signal_group_encrypt_message(&enc, ca, {dist_id, 16}, {msg, sizeof msg - 1}, &a_store));

    SignalOwnedBuffer dec = {};
    MUST(signal_group_decrypt_message(&dec, ca, {dist_id, 16}, {enc.base, enc.length}, &b_store));
    signal_free_buffer(enc.base, enc.length);

    if (dec.length != sizeof msg - 1 || memcmp(dec.base, msg, dec.length) != 0) {
        fputs("[FAIL] group plaintext mismatch\n", stderr); abort();
    }
    signal_free_buffer(dec.base, dec.length);
    signal_address_destroy(alice_addr);
    printf("Sender Keys (group)           PASS\n");
}

static void test_fingerprint() {
    SignalMutPointerSignalPrivateKey pa = {}, pb = {};
    MUST(signal_privatekey_generate(&pa));
    MUST(signal_privatekey_generate(&pb));
    SignalMutPointerSignalPublicKey qa = {}, qb = {};
    MUST(signal_privatekey_get_public_key(&qa, {pa.raw}));
    MUST(signal_privatekey_get_public_key(&qb, {pb.raw}));
    signal_privatekey_destroy(pa); signal_privatekey_destroy(pb);

    static const uint8_t alice_id[] = "+15551234567";
    static const uint8_t bob_id[]   = "+15559876543";
    SignalBorrowedBuffer aid = {alice_id, sizeof alice_id - 1};
    SignalBorrowedBuffer bid = {bob_id,   sizeof bob_id   - 1};

    SignalMutPointerSignalFingerprint fp_a = {}, fp_b = {};
    MUST(signal_fingerprint_new(&fp_a, 5200, 0, aid, {qa.raw}, bid, {qb.raw}));
    MUST(signal_fingerprint_new(&fp_b, 5200, 0, bid, {qb.raw}, aid, {qa.raw}));
    signal_publickey_destroy(qa); signal_publickey_destroy(qb);

    SignalOwnedBuffer scan_b = {};
    MUST(signal_fingerprint_scannable_encoding(&scan_b, {fp_b.raw}));

    bool match = false;
    MUST(signal_fingerprint_compare(&match, {fp_a.raw}, {scan_b.base, scan_b.length}));
    if (!match) { fputs("[FAIL] fingerprint compare failed\n", stderr); abort(); }
    signal_free_buffer(scan_b.base, scan_b.length);
    signal_fingerprint_destroy(fp_a); signal_fingerprint_destroy(fp_b);
    printf("Fingerprints                  PASS\n");
}

static void test_username() {
    uint8_t hash[32];
    MUST(signal_username_hash(hash, "alice.42"));
    SignalOwnedBuffer proof = {};
    MUST(signal_username_proof(&proof, "alice.42"));
    bool valid = false;
    MUST(signal_username_verify(&valid, hash, {proof.base, proof.length}));
    if (!valid) { fputs("[FAIL] username proof invalid\n", stderr); abort(); }
    signal_free_buffer(proof.base, proof.length);
    printf("Username ZK proof             PASS\n");
}

static void test_account_keys() {
    SignalMutPointerSignalAccountEntropyPool pool = {};
    MUST(signal_account_entropy_pool_generate(&pool));
    SignalConstPointerSignalAccountEntropyPool cp = {pool.raw};

    const char *s = nullptr;
    MUST(signal_account_entropy_pool_as_string(&s, cp));
    printf("  Entropy pool: %.16s…\n", s);
    signal_free_string(const_cast<char *>(s));

    uint8_t svr[32], bk_bytes[32];
    MUST(signal_account_entropy_pool_derive_svr_key(svr, cp));
    MUST(signal_account_entropy_pool_derive_backup_key(bk_bytes, cp));
    signal_account_entropy_pool_destroy(pool);

    if (memcmp(svr, bk_bytes, 32) == 0) {
        fputs("[FAIL] svr_key == backup_key\n", stderr); abort();
    }
    SignalMutPointerSignalBackupKey bk = {};
    MUST(signal_backup_key_from_bytes(&bk, {bk_bytes, 32}));
    uint8_t media[32];
    MUST(signal_backup_key_derive_media_encryption_key(media, {bk.raw}));
    signal_backup_key_destroy(bk);
    if (memcmp(bk_bytes, media, 32) == 0) {
        fputs("[FAIL] backup_key == media_key\n", stderr); abort();
    }
    printf("Account entropy pool          PASS\n");
}

int main() {
    test_ec_keys();
    test_kyber_keys();
    test_session();
    test_group();
    test_fingerprint();
    test_username();
    test_account_keys();
    return 0;
}
