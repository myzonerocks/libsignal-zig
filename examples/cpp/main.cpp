// Every C FFI function exported by libsignal-zig.
// Each section exercises a real-world roundtrip: generate → use → verify.
// Compile and run with: make && ./signal_example
#include "../../include/libsignal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <map>
#include <string>
#include <vector>
#include <array>
#include <utility>

static void die(const char *label, int rc) {
    fprintf(stderr, "[FAIL] %s: error %d\n", label, rc);
    exit(1);
}

static void must(int rc, const char *label) {
    if (rc != 0) die(label, rc);
}

// ── In-memory stores ─────────────────────────────────────────────────────────

struct SessionDB {
    std::map<std::pair<std::string,uint32_t>, std::vector<uint8_t>> rows;
};

static int sess_load(void *ud, const char *name, uint32_t dev,
                     uint8_t **out, size_t *out_len) {
    auto *db = static_cast<SessionDB*>(ud);
    auto it = db->rows.find({name, dev});
    if (it == db->rows.end()) return LIBSIGNAL_ERR_NOT_FOUND;
    *out_len = it->second.size();
    *out = static_cast<uint8_t*>(malloc(*out_len));
    memcpy(*out, it->second.data(), *out_len);
    return LIBSIGNAL_OK;
}
static int sess_store(void *ud, const char *name, uint32_t dev,
                      const uint8_t *data, size_t len) {
    auto *db = static_cast<SessionDB*>(ud);
    db->rows[{name, dev}] = std::vector<uint8_t>(data, data + len);
    return LIBSIGNAL_OK;
}

struct IdentityState {
    uint8_t  pub[33];
    uint8_t  priv[32];
    uint32_t reg_id;
};

static int id_get_kp(void *ud, uint8_t pub[33], uint8_t priv[32]) {
    auto *s = static_cast<IdentityState*>(ud);
    memcpy(pub, s->pub, 33); memcpy(priv, s->priv, 32); return 0;
}
static int id_get_reg(void *ud, uint32_t *out) {
    *out = static_cast<IdentityState*>(ud)->reg_id; return 0;
}
static int id_save(void *ud, const char *, uint32_t, const uint8_t *) {
    (void)ud; return 0;
}
static int id_trusted(void *, const char *, uint32_t, const uint8_t *, int) {
    return 1;
}

struct PreKeyState { uint32_t id; uint8_t pub[33]; uint8_t priv[32]; };

static int pk_load(void *ud, uint32_t id, uint8_t pub[33], uint8_t priv[32]) {
    auto *s = static_cast<PreKeyState*>(ud);
    if (id != s->id) return LIBSIGNAL_ERR_NOT_FOUND;
    memcpy(pub, s->pub, 33); memcpy(priv, s->priv, 32); return 0;
}
static int pk_remove(void *, uint32_t) { return 0; }

struct SignedPreKeyState {
    uint32_t id; uint8_t pub[33]; uint8_t priv[32]; uint8_t sig[64];
};

static int spk_load(void *ud, uint32_t id, uint8_t pub[33], uint8_t priv[32],
                    uint8_t sig[64], uint64_t *ts) {
    auto *s = static_cast<SignedPreKeyState*>(ud);
    if (id != s->id) return LIBSIGNAL_ERR_NOT_FOUND;
    memcpy(pub, s->pub, 33); memcpy(priv, s->priv, 32); memcpy(sig, s->sig, 64);
    *ts = 1700000000; return 0;
}

struct SKKey {
    std::string name; uint32_t dev; std::array<uint8_t,16> dist;
    bool operator<(const SKKey &o) const {
        if (name != o.name) return name < o.name;
        if (dev != o.dev) return dev < o.dev;
        return dist < o.dist;
    }
};

struct SenderKeyDB {
    std::map<SKKey, std::vector<uint8_t>> rows;
};

static int sk_store(void *ud, const char *name, uint32_t dev,
                    const uint8_t dist[16], const uint8_t *data, size_t len) {
    auto *db = static_cast<SenderKeyDB*>(ud);
    SKKey k; k.name = name; k.dev = dev; memcpy(k.dist.data(), dist, 16);
    db->rows[k] = std::vector<uint8_t>(data, data + len);
    return LIBSIGNAL_OK;
}
static int sk_load(void *ud, const char *name, uint32_t dev,
                   const uint8_t dist[16], uint8_t **out, size_t *out_len) {
    auto *db = static_cast<SenderKeyDB*>(ud);
    SKKey k; k.name = name; k.dev = dev; memcpy(k.dist.data(), dist, 16);
    auto it = db->rows.find(k);
    if (it == db->rows.end()) return LIBSIGNAL_ERR_NOT_FOUND;
    *out_len = it->second.size();
    *out = static_cast<uint8_t*>(malloc(*out_len));
    memcpy(*out, it->second.data(), *out_len);
    return LIBSIGNAL_OK;
}

// ── Store builder helpers ─────────────────────────────────────────────────────

static libsignal_session_store_t make_sess(SessionDB *db) {
    libsignal_session_store_t s;
    s.ud = db; s.load = sess_load; s.store = sess_store; return s;
}
static libsignal_identity_store_t make_id(IdentityState *s) {
    libsignal_identity_store_t st;
    st.ud = s; st.get_keypair = id_get_kp; st.get_registration_id = id_get_reg;
    st.save_identity = id_save; st.is_trusted = id_trusted; return st;
}
static libsignal_pre_key_store_t make_pk(PreKeyState *s) {
    libsignal_pre_key_store_t st;
    st.ud = s; st.load = pk_load; st.remove = pk_remove; return st;
}
static libsignal_signed_pre_key_store_t make_spk(SignedPreKeyState *s) {
    libsignal_signed_pre_key_store_t st;
    st.ud = s; st.load = spk_load; return st;
}
static libsignal_sender_key_store_t make_sk(SenderKeyDB *db) {
    libsignal_sender_key_store_t s;
    s.ud = db; s.store = sk_store; s.load = sk_load; return s;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

static void test_ec() {
    uint8_t pub_a[33], priv_a[32], pub_b[33], priv_b[32];
    must(libsignal_ec_keypair_generate(pub_a, priv_a), "ec_generate_a");
    must(libsignal_ec_keypair_generate(pub_b, priv_b), "ec_generate_b");

    uint8_t shared_a[32], shared_b[32];
    must(libsignal_ec_dh(pub_b, priv_a, shared_a), "ec_dh_a");
    must(libsignal_ec_dh(pub_a, priv_b, shared_b), "ec_dh_b");
    if (memcmp(shared_a, shared_b, 32) != 0) die("ec_dh_match", -1);

    const uint8_t msg[] = "hello signal";
    uint8_t sig[64];
    must(libsignal_xeddsa_sign(priv_a, msg, sizeof(msg)-1, sig), "xeddsa_sign");
    must(libsignal_xeddsa_verify(pub_a, msg, sizeof(msg)-1, sig), "xeddsa_verify");

    printf("EC + XEdDSA                   PASS\n");
}

static void test_kyber() {
    uint8_t pk[LIBSIGNAL_KYBER1024_PK_LEN], sk[LIBSIGNAL_KYBER1024_SK_LEN];
    must(libsignal_kyber1024_keypair_generate(pk, sk), "kyber_keygen");

    uint8_t ct[LIBSIGNAL_KYBER1024_CT_LEN], ss_enc[LIBSIGNAL_KYBER1024_SS_LEN];
    must(libsignal_kyber1024_encaps(pk, ct, ss_enc), "kyber_encaps");

    uint8_t ss_dec[LIBSIGNAL_KYBER1024_SS_LEN];
    must(libsignal_kyber1024_decaps(sk, ct, ss_dec), "kyber_decaps");
    if (memcmp(ss_enc, ss_dec, 32) != 0) die("kyber_ss_match", -1);

    printf("ML-KEM-1024 (Kyber)           PASS\n");
}

static void test_session() {
    // Alice identity + stores
    IdentityState alice_id;
    must(libsignal_ec_keypair_generate(alice_id.pub, alice_id.priv), "alice_id");
    alice_id.reg_id = 1001;
    SessionDB alice_sess_db, bob_sess_db;
    PreKeyState alice_pk = {}; alice_pk.id = 0;
    SignedPreKeyState alice_spk = {}; alice_spk.id = 0;

    // Bob identity + pre-keys
    IdentityState bob_id;
    must(libsignal_ec_keypair_generate(bob_id.pub, bob_id.priv), "bob_id");
    bob_id.reg_id = 2002;

    PreKeyState bob_pk; bob_pk.id = 1;
    must(libsignal_ec_keypair_generate(bob_pk.pub, bob_pk.priv), "bob_opk");

    SignedPreKeyState bob_spk; bob_spk.id = 1;
    must(libsignal_ec_keypair_generate(bob_spk.pub, bob_spk.priv), "bob_spk");
    must(libsignal_xeddsa_sign(bob_id.priv, bob_spk.pub, 33, bob_spk.sig), "bob_spk_sig");

    // Alice processes Bob's bundle
    libsignal_ctx_t *alice_ctx = libsignal_ctx_new(
        "bob", 1,
        make_sess(&alice_sess_db), make_id(&alice_id),
        make_pk(&alice_pk), make_spk(&alice_spk), nullptr);
    if (!alice_ctx) die("alice_ctx_new", -7);

    must(libsignal_process_prekey_bundle(alice_ctx, bob_id.reg_id,
        bob_pk.id, bob_pk.pub,
        bob_spk.id, bob_spk.pub, bob_spk.sig,
        bob_id.pub,
        0, nullptr, nullptr), "process_bundle");

    // Alice encrypts first message (PreKey)
    uint8_t *ct = nullptr; size_t ct_len = 0; int msg_type = 0;
    must(libsignal_encrypt(alice_ctx, (const uint8_t*)"hello bob", 9,
        &ct, &ct_len, &msg_type), "encrypt_1");
    if (msg_type != LIBSIGNAL_MSG_PREKEY) die("msg_type_prekey", msg_type);

    // Bob decrypts
    libsignal_ctx_t *bob_ctx = libsignal_ctx_new(
        "alice", 1,
        make_sess(&bob_sess_db), make_id(&bob_id),
        make_pk(&bob_pk), make_spk(&bob_spk), nullptr);
    if (!bob_ctx) die("bob_ctx_new", -7);

    uint8_t *pt = nullptr; size_t pt_len = 0;
    must(libsignal_decrypt_prekey(bob_ctx, ct, ct_len, &pt, &pt_len), "decrypt_prekey");
    if (pt_len != 9 || memcmp(pt, "hello bob", 9) != 0) die("plaintext_match", -1);
    free(ct); free(pt);

    // Bob replies (whisper)
    uint8_t *ct2 = nullptr; size_t ct2_len = 0; int mt2 = 0;
    must(libsignal_encrypt(bob_ctx, (const uint8_t*)"hey alice", 9,
        &ct2, &ct2_len, &mt2), "encrypt_2");

    uint8_t *pt2 = nullptr; size_t pt2_len = 0;
    must(libsignal_decrypt(alice_ctx, ct2, ct2_len, &pt2, &pt2_len), "decrypt_whisper");
    if (pt2_len != 9 || memcmp(pt2, "hey alice", 9) != 0) die("plaintext2_match", -1);
    free(ct2); free(pt2);

    libsignal_ctx_free(alice_ctx);
    libsignal_ctx_free(bob_ctx);
    printf("X3DH + Double Ratchet         PASS\n");
}

static void test_group() {
    const uint8_t dist_id[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };

    SenderKeyDB alice_skdb, bob_skdb;

    // Alice creates the sender key session and gets the SKDM
    uint8_t *skdm = nullptr; size_t skdm_len = 0;
    must(libsignal_group_create_session(
        "alice", 1, dist_id, make_sk(&alice_skdb),
        &skdm, &skdm_len), "group_create");

    // Bob processes the SKDM
    must(libsignal_group_process_session(
        "alice", 1, skdm, skdm_len, make_sk(&bob_skdb)), "group_process");
    free(skdm);

    // Alice encrypts a group message
    uint8_t *ct = nullptr; size_t ct_len = 0;
    must(libsignal_group_encrypt(
        "alice", 1, dist_id,
        (const uint8_t*)"group hello", 11,
        make_sk(&alice_skdb), &ct, &ct_len), "group_encrypt");

    // Bob decrypts it
    uint8_t *pt = nullptr; size_t pt_len = 0;
    must(libsignal_group_decrypt(
        "alice", 1, dist_id,
        ct, ct_len, make_sk(&bob_skdb), &pt, &pt_len), "group_decrypt");
    if (pt_len != 11 || memcmp(pt, "group hello", 11) != 0) die("group_plaintext", -1);
    free(ct); free(pt);

    printf("Sender Keys (group)           PASS\n");
}

static void test_sealed_sender_v1() {
    // Trust root + server cert
    uint8_t trust_pub[33], trust_priv[32];
    must(libsignal_ec_keypair_generate(trust_pub, trust_priv), "trust_root");

    uint8_t server_pub[33], server_priv[32];
    must(libsignal_ec_keypair_generate(server_pub, server_priv), "server_kp");

    uint8_t *srv_cert = nullptr; size_t srv_cert_len = 0;
    must(libsignal_server_cert_serialize(1, server_pub, trust_priv,
        &srv_cert, &srv_cert_len), "server_cert");

    // Recipient key pair
    uint8_t recv_pub[33], recv_priv[32];
    must(libsignal_ec_keypair_generate(recv_pub, recv_priv), "recv_kp");

    // Sender cert
    uint8_t sender_pub[33], sender_priv[32];
    must(libsignal_ec_keypair_generate(sender_pub, sender_priv), "sender_kp");

    uint8_t *snd_cert = nullptr; size_t snd_cert_len = 0;
    must(libsignal_sender_cert_serialize(
        "alice-uuid", "+15551234567", 1,
        sender_pub, 9999999999ULL,
        srv_cert, srv_cert_len, server_priv,
        &snd_cert, &snd_cert_len), "sender_cert");
    free(srv_cert);

    // Encrypt
    const uint8_t msg[] = "sealed v1 message";
    uint8_t *envelope = nullptr; size_t env_len = 0;
    must(libsignal_sealed_sender_encrypt(
        recv_pub, snd_cert, snd_cert_len,
        1, 0, nullptr,
        msg, sizeof(msg)-1,
        &envelope, &env_len), "ss_v1_encrypt");
    free(snd_cert);

    // Decrypt
    uint8_t *uuid_out = nullptr; size_t uuid_len = 0;
    uint8_t *e164_out = nullptr; size_t e164_len = 0;
    uint32_t dev_id_out = 0;
    uint8_t ctype_out = 0;
    uint8_t *contents_out = nullptr; size_t contents_len = 0;

    must(libsignal_sealed_sender_decrypt(
        envelope, env_len, recv_priv,
        &uuid_out, &uuid_len,
        &e164_out, &e164_len,
        &dev_id_out, &ctype_out,
        &contents_out, &contents_len), "ss_v1_decrypt");
    free(envelope);

    if (memcmp(uuid_out, "alice-uuid", uuid_len) != 0) die("uuid_match", -1);
    if (contents_len != sizeof(msg)-1 || memcmp(contents_out, msg, contents_len) != 0)
        die("ss_v1_contents", -1);

    free(uuid_out); free(e164_out); free(contents_out);
    printf("Sealed Sender V1              PASS\n");
}

static void test_sealed_sender_v2() {
    // Sender ephemeral key
    uint8_t sender_pub[33], sender_priv[32];
    must(libsignal_ec_keypair_generate(sender_pub, sender_priv), "ss2_sender");

    // Recipient
    uint8_t recv_pub[33], recv_priv[32];
    must(libsignal_ec_keypair_generate(recv_pub, recv_priv), "ss2_recv");

    libsignal_sealed_sender_v2_recipient_t recip;
    recip.service_id_fixed[0] = 0x00; // ACI
    // fill remaining 16 bytes as a UUID
    for (int i = 1; i < 17; i++) recip.service_id_fixed[i] = (uint8_t)i;
    recip.device_id = 1;
    memcpy(recip.identity_pub, recv_pub, 33);

    const uint8_t msg[] = "sealed v2 message";
    uint8_t *sent = nullptr; size_t sent_len = 0;
    must(libsignal_sealed_sender_encrypt_v2(
        msg, sizeof(msg)-1,
        sender_priv, sender_pub,
        &recip, 1,
        nullptr, 0,
        &sent, &sent_len), "ss2_encrypt");

    // Server dispatch
    uint8_t *received = nullptr; size_t recv_len = 0;
    must(libsignal_sealed_sender_v2_dispatch(
        sent, sent_len,
        recip.service_id_fixed, recip.device_id,
        &received, &recv_len), "ss2_dispatch");
    free(sent);

    // Recipient decrypts
    uint8_t *pt = nullptr; size_t pt_len = 0;
    must(libsignal_sealed_sender_decrypt_v2(
        received, recv_len,
        recv_priv, recv_pub,
        sender_pub,
        &pt, &pt_len), "ss2_decrypt");
    free(received);

    if (pt_len != sizeof(msg)-1 || memcmp(pt, msg, pt_len) != 0) die("ss2_contents", -1);
    free(pt);
    printf("Sealed Sender V2              PASS\n");
}

static void test_fingerprint() {
    uint8_t a_pub[33], a_priv[32], b_pub[33], b_priv[32];
    must(libsignal_ec_keypair_generate(a_pub, a_priv), "fp_a");
    must(libsignal_ec_keypair_generate(b_pub, b_priv), "fp_b");

    const uint8_t alice_id[] = "+15551234567";
    const uint8_t bob_id[]   = "+15559876543";

    uint8_t disp_a[60], disp_b[60];
    uint8_t *scan_a = nullptr; size_t scan_a_len = 0;
    uint8_t *scan_b = nullptr; size_t scan_b_len = 0;

    must(libsignal_fingerprint_compute(
        a_pub, alice_id, sizeof(alice_id)-1,
        b_pub, bob_id,   sizeof(bob_id)-1,
        disp_a, &scan_a, &scan_a_len), "fp_compute_a");

    must(libsignal_fingerprint_compute(
        b_pub, bob_id,   sizeof(bob_id)-1,
        a_pub, alice_id, sizeof(alice_id)-1,
        disp_b, &scan_b, &scan_b_len), "fp_compute_b");

    int match = 0;
    must(libsignal_fingerprint_compare(
        scan_a, scan_a_len, scan_b, scan_b_len, &match), "fp_compare");
    if (!match) die("fp_match", -1);

    free(scan_a); free(scan_b);
    printf("Fingerprints                  PASS\n");
}

static void test_username() {
    const char *username = "alice.42";

    uint8_t hash[32];
    must(libsignal_username_hash(username, hash), "username_hash");

    uint8_t randomness[32];
    // fill with deterministic bytes for the test
    for (int i = 0; i < 32; i++) randomness[i] = (uint8_t)(i * 7 + 3);

    uint8_t proof[128];
    must(libsignal_username_proof(username, randomness, proof), "username_proof");

    int valid = 0;
    must(libsignal_username_verify(hash, proof, &valid), "username_verify");
    if (!valid) die("username_valid", -1);

    printf("Username ZK proof             PASS\n");
}

static void test_account_keys() {
    uint8_t pool[64];
    libsignal_account_entropy_pool_generate(pool);
    must(libsignal_account_entropy_pool_parse(pool), "entropy_pool_parse");

    uint8_t svr_key[32], backup_key[32], media_key[32];
    must(libsignal_account_entropy_derive_svr_key(pool, svr_key), "svr_key");
    must(libsignal_account_entropy_derive_backup_key(pool, backup_key), "backup_key");
    libsignal_backup_key_derive_media_key(backup_key, media_key);

    // All three keys must be distinct
    if (memcmp(svr_key, backup_key, 32) == 0) die("keys_distinct_sv_bk", -1);
    if (memcmp(backup_key, media_key, 32) == 0) die("keys_distinct_bk_mk", -1);

    printf("Account entropy pool          PASS\n");
}

int main(void) {
    test_ec();
    test_kyber();
    test_session();
    test_group();
    test_sealed_sender_v1();
    test_sealed_sender_v2();
    test_fingerprint();
    test_username();
    test_account_keys();
    return 0;
}
