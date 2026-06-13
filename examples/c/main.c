/*
 * Every C FFI function exported by libsignal-zig.
 * Each section exercises a real-world roundtrip: generate → use → verify.
 * Any failure calls abort(); a clean run prints PASS for each section.
 *
 * Compile and run with: make run
 */
#include "../../include/libsignal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static void must(int rc, const char *label) {
    if (rc != 0) {
        fprintf(stderr, "[FAIL] %s: error %d\n", label, rc);
        abort();
    }
}

/* ── In-memory session store ─────────────────────────────────────────────── */

#define MAX_SESSIONS 64

typedef struct {
    char     name[128];
    uint32_t device_id;
    uint8_t *data;
    size_t   len;
} session_entry_t;

typedef struct {
    session_entry_t entries[MAX_SESSIONS];
    int             count;
} session_db_t;

static int sess_load(void *ud, const char *name, uint32_t dev,
                     uint8_t **out, size_t *out_len) {
    session_db_t *db = (session_db_t *)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 &&
            db->entries[i].device_id == dev) {
            *out_len = db->entries[i].len;
            *out     = (uint8_t *)malloc(db->entries[i].len);
            memcpy(*out, db->entries[i].data, db->entries[i].len);
            return LIBSIGNAL_OK;
        }
    }
    return LIBSIGNAL_ERR_NOT_FOUND;
}

static int sess_store(void *ud, const char *name, uint32_t dev,
                      const uint8_t *data, size_t len) {
    session_db_t *db = (session_db_t *)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 &&
            db->entries[i].device_id == dev) {
            free(db->entries[i].data);
            db->entries[i].data = (uint8_t *)malloc(len);
            db->entries[i].len  = len;
            memcpy(db->entries[i].data, data, len);
            return LIBSIGNAL_OK;
        }
    }
    if (db->count >= MAX_SESSIONS) return LIBSIGNAL_ERR_INTERNAL;
    strncpy(db->entries[db->count].name, name, 127);
    db->entries[db->count].name[127]    = '\0';
    db->entries[db->count].device_id    = dev;
    db->entries[db->count].data         = (uint8_t *)malloc(len);
    db->entries[db->count].len          = len;
    memcpy(db->entries[db->count].data, data, len);
    db->count++;
    return LIBSIGNAL_OK;
}

static libsignal_session_store_t make_sess_store(session_db_t *db) {
    libsignal_session_store_t s;
    s.ud    = db;
    s.load  = sess_load;
    s.store = sess_store;
    return s;
}

static void free_session_db(session_db_t *db) {
    for (int i = 0; i < db->count; i++) free(db->entries[i].data);
}

/* ── Identity store ──────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  pub[33];
    uint8_t  priv[32];
    uint32_t reg_id;
} id_state_t;

static int id_get_keypair(void *ud, uint8_t pub[33], uint8_t priv[32]) {
    id_state_t *s = (id_state_t *)ud;
    memcpy(pub, s->pub, 33);
    memcpy(priv, s->priv, 32);
    return LIBSIGNAL_OK;
}
static int id_get_reg(void *ud, uint32_t *out) {
    *out = ((id_state_t *)ud)->reg_id;
    return LIBSIGNAL_OK;
}
static int id_save(void *ud, const char *name, uint32_t dev,
                   const uint8_t pub[33]) {
    (void)ud; (void)name; (void)dev; (void)pub;
    return LIBSIGNAL_OK;
}
static int id_trusted(void *ud, const char *name, uint32_t dev,
                       const uint8_t pub[33], int dir) {
    (void)ud; (void)name; (void)dev; (void)pub; (void)dir;
    return 1;
}

static libsignal_identity_store_t make_id_store(id_state_t *s) {
    libsignal_identity_store_t st;
    st.ud                  = s;
    st.get_keypair         = id_get_keypair;
    st.get_registration_id = id_get_reg;
    st.save_identity       = id_save;
    st.is_trusted          = id_trusted;
    return st;
}

/* ── Pre-key store ───────────────────────────────────────────────────────── */

typedef struct {
    uint32_t id;
    uint8_t  pub[33];
    uint8_t  priv[32];
} pk_state_t;

static int pk_load(void *ud, uint32_t id, uint8_t pub[33], uint8_t priv[32]) {
    pk_state_t *s = (pk_state_t *)ud;
    if (id != s->id) return LIBSIGNAL_ERR_NOT_FOUND;
    memcpy(pub, s->pub, 33);
    memcpy(priv, s->priv, 32);
    return LIBSIGNAL_OK;
}
static int pk_remove(void *ud, uint32_t id) {
    (void)ud; (void)id;
    return LIBSIGNAL_OK;
}

static libsignal_pre_key_store_t make_pk_store(pk_state_t *s) {
    libsignal_pre_key_store_t st;
    st.ud     = s;
    st.load   = pk_load;
    st.remove = pk_remove;
    return st;
}

/* ── Signed pre-key store ────────────────────────────────────────────────── */

typedef struct {
    uint32_t id;
    uint8_t  pub[33];
    uint8_t  priv[32];
    uint8_t  sig[64];
} spk_state_t;

static int spk_load(void *ud, uint32_t id, uint8_t pub[33], uint8_t priv[32],
                    uint8_t sig[64], uint64_t *ts) {
    spk_state_t *s = (spk_state_t *)ud;
    if (id != s->id) return LIBSIGNAL_ERR_NOT_FOUND;
    memcpy(pub, s->pub, 33);
    memcpy(priv, s->priv, 32);
    memcpy(sig, s->sig, 64);
    *ts = 1700000000;
    return LIBSIGNAL_OK;
}

static libsignal_signed_pre_key_store_t make_spk_store(spk_state_t *s) {
    libsignal_signed_pre_key_store_t st;
    st.ud   = s;
    st.load = spk_load;
    return st;
}

/* ── Sender key store ────────────────────────────────────────────────────── */

#define MAX_SK_ENTRIES 16

typedef struct {
    char     name[128];
    uint32_t dev;
    uint8_t  dist[16];
    uint8_t *data;
    size_t   len;
} sk_entry_t;

typedef struct {
    sk_entry_t entries[MAX_SK_ENTRIES];
    int        count;
} sk_db_t;

static int sk_store(void *ud, const char *name, uint32_t dev,
                    const uint8_t dist[16], const uint8_t *data, size_t len) {
    sk_db_t *db = (sk_db_t *)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 &&
            db->entries[i].dev == dev &&
            memcmp(db->entries[i].dist, dist, 16) == 0) {
            free(db->entries[i].data);
            db->entries[i].data = (uint8_t *)malloc(len);
            db->entries[i].len  = len;
            memcpy(db->entries[i].data, data, len);
            return LIBSIGNAL_OK;
        }
    }
    if (db->count >= MAX_SK_ENTRIES) return LIBSIGNAL_ERR_INTERNAL;
    strncpy(db->entries[db->count].name, name, 127);
    db->entries[db->count].name[127] = '\0';
    db->entries[db->count].dev       = dev;
    memcpy(db->entries[db->count].dist, dist, 16);
    db->entries[db->count].data      = (uint8_t *)malloc(len);
    db->entries[db->count].len       = len;
    memcpy(db->entries[db->count].data, data, len);
    db->count++;
    return LIBSIGNAL_OK;
}

static int sk_load(void *ud, const char *name, uint32_t dev,
                   const uint8_t dist[16], uint8_t **out, size_t *out_len) {
    sk_db_t *db = (sk_db_t *)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 &&
            db->entries[i].dev == dev &&
            memcmp(db->entries[i].dist, dist, 16) == 0) {
            *out_len = db->entries[i].len;
            *out     = (uint8_t *)malloc(db->entries[i].len);
            memcpy(*out, db->entries[i].data, db->entries[i].len);
            return LIBSIGNAL_OK;
        }
    }
    return LIBSIGNAL_ERR_NOT_FOUND;
}

static libsignal_sender_key_store_t make_sk_store(sk_db_t *db) {
    libsignal_sender_key_store_t s;
    s.ud    = db;
    s.store = sk_store;
    s.load  = sk_load;
    return s;
}

static void free_sk_db(sk_db_t *db) {
    for (int i = 0; i < db->count; i++) free(db->entries[i].data);
}

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_ec(void) {
    uint8_t pub_a[33], priv_a[32], pub_b[33], priv_b[32];
    must(libsignal_ec_keypair_generate(pub_a, priv_a), "ec_generate_a");
    must(libsignal_ec_keypair_generate(pub_b, priv_b), "ec_generate_b");

    uint8_t shared_a[32], shared_b[32];
    must(libsignal_ec_dh(pub_b, priv_a, shared_a), "ec_dh_a");
    must(libsignal_ec_dh(pub_a, priv_b, shared_b), "ec_dh_b");
    if (memcmp(shared_a, shared_b, 32) != 0) {
        fprintf(stderr, "[FAIL] ec_dh: shared secrets do not match\n");
        abort();
    }

    const uint8_t msg[] = "hello signal";
    uint8_t sig[64];
    must(libsignal_xeddsa_sign(priv_a, msg, sizeof(msg) - 1, sig), "xeddsa_sign");
    must(libsignal_xeddsa_verify(pub_a, msg, sizeof(msg) - 1, sig), "xeddsa_verify");

    printf("EC + XEdDSA                   PASS\n");
}

static void test_kyber(void) {
    uint8_t pk[LIBSIGNAL_KYBER1024_PK_LEN];
    uint8_t sk[LIBSIGNAL_KYBER1024_SK_LEN];
    must(libsignal_kyber1024_keypair_generate(pk, sk), "kyber_keygen");

    uint8_t ct[LIBSIGNAL_KYBER1024_CT_LEN], ss_enc[LIBSIGNAL_KYBER1024_SS_LEN];
    must(libsignal_kyber1024_encaps(pk, ct, ss_enc), "kyber_encaps");

    uint8_t ss_dec[LIBSIGNAL_KYBER1024_SS_LEN];
    must(libsignal_kyber1024_decaps(sk, ct, ss_dec), "kyber_decaps");
    if (memcmp(ss_enc, ss_dec, LIBSIGNAL_KYBER1024_SS_LEN) != 0) {
        fprintf(stderr, "[FAIL] kyber: shared secrets do not match\n");
        abort();
    }

    printf("ML-KEM-1024 (Kyber)           PASS\n");
}

static void test_session(void) {
    id_state_t alice_id, bob_id;
    must(libsignal_ec_keypair_generate(alice_id.pub, alice_id.priv), "alice_id");
    alice_id.reg_id = 1001;
    must(libsignal_ec_keypair_generate(bob_id.pub, bob_id.priv), "bob_id");
    bob_id.reg_id = 2002;

    pk_state_t  alice_pk  = {0};
    spk_state_t alice_spk = {0};
    pk_state_t  bob_pk;
    spk_state_t bob_spk;
    bob_pk.id = 1;
    must(libsignal_ec_keypair_generate(bob_pk.pub, bob_pk.priv), "bob_opk");
    bob_spk.id = 1;
    must(libsignal_ec_keypair_generate(bob_spk.pub, bob_spk.priv), "bob_spk");
    must(libsignal_xeddsa_sign(bob_id.priv, bob_spk.pub, 33, bob_spk.sig), "bob_spk_sig");

    session_db_t alice_db = {0}, bob_db = {0};

    libsignal_ctx_t *alice_ctx = libsignal_ctx_new(
        "bob", 1,
        make_sess_store(&alice_db), make_id_store(&alice_id),
        make_pk_store(&alice_pk),   make_spk_store(&alice_spk),
        NULL);
    if (!alice_ctx) { fprintf(stderr, "[FAIL] alice ctx_new\n"); abort(); }

    must(libsignal_process_prekey_bundle(alice_ctx, bob_id.reg_id,
        bob_pk.id,  bob_pk.pub,
        bob_spk.id, bob_spk.pub, bob_spk.sig,
        bob_id.pub,
        0, NULL, NULL), "process_bundle");

    uint8_t *ct = NULL; size_t ct_len = 0; int msg_type = 0;
    must(libsignal_encrypt(alice_ctx,
        (const uint8_t *)"hello bob", 9,
        &ct, &ct_len, &msg_type), "encrypt_1");

    libsignal_ctx_t *bob_ctx = libsignal_ctx_new(
        "alice", 1,
        make_sess_store(&bob_db), make_id_store(&bob_id),
        make_pk_store(&bob_pk),   make_spk_store(&bob_spk),
        NULL);
    if (!bob_ctx) { fprintf(stderr, "[FAIL] bob ctx_new\n"); abort(); }

    uint8_t *pt = NULL; size_t pt_len = 0;
    must(libsignal_decrypt_prekey(bob_ctx, ct, ct_len, &pt, &pt_len), "decrypt_prekey");
    if (pt_len != 9 || memcmp(pt, "hello bob", 9) != 0) {
        fprintf(stderr, "[FAIL] session plaintext mismatch\n");
        abort();
    }
    free(ct); free(pt);

    /* Bob replies — session is now established, whisper message */
    uint8_t *ct2 = NULL; size_t ct2_len = 0; int mt2 = 0;
    must(libsignal_encrypt(bob_ctx,
        (const uint8_t *)"hey alice", 9,
        &ct2, &ct2_len, &mt2), "encrypt_2");

    uint8_t *pt2 = NULL; size_t pt2_len = 0;
    must(libsignal_decrypt(alice_ctx, ct2, ct2_len, &pt2, &pt2_len), "decrypt_whisper");
    if (pt2_len != 9 || memcmp(pt2, "hey alice", 9) != 0) {
        fprintf(stderr, "[FAIL] whisper plaintext mismatch\n");
        abort();
    }
    free(ct2); free(pt2);

    libsignal_ctx_free(alice_ctx);
    libsignal_ctx_free(bob_ctx);
    free_session_db(&alice_db);
    free_session_db(&bob_db);
    printf("X3DH + Double Ratchet         PASS\n");
}

static void test_group(void) {
    static const uint8_t dist_id[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };

    sk_db_t alice_db = {0}, bob_db = {0};

    uint8_t *skdm = NULL; size_t skdm_len = 0;
    must(libsignal_group_create_session(
        "alice", 1, dist_id, make_sk_store(&alice_db),
        &skdm, &skdm_len), "group_create");

    must(libsignal_group_process_session(
        "alice", 1, skdm, skdm_len,
        make_sk_store(&bob_db)), "group_process");
    free(skdm);

    uint8_t *ct = NULL; size_t ct_len = 0;
    must(libsignal_group_encrypt(
        "alice", 1, dist_id,
        (const uint8_t *)"group hello", 11,
        make_sk_store(&alice_db),
        &ct, &ct_len), "group_encrypt");

    uint8_t *pt = NULL; size_t pt_len = 0;
    must(libsignal_group_decrypt(
        "alice", 1, dist_id,
        ct, ct_len,
        make_sk_store(&bob_db),
        &pt, &pt_len), "group_decrypt");
    if (pt_len != 11 || memcmp(pt, "group hello", 11) != 0) {
        fprintf(stderr, "[FAIL] group plaintext mismatch\n");
        abort();
    }
    free(ct); free(pt);
    free_sk_db(&alice_db);
    free_sk_db(&bob_db);
    printf("Sender Keys (group)           PASS\n");
}

static void test_sealed_sender_v1(void) {
    uint8_t trust_pub[33], trust_priv[32];
    uint8_t server_pub[33], server_priv[32];
    uint8_t recv_pub[33], recv_priv[32];
    uint8_t sender_pub[33], sender_priv[32];
    must(libsignal_ec_keypair_generate(trust_pub,  trust_priv),  "trust_root");
    must(libsignal_ec_keypair_generate(server_pub, server_priv), "server_kp");
    must(libsignal_ec_keypair_generate(recv_pub,   recv_priv),   "recv_kp");
    must(libsignal_ec_keypair_generate(sender_pub, sender_priv), "sender_kp");
    (void)sender_priv;

    uint8_t *srv_cert = NULL; size_t srv_cert_len = 0;
    must(libsignal_server_cert_serialize(
        1, server_pub, trust_priv,
        &srv_cert, &srv_cert_len), "server_cert");

    uint8_t *snd_cert = NULL; size_t snd_cert_len = 0;
    must(libsignal_sender_cert_serialize(
        "alice-uuid", "+15551234567", 1,
        sender_pub, 9999999999ULL,
        srv_cert, srv_cert_len, server_priv,
        &snd_cert, &snd_cert_len), "sender_cert");
    free(srv_cert);

    static const uint8_t msg[] = "sealed v1 message";
    uint8_t *envelope = NULL; size_t env_len = 0;
    must(libsignal_sealed_sender_encrypt(
        recv_pub, snd_cert, snd_cert_len,
        1, 0, NULL,
        msg, sizeof(msg) - 1,
        &envelope, &env_len), "ss_v1_encrypt");
    free(snd_cert);

    uint8_t *uuid_out = NULL; size_t uuid_len = 0;
    uint8_t *e164_out = NULL; size_t e164_len = 0;
    uint32_t dev_id   = 0;
    uint8_t  ctype    = 0;
    uint8_t *contents = NULL; size_t cont_len = 0;

    must(libsignal_sealed_sender_decrypt(
        envelope, env_len, recv_priv,
        &uuid_out,  &uuid_len,
        &e164_out,  &e164_len,
        &dev_id,    &ctype,
        &contents,  &cont_len), "ss_v1_decrypt");
    free(envelope);

    if (uuid_len != 10 || memcmp(uuid_out, "alice-uuid", 10) != 0) {
        fprintf(stderr, "[FAIL] ss_v1 uuid mismatch\n");
        abort();
    }
    if (cont_len != sizeof(msg) - 1 || memcmp(contents, msg, cont_len) != 0) {
        fprintf(stderr, "[FAIL] ss_v1 contents mismatch\n");
        abort();
    }
    free(uuid_out);
    if (e164_out) free(e164_out);
    free(contents);
    printf("Sealed Sender V1              PASS\n");
}

static void test_sealed_sender_v2(void) {
    uint8_t sender_pub[33], sender_priv[32];
    uint8_t recv_pub[33], recv_priv[32];
    must(libsignal_ec_keypair_generate(sender_pub, sender_priv), "ss2_sender");
    must(libsignal_ec_keypair_generate(recv_pub,   recv_priv),   "ss2_recv");

    libsignal_sealed_sender_v2_recipient_t recip;
    recip.service_id_fixed[0] = 0x00; /* ACI */
    for (int i = 1; i < 17; i++) recip.service_id_fixed[i] = (uint8_t)i;
    recip.device_id = 1;
    memcpy(recip.identity_pub, recv_pub, 33);

    static const uint8_t msg[] = "sealed v2 message";
    uint8_t *sent = NULL; size_t sent_len = 0;
    must(libsignal_sealed_sender_encrypt_v2(
        msg, sizeof(msg) - 1,
        sender_priv, sender_pub,
        &recip, 1,
        NULL, 0,
        &sent, &sent_len), "ss2_encrypt");

    uint8_t *received = NULL; size_t recv_len = 0;
    must(libsignal_sealed_sender_v2_dispatch(
        sent, sent_len,
        recip.service_id_fixed, recip.device_id,
        &received, &recv_len), "ss2_dispatch");
    free(sent);

    uint8_t *pt = NULL; size_t pt_len = 0;
    must(libsignal_sealed_sender_decrypt_v2(
        received, recv_len,
        recv_priv, recv_pub, sender_pub,
        &pt, &pt_len), "ss2_decrypt");
    free(received);

    if (pt_len != sizeof(msg) - 1 || memcmp(pt, msg, pt_len) != 0) {
        fprintf(stderr, "[FAIL] ss2 contents mismatch\n");
        abort();
    }
    free(pt);
    printf("Sealed Sender V2              PASS\n");
}

static void test_fingerprint(void) {
    uint8_t a_pub[33], a_priv[32], b_pub[33], b_priv[32];
    must(libsignal_ec_keypair_generate(a_pub, a_priv), "fp_a");
    must(libsignal_ec_keypair_generate(b_pub, b_priv), "fp_b");
    (void)a_priv; (void)b_priv;

    static const uint8_t alice_id[] = "+15551234567";
    static const uint8_t bob_id[]   = "+15559876543";

    uint8_t disp_a[60], disp_b[60];
    uint8_t *scan_a = NULL; size_t scan_a_len = 0;
    uint8_t *scan_b = NULL; size_t scan_b_len = 0;

    must(libsignal_fingerprint_compute(
        a_pub, alice_id, sizeof(alice_id) - 1,
        b_pub, bob_id,   sizeof(bob_id)   - 1,
        disp_a, &scan_a, &scan_a_len), "fp_compute_a");

    must(libsignal_fingerprint_compute(
        b_pub, bob_id,   sizeof(bob_id)   - 1,
        a_pub, alice_id, sizeof(alice_id) - 1,
        disp_b, &scan_b, &scan_b_len), "fp_compute_b");

    int match = 0;
    must(libsignal_fingerprint_compare(
        scan_a, scan_a_len,
        scan_b, scan_b_len,
        &match), "fp_compare");
    if (!match) {
        fprintf(stderr, "[FAIL] fingerprint: scannable comparison mismatch\n");
        abort();
    }
    free(scan_a); free(scan_b);
    printf("Fingerprints                  PASS\n");
}

static void test_username(void) {
    uint8_t hash[32];
    must(libsignal_username_hash("alice.42", hash), "username_hash");

    uint8_t randomness[32];
    for (int i = 0; i < 32; i++) randomness[i] = (uint8_t)(i * 7 + 3);

    uint8_t proof[128];
    must(libsignal_username_proof("alice.42", randomness, proof), "username_proof");

    int valid = 0;
    must(libsignal_username_verify(hash, proof, &valid), "username_verify");
    if (!valid) {
        fprintf(stderr, "[FAIL] username: proof verification failed\n");
        abort();
    }
    printf("Username ZK proof             PASS\n");
}

static void test_account_keys(void) {
    uint8_t pool[64];
    libsignal_account_entropy_pool_generate(pool);
    must(libsignal_account_entropy_pool_parse(pool), "entropy_pool_parse");

    uint8_t svr_key[32], backup_key[32], media_key[32];
    must(libsignal_account_entropy_derive_svr_key(pool, svr_key), "svr_key");
    must(libsignal_account_entropy_derive_backup_key(pool, backup_key), "backup_key");
    libsignal_backup_key_derive_media_key(backup_key, media_key);

    if (memcmp(svr_key, backup_key, 32) == 0) {
        fprintf(stderr, "[FAIL] account keys: svr_key == backup_key\n");
        abort();
    }
    if (memcmp(backup_key, media_key, 32) == 0) {
        fprintf(stderr, "[FAIL] account keys: backup_key == media_key\n");
        abort();
    }
    printf("Account entropy pool          PASS\n");
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

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
