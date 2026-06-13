// Every C FFI function exported by libsignal-zig.
// Each section exercises a real-world roundtrip: generate → use → verify.
// Any failure calls log.Fatalf; a clean run prints PASS for each section.
package main

/*
#cgo CFLAGS:  -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../zig-out/lib -lsignal -Wl,-rpath,${SRCDIR}/../../zig-out/lib

#include "libsignal.h"
#include <stdlib.h>
#include <string.h>

// ── Per-context identity state passed via ud ────────────────────────────────

typedef struct {
    uint8_t  id_pub[33];
    uint8_t  id_priv[32];
    uint32_t reg_id;
} id_state_t;

static int id_get_keypair(void *ud, uint8_t pub[33], uint8_t priv[32]) {
    id_state_t *s = (id_state_t*)ud;
    memcpy(pub,  s->id_pub,  33);
    memcpy(priv, s->id_priv, 32);
    return 0;
}
static int id_get_reg_id(void *ud, uint32_t *out) {
    *out = ((id_state_t*)ud)->reg_id;
    return 0;
}
static int id_save(void *ud, const char *name, uint32_t dev, const uint8_t pub[33]) {
    (void)ud; (void)name; (void)dev; (void)pub;
    return 0;
}
static int id_is_trusted(void *ud, const char *name, uint32_t dev,
                          const uint8_t pub[33], int dir) {
    (void)ud; (void)name; (void)dev; (void)pub; (void)dir;
    return 1;
}

static libsignal_identity_store_t make_id_store(id_state_t *s) {
    libsignal_identity_store_t st;
    st.ud                  = s;
    st.get_keypair         = id_get_keypair;
    st.get_registration_id = id_get_reg_id;
    st.save_identity       = id_save;
    st.is_trusted          = id_is_trusted;
    return st;
}

// ── In-process session store keyed by (name, device_id) ────────────────────

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
    session_db_t *db = (session_db_t*)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 && db->entries[i].device_id == dev) {
            *out     = (uint8_t*)malloc(db->entries[i].len);
            *out_len = db->entries[i].len;
            memcpy(*out, db->entries[i].data, db->entries[i].len);
            return 0;
        }
    }
    return -6;
}
static int sess_store(void *ud, const char *name, uint32_t dev,
                      const uint8_t *data, size_t len) {
    session_db_t *db = (session_db_t*)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 && db->entries[i].device_id == dev) {
            free(db->entries[i].data);
            db->entries[i].data = (uint8_t*)malloc(len);
            db->entries[i].len  = len;
            memcpy(db->entries[i].data, data, len);
            return 0;
        }
    }
    if (db->count >= MAX_SESSIONS) return -7;
    strncpy(db->entries[db->count].name, name, 127);
    db->entries[db->count].device_id = dev;
    db->entries[db->count].data = (uint8_t*)malloc(len);
    db->entries[db->count].len  = len;
    memcpy(db->entries[db->count].data, data, len);
    db->count++;
    return 0;
}

static libsignal_session_store_t make_sess_store(session_db_t *db) {
    libsignal_session_store_t s;
    s.ud    = db;
    s.load  = sess_load;
    s.store = sess_store;
    return s;
}

static session_db_t *new_session_db(void) {
    session_db_t *db = (session_db_t*)calloc(1, sizeof(session_db_t));
    return db;
}

static void free_session_db(session_db_t *db) {
    for (int i = 0; i < db->count; i++) free(db->entries[i].data);
    free(db);
}

// ── Per-context pre-key store (single key) ──────────────────────────────────

typedef struct {
    uint32_t id;
    uint8_t  pub[33];
    uint8_t  priv[32];
} pk_state_t;

static int pk_load(void *ud, uint32_t id, uint8_t pub[33], uint8_t priv[32]) {
    pk_state_t *s = (pk_state_t*)ud;
    if (id != s->id) return -6;
    memcpy(pub,  s->pub,  33);
    memcpy(priv, s->priv, 32);
    return 0;
}
static int pk_remove(void *ud, uint32_t id) { (void)ud; (void)id; return 0; }

static libsignal_pre_key_store_t make_pk_store(pk_state_t *s) {
    libsignal_pre_key_store_t st;
    st.ud     = s;
    st.load   = pk_load;
    st.remove = pk_remove;
    return st;
}

// ── Per-context signed pre-key store ────────────────────────────────────────

typedef struct {
    uint32_t id;
    uint8_t  pub[33];
    uint8_t  priv[32];
    uint8_t  sig[64];
} spk_state_t;

static int spk_load(void *ud, uint32_t id, uint8_t pub[33], uint8_t priv[32],
                    uint8_t sig[64], uint64_t *ts) {
    spk_state_t *s = (spk_state_t*)ud;
    if (id != s->id) return -6;
    memcpy(pub,  s->pub,  33);
    memcpy(priv, s->priv, 32);
    memcpy(sig,  s->sig,  64);
    *ts = 1700000000;
    return 0;
}

static libsignal_signed_pre_key_store_t make_spk_store(spk_state_t *s) {
    libsignal_signed_pre_key_store_t st;
    st.ud   = s;
    st.load = spk_load;
    return st;
}

// ── In-process sender-key store ─────────────────────────────────────────────

#define MAX_SKDM 16
typedef struct {
    char     name[128];
    uint32_t dev;
    uint8_t  dist[16];
    uint8_t *data;
    size_t   len;
} sk_entry_t;

typedef struct {
    sk_entry_t entries[MAX_SKDM];
    int        count;
} sk_db_t;

static int sk_store_fn(void *ud, const char *name, uint32_t dev,
                        const uint8_t dist[16], const uint8_t *data, size_t len) {
    sk_db_t *db = (sk_db_t*)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 && db->entries[i].dev == dev &&
            memcmp(db->entries[i].dist, dist, 16) == 0) {
            free(db->entries[i].data);
            db->entries[i].data = (uint8_t*)malloc(len);
            db->entries[i].len  = len;
            memcpy(db->entries[i].data, data, len);
            return 0;
        }
    }
    if (db->count >= MAX_SKDM) return -7;
    strncpy(db->entries[db->count].name, name, 127);
    db->entries[db->count].dev = dev;
    memcpy(db->entries[db->count].dist, dist, 16);
    db->entries[db->count].data = (uint8_t*)malloc(len);
    db->entries[db->count].len  = len;
    memcpy(db->entries[db->count].data, data, len);
    db->count++;
    return 0;
}
static int sk_load_fn(void *ud, const char *name, uint32_t dev,
                       const uint8_t dist[16], uint8_t **out, size_t *out_len) {
    sk_db_t *db = (sk_db_t*)ud;
    for (int i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0 && db->entries[i].dev == dev &&
            memcmp(db->entries[i].dist, dist, 16) == 0) {
            *out     = (uint8_t*)malloc(db->entries[i].len);
            *out_len = db->entries[i].len;
            memcpy(*out, db->entries[i].data, db->entries[i].len);
            return 0;
        }
    }
    return -6;
}

static libsignal_sender_key_store_t make_sk_store(sk_db_t *db) {
    libsignal_sender_key_store_t s;
    s.ud    = db;
    s.store = sk_store_fn;
    s.load  = sk_load_fn;
    return s;
}

static sk_db_t *new_sk_db(void) {
    return (sk_db_t*)calloc(1, sizeof(sk_db_t));
}
static void free_sk_db(sk_db_t *db) {
    for (int i = 0; i < db->count; i++) free(db->entries[i].data);
    free(db);
}
*/
import "C"

import (
	"crypto/rand"
	"fmt"
	"log"
	"unsafe"
)

func must(rc C.int, label string) {
	if rc != 0 {
		log.Fatalf("[FAIL] %s: error code %d", label, int(rc))
	}
}

// ── Section 1: EC key generation, DH, XEdDSA sign/verify ───────────────────

func testEC() {
	var pubA, pubB [33]C.uint8_t
	var privA, privB [32]C.uint8_t
	must(C.libsignal_ec_keypair_generate(&pubA[0], &privA[0]), "ec_keypair_generate A")
	must(C.libsignal_ec_keypair_generate(&pubB[0], &privB[0]), "ec_keypair_generate B")

	var sharedA, sharedB [32]C.uint8_t
	must(C.libsignal_ec_dh(&pubB[0], &privA[0], &sharedA[0]), "ec_dh A->B")
	must(C.libsignal_ec_dh(&pubA[0], &privB[0], &sharedB[0]), "ec_dh B->A")
	if sharedA != sharedB {
		log.Fatalf("[FAIL] ec_dh: DH outputs do not match")
	}

	msg := []byte("hello signal")
	var sig [64]C.uint8_t
	must(C.libsignal_xeddsa_sign(&privA[0],
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		&sig[0]), "xeddsa_sign")
	must(C.libsignal_xeddsa_verify(&pubA[0],
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		&sig[0]), "xeddsa_verify")

	// Corrupted signature must fail
	sig[0] ^= 0xFF
	rc := C.libsignal_xeddsa_verify(&pubA[0],
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		&sig[0])
	if rc == 0 {
		log.Fatalf("[FAIL] xeddsa_verify: accepted corrupted signature")
	}

	fmt.Println("PASS ec_keypair_generate / ec_dh / xeddsa_sign / xeddsa_verify")
}

// ── Section 2: ML-KEM-1024 encap/decap ─────────────────────────────────────

func testKyber() {
	pub := (*C.uint8_t)(C.malloc(C.LIBSIGNAL_KYBER1024_PK_LEN))
	sec := (*C.uint8_t)(C.malloc(C.LIBSIGNAL_KYBER1024_SK_LEN))
	defer C.free(unsafe.Pointer(pub))
	defer C.free(unsafe.Pointer(sec))

	must(C.libsignal_kyber1024_keypair_generate(pub, sec), "kyber_keypair_generate")

	var ct [C.LIBSIGNAL_KYBER1024_CT_LEN]C.uint8_t
	var ssEnc [C.LIBSIGNAL_KYBER1024_SS_LEN]C.uint8_t
	must(C.libsignal_kyber1024_encaps(pub, &ct[0], &ssEnc[0]), "kyber_encaps")

	var ssDec [C.LIBSIGNAL_KYBER1024_SS_LEN]C.uint8_t
	must(C.libsignal_kyber1024_decaps(sec, &ct[0], &ssDec[0]), "kyber_decaps")

	if ssEnc != ssDec {
		log.Fatalf("[FAIL] kyber encap/decap: shared secrets do not match")
	}
	fmt.Println("PASS kyber1024_keypair_generate / kyber1024_encaps / kyber1024_decaps")
}

// ── Section 3: Double Ratchet session (Alice sends to Bob) ──────────────────

func testSession() {
	// Bob's identity + pre-keys
	bobID := (*C.id_state_t)(C.calloc(1, C.sizeof_id_state_t))
	defer C.free(unsafe.Pointer(bobID))
	bobID.reg_id = 1234
	must(C.libsignal_ec_keypair_generate(&bobID.id_pub[0], &bobID.id_priv[0]), "bob id keypair")

	pkBob := (*C.pk_state_t)(C.calloc(1, C.sizeof_pk_state_t))
	defer C.free(unsafe.Pointer(pkBob))
	pkBob.id = 1
	must(C.libsignal_ec_keypair_generate(&pkBob.pub[0], &pkBob.priv[0]), "bob prekey")

	spkBob := (*C.spk_state_t)(C.calloc(1, C.sizeof_spk_state_t))
	defer C.free(unsafe.Pointer(spkBob))
	spkBob.id = 10
	must(C.libsignal_ec_keypair_generate(&spkBob.pub[0], &spkBob.priv[0]), "bob spk")
	must(C.libsignal_xeddsa_sign(&bobID.id_priv[0], &spkBob.pub[0],
		C.LIBSIGNAL_EC_PUBLIC_KEY_LEN, &spkBob.sig[0]), "sign spk")

	// Alice's identity
	aliceID := (*C.id_state_t)(C.calloc(1, C.sizeof_id_state_t))
	defer C.free(unsafe.Pointer(aliceID))
	aliceID.reg_id = 5678
	must(C.libsignal_ec_keypair_generate(&aliceID.id_pub[0], &aliceID.id_priv[0]), "alice id keypair")

	// Shared session DB (Alice encrypts, Bob decrypts — same in-memory store)
	aliceSessDB := C.new_session_db()
	defer C.free_session_db(aliceSessDB)
	bobSessDB := C.new_session_db()
	defer C.free_session_db(bobSessDB)

	// Alice context: targeting "bob"/device 1
	aliceCtx := C.libsignal_ctx_new(
		C.CString("bob"), 1,
		C.make_sess_store(aliceSessDB),
		C.make_id_store(aliceID),
		C.make_pk_store(pkBob), // Alice needs Bob's pre-keys to build the bundle
		C.make_spk_store(spkBob),
		nil,
	)
	if aliceCtx == nil {
		log.Fatalf("[FAIL] libsignal_ctx_new alice returned nil")
	}
	defer C.libsignal_ctx_free(aliceCtx)

	// Alice processes Bob's pre-key bundle
	must(C.libsignal_process_prekey_bundle(
		aliceCtx,
		bobID.reg_id,
		pkBob.id, &pkBob.pub[0],
		spkBob.id, &spkBob.pub[0], &spkBob.sig[0],
		&bobID.id_pub[0],
		0, nil, nil,
	), "process_prekey_bundle")

	// Alice encrypts first message (PreKey message)
	plaintext := []byte("Hello Bob from Alice!")
	var ctPtr *C.uint8_t
	var ctLen C.size_t
	var msgType C.int
	must(C.libsignal_encrypt(aliceCtx,
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		&ctPtr, &ctLen, &msgType), "encrypt")
	defer C.free(unsafe.Pointer(ctPtr))

	if msgType != C.LIBSIGNAL_MSG_PREKEY {
		log.Fatalf("[FAIL] expected PREKEY msg type, got %d", int(msgType))
	}

	// Bob context: targeting "alice"/device 1
	pkBobForDecrypt := (*C.pk_state_t)(C.calloc(1, C.sizeof_pk_state_t))
	defer C.free(unsafe.Pointer(pkBobForDecrypt))
	*pkBobForDecrypt = *pkBob

	spkBobForDecrypt := (*C.spk_state_t)(C.calloc(1, C.sizeof_spk_state_t))
	defer C.free(unsafe.Pointer(spkBobForDecrypt))
	*spkBobForDecrypt = *spkBob

	bobCtx := C.libsignal_ctx_new(
		C.CString("alice"), 1,
		C.make_sess_store(bobSessDB),
		C.make_id_store(bobID),
		C.make_pk_store(pkBobForDecrypt),
		C.make_spk_store(spkBobForDecrypt),
		nil,
	)
	if bobCtx == nil {
		log.Fatalf("[FAIL] libsignal_ctx_new bob returned nil")
	}
	defer C.libsignal_ctx_free(bobCtx)

	var ptPtr *C.uint8_t
	var ptLen C.size_t
	must(C.libsignal_decrypt_prekey(bobCtx, ctPtr, ctLen, &ptPtr, &ptLen), "decrypt_prekey")
	defer C.free(unsafe.Pointer(ptPtr))

	recovered := C.GoStringN((*C.char)(unsafe.Pointer(ptPtr)), C.int(ptLen))
	if recovered != string(plaintext) {
		log.Fatalf("[FAIL] session decrypt: got %q, want %q", recovered, string(plaintext))
	}

	// Follow-up whisper message (ratchet advances): Bob replies to Alice
	// For this we need Bob's stored session to be stored and Alice to have received the prekey
	// The above roundtrip is the full session establishment — that suffices for the PREKEY path.
	fmt.Println("PASS ctx_new / process_prekey_bundle / encrypt / decrypt_prekey")
}

// ── Section 4: Group messaging (Sender Key) ─────────────────────────────────

func testGroup() {
	distID := [16]C.uint8_t{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	// Each participant has their own sender key database — they must not share one,
	// as processSession would overwrite the sender's record (with real private key)
	// with a recipient-view record (public key only), breaking subsequent encryption.
	aliceDB := C.new_sk_db()
	defer C.free_sk_db(aliceDB)
	bobDB := C.new_sk_db()
	defer C.free_sk_db(bobDB)

	senderName := C.CString("alice")
	defer C.free(unsafe.Pointer(senderName))

	// Alice creates the sender key session using her own DB
	var skdmPtr *C.uint8_t
	var skdmLen C.size_t
	must(C.libsignal_group_create_session(senderName, 1, &distID[0],
		C.make_sk_store(aliceDB), &skdmPtr, &skdmLen), "group_create_session")
	defer C.free(unsafe.Pointer(skdmPtr))

	// Bob processes the SKDM into his own DB
	must(C.libsignal_group_process_session(senderName, 1, skdmPtr, skdmLen,
		C.make_sk_store(bobDB)), "group_process_session")

	// Alice encrypts (from her DB, which has her full signing key pair)
	msg := []byte("Group message from Alice!")
	var ctPtr *C.uint8_t
	var ctLen C.size_t
	must(C.libsignal_group_encrypt(senderName, 1, &distID[0],
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		C.make_sk_store(aliceDB), &ctPtr, &ctLen), "group_encrypt")
	defer C.free(unsafe.Pointer(ctPtr))

	// Bob decrypts (from his DB, which has Alice's signing public key)
	var ptPtr *C.uint8_t
	var ptLen C.size_t
	must(C.libsignal_group_decrypt(senderName, 1, &distID[0],
		ctPtr, ctLen, C.make_sk_store(bobDB), &ptPtr, &ptLen), "group_decrypt")
	defer C.free(unsafe.Pointer(ptPtr))

	recovered := C.GoStringN((*C.char)(unsafe.Pointer(ptPtr)), C.int(ptLen))
	if recovered != string(msg) {
		log.Fatalf("[FAIL] group decrypt: got %q, want %q", recovered, string(msg))
	}
	fmt.Println("PASS group_create_session / group_process_session / group_encrypt / group_decrypt")
}

// ── Section 5: Sealed sender V1 ─────────────────────────────────────────────

func testSealedSenderV1() {
	var trPriv [32]C.uint8_t
	var serverPub [33]C.uint8_t
	var serverPriv [32]C.uint8_t
	var recvPub [33]C.uint8_t
	var recvPriv [32]C.uint8_t
	var senderPub [33]C.uint8_t
	var senderPriv [32]C.uint8_t
	var trPub [33]C.uint8_t

	must(C.libsignal_ec_keypair_generate(&trPub[0], &trPriv[0]), "trust root keypair")
	must(C.libsignal_ec_keypair_generate(&serverPub[0], &serverPriv[0]), "server cert keypair")
	must(C.libsignal_ec_keypair_generate(&recvPub[0], &recvPriv[0]), "recipient keypair")
	must(C.libsignal_ec_keypair_generate(&senderPub[0], &senderPriv[0]), "sender keypair")
	_ = trPub
	_ = senderPriv

	var scertPtr *C.uint8_t
	var scertLen C.size_t
	must(C.libsignal_server_cert_serialize(42, &serverPub[0], &trPriv[0],
		&scertPtr, &scertLen), "server_cert_serialize")
	defer C.free(unsafe.Pointer(scertPtr))

	senderUUID := C.CString("11111111-1111-1111-1111-111111111111")
	defer C.free(unsafe.Pointer(senderUUID))

	var sendercertPtr *C.uint8_t
	var sendercertLen C.size_t
	must(C.libsignal_sender_cert_serialize(
		senderUUID, nil, 1,
		&senderPub[0],
		2000000000,
		scertPtr, scertLen,
		&serverPriv[0],
		&sendercertPtr, &sendercertLen,
	), "sender_cert_serialize")
	defer C.free(unsafe.Pointer(sendercertPtr))

	plaintext := []byte("Sealed V1 payload")
	var ctPtr *C.uint8_t
	var ctLen C.size_t
	must(C.libsignal_sealed_sender_encrypt(
		&recvPub[0],
		sendercertPtr, sendercertLen,
		1, 0, nil,
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		&ctPtr, &ctLen,
	), "sealed_sender_encrypt")
	defer C.free(unsafe.Pointer(ctPtr))

	var uuidPtr, e164Ptr, contentsPtr *C.uint8_t
	var uuidLen, e164Len, contentsLen C.size_t
	var devID C.uint32_t
	var contentType C.uint8_t
	must(C.libsignal_sealed_sender_decrypt(
		ctPtr, ctLen, &recvPriv[0],
		&uuidPtr, &uuidLen,
		&e164Ptr, &e164Len,
		&devID, &contentType,
		&contentsPtr, &contentsLen,
	), "sealed_sender_decrypt")
	defer C.free(unsafe.Pointer(uuidPtr))
	if e164Ptr != nil {
		defer C.free(unsafe.Pointer(e164Ptr))
	}
	defer C.free(unsafe.Pointer(contentsPtr))

	recovered := C.GoStringN((*C.char)(unsafe.Pointer(contentsPtr)), C.int(contentsLen))
	if recovered != string(plaintext) {
		log.Fatalf("[FAIL] sealed V1 decrypt: got %q, want %q", recovered, string(plaintext))
	}
	gotUUID := C.GoStringN((*C.char)(unsafe.Pointer(uuidPtr)), C.int(uuidLen))
	if gotUUID != "11111111-1111-1111-1111-111111111111" {
		log.Fatalf("[FAIL] sealed V1 sender UUID: got %q", gotUUID)
	}
	fmt.Println("PASS server_cert_serialize / sender_cert_serialize / sealed_sender_encrypt / sealed_sender_decrypt")
}

// ── Section 6: Sealed sender V2 ─────────────────────────────────────────────

func testSealedSenderV2() {
	var senderPub [33]C.uint8_t
	var senderPriv [32]C.uint8_t
	var recipientPub [33]C.uint8_t
	var recipientPriv [32]C.uint8_t
	must(C.libsignal_ec_keypair_generate(&senderPub[0], &senderPriv[0]), "v2 sender keypair")
	must(C.libsignal_ec_keypair_generate(&recipientPub[0], &recipientPriv[0]), "v2 recipient keypair")

	// Build recipient descriptor: ACI service_id (type 0x00 || 16 random UUID bytes)
	var recip C.libsignal_sealed_sender_v2_recipient_t
	recip.service_id_fixed[0] = 0x00 // ACI
	for i := 1; i < 17; i++ {
		recip.service_id_fixed[i] = C.uint8_t(i)
	}
	recip.device_id = 1
	for i := 0; i < 33; i++ {
		recip.identity_pub[i] = recipientPub[i]
	}

	msg := []byte("Sealed V2 multi-recipient payload")
	var sentPtr *C.uint8_t
	var sentLen C.size_t
	must(C.libsignal_sealed_sender_encrypt_v2(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		&senderPriv[0], &senderPub[0],
		&recip, 1,
		nil, 0,
		&sentPtr, &sentLen,
	), "sealed_sender_encrypt_v2")
	defer C.free(unsafe.Pointer(sentPtr))

	// Server dispatch: convert 0x23 sent message → 0x22 received message for our recipient
	var recvPtr *C.uint8_t
	var recvLen C.size_t
	must(C.libsignal_sealed_sender_v2_dispatch(
		sentPtr, sentLen,
		&recip.service_id_fixed[0],
		recip.device_id,
		&recvPtr, &recvLen,
	), "sealed_sender_v2_dispatch")
	defer C.free(unsafe.Pointer(recvPtr))

	var ptPtr *C.uint8_t
	var ptLen C.size_t
	must(C.libsignal_sealed_sender_decrypt_v2(
		recvPtr, recvLen,
		&recipientPriv[0], &recipientPub[0],
		&senderPub[0],
		&ptPtr, &ptLen,
	), "sealed_sender_decrypt_v2")
	defer C.free(unsafe.Pointer(ptPtr))

	recovered := C.GoStringN((*C.char)(unsafe.Pointer(ptPtr)), C.int(ptLen))
	if recovered != string(msg) {
		log.Fatalf("[FAIL] sealed V2 decrypt: got %q, want %q", recovered, string(msg))
	}
	fmt.Println("PASS sealed_sender_encrypt_v2 / v2_dispatch / sealed_sender_decrypt_v2")
}

// ── Section 7: Fingerprint compute + compare ────────────────────────────────

func testFingerprint() {
	var alicePub [33]C.uint8_t
	var alicePriv [32]C.uint8_t
	var bobPub [33]C.uint8_t
	var bobPriv [32]C.uint8_t
	must(C.libsignal_ec_keypair_generate(&alicePub[0], &alicePriv[0]), "fp alice keypair")
	must(C.libsignal_ec_keypair_generate(&bobPub[0], &bobPriv[0]), "fp bob keypair")
	_ = alicePriv
	_ = bobPriv

	aliceID := []byte("+14151234567")
	bobID := []byte("+14159876543")

	var aliceDisplayable [60]C.uint8_t
	var aliceScannablePtr *C.uint8_t
	var aliceScannableLen C.size_t
	must(C.libsignal_fingerprint_compute(
		&alicePub[0],
		(*C.uint8_t)(unsafe.Pointer(&aliceID[0])), C.size_t(len(aliceID)),
		&bobPub[0],
		(*C.uint8_t)(unsafe.Pointer(&bobID[0])), C.size_t(len(bobID)),
		&aliceDisplayable[0],
		&aliceScannablePtr, &aliceScannableLen,
	), "fingerprint_compute alice")
	defer C.free(unsafe.Pointer(aliceScannablePtr))

	var bobDisplayable [60]C.uint8_t
	var bobScannablePtr *C.uint8_t
	var bobScannableLen C.size_t
	must(C.libsignal_fingerprint_compute(
		&bobPub[0],
		(*C.uint8_t)(unsafe.Pointer(&bobID[0])), C.size_t(len(bobID)),
		&alicePub[0],
		(*C.uint8_t)(unsafe.Pointer(&aliceID[0])), C.size_t(len(aliceID)),
		&bobDisplayable[0],
		&bobScannablePtr, &bobScannableLen,
	), "fingerprint_compute bob")
	defer C.free(unsafe.Pointer(bobScannablePtr))

	if aliceDisplayable != bobDisplayable {
		log.Fatalf("[FAIL] fingerprint displayable strings do not match")
	}

	var match C.int
	must(C.libsignal_fingerprint_compare(
		aliceScannablePtr, aliceScannableLen,
		bobScannablePtr, bobScannableLen,
		&match,
	), "fingerprint_compare")
	if match != 1 {
		log.Fatalf("[FAIL] fingerprint_compare returned no match")
	}
	fmt.Println("PASS fingerprint_compute / fingerprint_compare")
}

// ── Section 8: Username hash + ZK proof + verify ────────────────────────────

func testUsername() {
	username := C.CString("alice.42")
	defer C.free(unsafe.Pointer(username))

	var hash [32]C.uint8_t
	must(C.libsignal_username_hash(username, &hash[0]), "username_hash")

	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		log.Fatalf("[FAIL] rand.Read: %v", err)
	}
	var randomness [32]C.uint8_t
	for i, b := range randBytes {
		randomness[i] = C.uint8_t(b)
	}

	var proof [128]C.uint8_t
	must(C.libsignal_username_proof(username, &randomness[0], &proof[0]), "username_proof")

	var valid C.int
	must(C.libsignal_username_verify(&hash[0], &proof[0], &valid), "username_verify")
	if valid != 1 {
		log.Fatalf("[FAIL] username_verify returned invalid for correct proof")
	}

	// Corrupt one hash byte — must fail
	hash[0] ^= 0xFF
	must(C.libsignal_username_verify(&hash[0], &proof[0], &valid), "username_verify corrupted hash")
	if valid != 0 {
		log.Fatalf("[FAIL] username_verify accepted proof against wrong hash")
	}
	fmt.Println("PASS username_hash / username_proof / username_verify")
}

// ── Section 9: AccountEntropyPool generate / parse / derive ─────────────────

func testAccountKeys() {
	var pool [64]C.uint8_t
	C.libsignal_account_entropy_pool_generate(&pool[0])
	must(C.libsignal_account_entropy_pool_parse(&pool[0]), "account_entropy_pool_parse")

	var svrKey [32]C.uint8_t
	must(C.libsignal_account_entropy_derive_svr_key(&pool[0], &svrKey[0]),
		"account_entropy_derive_svr_key")

	var backupKey [32]C.uint8_t
	must(C.libsignal_account_entropy_derive_backup_key(&pool[0], &backupKey[0]),
		"account_entropy_derive_backup_key")

	var mediaKey [32]C.uint8_t
	C.libsignal_backup_key_derive_media_key(&backupKey[0], &mediaKey[0])

	// Determinism: same pool yields same SVR key
	var svrKey2 [32]C.uint8_t
	must(C.libsignal_account_entropy_derive_svr_key(&pool[0], &svrKey2[0]),
		"account_entropy_derive_svr_key repeat")
	if svrKey != svrKey2 {
		log.Fatalf("[FAIL] account_entropy_derive_svr_key is not deterministic")
	}

	// All-zero pool must be rejected
	var badPool [64]C.uint8_t
	rc := C.libsignal_account_entropy_pool_parse(&badPool[0])
	if rc == 0 {
		log.Fatalf("[FAIL] account_entropy_pool_parse accepted all-zero pool")
	}
	fmt.Println("PASS account_entropy_pool_generate / parse / derive_svr_key / derive_backup_key / backup_key_derive_media_key")
}

func main() {
	testEC()
	testKyber()
	testSession()
	testGroup()
	testSealedSenderV1()
	testSealedSenderV2()
	testFingerprint()
	testUsername()
	testAccountKeys()

	fmt.Println("\nAll C FFI tests PASSED.")
}
