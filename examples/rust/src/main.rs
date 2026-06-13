/*
 * Every C FFI function exported by libsignal-zig.
 * Each section exercises a real-world roundtrip: generate → use → verify.
 * Any failure panics; a clean run prints PASS for each section.
 *
 * Run with: cargo run
 */

use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr;

// ── FFI bindings ──────────────────────────────────────────────────────────────

mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    pub const OK: c_int = 0;
    pub const ERR_NOT_FOUND: c_int = -6;
    pub const KYBER_PK: usize = 1568;
    pub const KYBER_SK: usize = 3168;
    pub const KYBER_CT: usize = 1568;
    pub const KYBER_SS: usize = 32;

    #[repr(C)]
    pub struct SessionStore {
        pub ud: *mut c_void,
        pub load:  Option<unsafe extern "C" fn(*mut c_void, *const c_char, u32, *mut *mut u8, *mut usize) -> c_int>,
        pub store: Option<unsafe extern "C" fn(*mut c_void, *const c_char, u32, *const u8, usize) -> c_int>,
    }

    #[repr(C)]
    pub struct IdentityStore {
        pub ud: *mut c_void,
        pub get_keypair:         Option<unsafe extern "C" fn(*mut c_void, *mut u8, *mut u8) -> c_int>,
        pub get_registration_id: Option<unsafe extern "C" fn(*mut c_void, *mut u32) -> c_int>,
        pub save_identity:       Option<unsafe extern "C" fn(*mut c_void, *const c_char, u32, *const u8) -> c_int>,
        pub is_trusted:          Option<unsafe extern "C" fn(*mut c_void, *const c_char, u32, *const u8, c_int) -> c_int>,
    }

    #[repr(C)]
    pub struct PreKeyStore {
        pub ud:     *mut c_void,
        pub load:   Option<unsafe extern "C" fn(*mut c_void, u32, *mut u8, *mut u8) -> c_int>,
        pub remove: Option<unsafe extern "C" fn(*mut c_void, u32) -> c_int>,
    }

    #[repr(C)]
    pub struct SignedPreKeyStore {
        pub ud:   *mut c_void,
        pub load: Option<unsafe extern "C" fn(*mut c_void, u32, *mut u8, *mut u8, *mut u8, *mut u64) -> c_int>,
    }

    #[repr(C)]
    pub struct KyberPreKeyStore {
        pub ud:        *mut c_void,
        pub load:      Option<unsafe extern "C" fn(*mut c_void, u32, *mut u8, *mut u8, *mut u8) -> c_int>,
        pub mark_used: Option<unsafe extern "C" fn(*mut c_void, u32) -> c_int>,
    }

    // Note: store field precedes load — matches the C struct declaration order.
    #[repr(C)]
    pub struct SenderKeyStore {
        pub ud:    *mut c_void,
        pub store: Option<unsafe extern "C" fn(*mut c_void, *const c_char, u32, *const u8, *const u8, usize) -> c_int>,
        pub load:  Option<unsafe extern "C" fn(*mut c_void, *const c_char, u32, *const u8, *mut *mut u8, *mut usize) -> c_int>,
    }

    #[repr(C)]
    pub struct V2Recipient {
        pub service_id_fixed: [u8; 17],
        pub device_id:        u8,
        pub identity_pub:     [u8; 33],
    }

    pub enum Ctx {}

    extern "C" {
        pub fn libsignal_ec_keypair_generate(pub_out: *mut u8, priv_out: *mut u8) -> c_int;
        pub fn libsignal_ec_dh(their_pub: *const u8, our_priv: *const u8, out: *mut u8) -> c_int;
        pub fn libsignal_xeddsa_sign(priv_: *const u8, msg: *const u8, len: usize, sig: *mut u8) -> c_int;
        pub fn libsignal_xeddsa_verify(pub_: *const u8, msg: *const u8, len: usize, sig: *const u8) -> c_int;

        pub fn libsignal_kyber1024_keypair_generate(pk: *mut u8, sk: *mut u8) -> c_int;
        pub fn libsignal_kyber1024_encaps(pk: *const u8, ct: *mut u8, ss: *mut u8) -> c_int;
        pub fn libsignal_kyber1024_decaps(sk: *const u8, ct: *const u8, ss: *mut u8) -> c_int;

        pub fn libsignal_ctx_new(
            remote_name:      *const c_char,
            remote_device_id: u32,
            sess:             SessionStore,
            id:               IdentityStore,
            pk:               PreKeyStore,
            spk:              SignedPreKeyStore,
            kyber:            *const KyberPreKeyStore,
        ) -> *mut Ctx;
        pub fn libsignal_ctx_free(ctx: *mut Ctx);
        pub fn libsignal_process_prekey_bundle(
            ctx:     *mut Ctx,
            reg_id:  u32,
            pk_id:   u32,
            pk_pub:  *const u8,
            spk_id:  u32,
            spk_pub: *const u8,
            spk_sig: *const u8,
            id_pub:  *const u8,
            kyber_id:  u32,
            kyber_pub: *const u8,
            kyber_sig: *const u8,
        ) -> c_int;
        pub fn libsignal_encrypt(
            ctx: *mut Ctx,
            pt: *const u8, pt_len: usize,
            ct: *mut *mut u8, ct_len: *mut usize,
            msg_type: *mut c_int,
        ) -> c_int;
        pub fn libsignal_decrypt_prekey(
            ctx: *mut Ctx,
            ct: *const u8, ct_len: usize,
            pt: *mut *mut u8, pt_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_decrypt(
            ctx: *mut Ctx,
            ct: *const u8, ct_len: usize,
            pt: *mut *mut u8, pt_len: *mut usize,
        ) -> c_int;

        pub fn libsignal_group_create_session(
            name: *const c_char, dev: u32, dist: *const u8,
            sk: SenderKeyStore,
            skdm: *mut *mut u8, skdm_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_group_process_session(
            name: *const c_char, dev: u32,
            skdm: *const u8, skdm_len: usize,
            sk: SenderKeyStore,
        ) -> c_int;
        pub fn libsignal_group_encrypt(
            name: *const c_char, dev: u32, dist: *const u8,
            pt: *const u8, pt_len: usize,
            sk: SenderKeyStore,
            ct: *mut *mut u8, ct_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_group_decrypt(
            name: *const c_char, dev: u32, dist: *const u8,
            ct: *const u8, ct_len: usize,
            sk: SenderKeyStore,
            pt: *mut *mut u8, pt_len: *mut usize,
        ) -> c_int;

        pub fn libsignal_server_cert_serialize(
            key_id: u32, key_pub: *const u8, trust_root_priv: *const u8,
            out: *mut *mut u8, out_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_sender_cert_serialize(
            uuid: *const c_char, e164: *const c_char,
            dev: u32, key_pub: *const u8, expiry: u64,
            srv_cert: *const u8, srv_cert_len: usize, srv_priv: *const u8,
            out: *mut *mut u8, out_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_sealed_sender_encrypt(
            recip_pub: *const u8,
            cert: *const u8, cert_len: usize,
            msg_type: u8, hint: u8, group_id: *const c_char,
            pt: *const u8, pt_len: usize,
            out: *mut *mut u8, out_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_sealed_sender_decrypt(
            data: *const u8, data_len: usize, our_priv: *const u8,
            uuid_out: *mut *mut u8, uuid_len: *mut usize,
            e164_out: *mut *mut u8, e164_len: *mut usize,
            dev_out: *mut u32, ctype_out: *mut u8,
            contents: *mut *mut u8, contents_len: *mut usize,
        ) -> c_int;

        pub fn libsignal_sealed_sender_encrypt_v2(
            msg: *const u8, msg_len: usize,
            sender_priv: *const u8, sender_pub: *const u8,
            recips: *const V2Recipient, recip_count: usize,
            excl: *const u8, excl_count: usize,
            out: *mut *mut u8, out_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_sealed_sender_v2_dispatch(
            sent: *const u8, sent_len: usize,
            svc_id: *const u8, dev: u8,
            out: *mut *mut u8, out_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_sealed_sender_decrypt_v2(
            recv: *const u8, recv_len: usize,
            our_priv: *const u8, our_pub: *const u8, sender_pub: *const u8,
            out: *mut *mut u8, out_len: *mut usize,
        ) -> c_int;

        pub fn libsignal_fingerprint_compute(
            local_pub: *const u8, local_id: *const u8, local_id_len: usize,
            remote_pub: *const u8, remote_id: *const u8, remote_id_len: usize,
            disp: *mut u8,
            scan: *mut *mut u8, scan_len: *mut usize,
        ) -> c_int;
        pub fn libsignal_fingerprint_compare(
            a: *const u8, a_len: usize,
            b: *const u8, b_len: usize,
            match_out: *mut c_int,
        ) -> c_int;

        pub fn libsignal_username_hash(name: *const c_char, out: *mut u8) -> c_int;
        pub fn libsignal_username_proof(name: *const c_char, rand: *const u8, out: *mut u8) -> c_int;
        pub fn libsignal_username_verify(hash: *const u8, proof: *const u8, valid: *mut c_int) -> c_int;

        pub fn libsignal_account_entropy_pool_generate(out: *mut u8);
        pub fn libsignal_account_entropy_pool_parse(pool: *const u8) -> c_int;
        pub fn libsignal_account_entropy_derive_svr_key(pool: *const u8, out: *mut u8) -> c_int;
        pub fn libsignal_account_entropy_derive_backup_key(pool: *const u8, out: *mut u8) -> c_int;
        pub fn libsignal_backup_key_derive_media_key(backup: *const u8, out: *mut u8);
    }
}

// ── Store data types ──────────────────────────────────────────────────────────

struct SessionDb(HashMap<(String, u32), Vec<u8>>);
struct SenderKeyDb(HashMap<(String, u32, [u8; 16]), Vec<u8>>);

struct IdState {
    pub_key:  [u8; 33],
    priv_key: [u8; 32],
    reg_id:   u32,
}

struct PkState {
    id:       u32,
    pub_key:  [u8; 33],
    priv_key: [u8; 32],
}

struct SpkState {
    id:       u32,
    pub_key:  [u8; 33],
    priv_key: [u8; 32],
    sig:      [u8; 64],
}

// ── Session store callbacks ───────────────────────────────────────────────────

unsafe extern "C" fn sess_load(
    ud: *mut c_void, name: *const c_char, dev: u32,
    out: *mut *mut u8, out_len: *mut usize,
) -> c_int {
    let db = &*(ud as *const SessionDb);
    let key = (CStr::from_ptr(name).to_string_lossy().into_owned(), dev);
    match db.0.get(&key) {
        None => ffi::ERR_NOT_FOUND,
        Some(data) => {
            let buf = libc::malloc(data.len()) as *mut u8;
            ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
            *out = buf;
            *out_len = data.len();
            ffi::OK
        }
    }
}

unsafe extern "C" fn sess_store(
    ud: *mut c_void, name: *const c_char, dev: u32,
    data: *const u8, len: usize,
) -> c_int {
    let db = &mut *(ud as *mut SessionDb);
    let key = (CStr::from_ptr(name).to_string_lossy().into_owned(), dev);
    db.0.insert(key, std::slice::from_raw_parts(data, len).to_vec());
    ffi::OK
}

fn make_sess_store(db: &mut SessionDb) -> ffi::SessionStore {
    ffi::SessionStore {
        ud:    db as *mut SessionDb as *mut c_void,
        load:  Some(sess_load),
        store: Some(sess_store),
    }
}

// ── Identity store callbacks ──────────────────────────────────────────────────

unsafe extern "C" fn id_get_keypair(ud: *mut c_void, pub_out: *mut u8, priv_out: *mut u8) -> c_int {
    let s = &*(ud as *const IdState);
    ptr::copy_nonoverlapping(s.pub_key.as_ptr(), pub_out, 33);
    ptr::copy_nonoverlapping(s.priv_key.as_ptr(), priv_out, 32);
    ffi::OK
}
unsafe extern "C" fn id_get_reg(ud: *mut c_void, out: *mut u32) -> c_int {
    *out = (*(ud as *const IdState)).reg_id;
    ffi::OK
}
unsafe extern "C" fn id_save(
    _ud: *mut c_void, _name: *const c_char, _dev: u32, _pub: *const u8,
) -> c_int { ffi::OK }
unsafe extern "C" fn id_trusted(
    _ud: *mut c_void, _name: *const c_char, _dev: u32, _pub: *const u8, _dir: c_int,
) -> c_int { 1 }

fn make_id_store(s: &mut IdState) -> ffi::IdentityStore {
    ffi::IdentityStore {
        ud:                  s as *mut IdState as *mut c_void,
        get_keypair:         Some(id_get_keypair),
        get_registration_id: Some(id_get_reg),
        save_identity:       Some(id_save),
        is_trusted:          Some(id_trusted),
    }
}

// ── Pre-key store callbacks ───────────────────────────────────────────────────

unsafe extern "C" fn pk_load(ud: *mut c_void, id: u32, pub_out: *mut u8, priv_out: *mut u8) -> c_int {
    let s = &*(ud as *const PkState);
    if id != s.id { return ffi::ERR_NOT_FOUND; }
    ptr::copy_nonoverlapping(s.pub_key.as_ptr(), pub_out, 33);
    ptr::copy_nonoverlapping(s.priv_key.as_ptr(), priv_out, 32);
    ffi::OK
}
unsafe extern "C" fn pk_remove(_ud: *mut c_void, _id: u32) -> c_int { ffi::OK }

fn make_pk_store(s: &mut PkState) -> ffi::PreKeyStore {
    ffi::PreKeyStore {
        ud:     s as *mut PkState as *mut c_void,
        load:   Some(pk_load),
        remove: Some(pk_remove),
    }
}

// ── Signed pre-key store callbacks ───────────────────────────────────────────

unsafe extern "C" fn spk_load(
    ud: *mut c_void, id: u32,
    pub_out: *mut u8, priv_out: *mut u8, sig_out: *mut u8, ts: *mut u64,
) -> c_int {
    let s = &*(ud as *const SpkState);
    if id != s.id { return ffi::ERR_NOT_FOUND; }
    ptr::copy_nonoverlapping(s.pub_key.as_ptr(), pub_out, 33);
    ptr::copy_nonoverlapping(s.priv_key.as_ptr(), priv_out, 32);
    ptr::copy_nonoverlapping(s.sig.as_ptr(), sig_out, 64);
    *ts = 1700000000;
    ffi::OK
}

fn make_spk_store(s: &mut SpkState) -> ffi::SignedPreKeyStore {
    ffi::SignedPreKeyStore {
        ud:   s as *mut SpkState as *mut c_void,
        load: Some(spk_load),
    }
}

// ── Sender key store callbacks ────────────────────────────────────────────────

unsafe extern "C" fn sk_store_cb(
    ud: *mut c_void, name: *const c_char, dev: u32,
    dist: *const u8, data: *const u8, len: usize,
) -> c_int {
    let db = &mut *(ud as *mut SenderKeyDb);
    let name = CStr::from_ptr(name).to_string_lossy().into_owned();
    let mut dist_arr = [0u8; 16];
    ptr::copy_nonoverlapping(dist, dist_arr.as_mut_ptr(), 16);
    db.0.insert((name, dev, dist_arr), std::slice::from_raw_parts(data, len).to_vec());
    ffi::OK
}

unsafe extern "C" fn sk_load_cb(
    ud: *mut c_void, name: *const c_char, dev: u32,
    dist: *const u8, out: *mut *mut u8, out_len: *mut usize,
) -> c_int {
    let db = &*(ud as *const SenderKeyDb);
    let name = CStr::from_ptr(name).to_string_lossy().into_owned();
    let mut dist_arr = [0u8; 16];
    ptr::copy_nonoverlapping(dist, dist_arr.as_mut_ptr(), 16);
    match db.0.get(&(name, dev, dist_arr)) {
        None => ffi::ERR_NOT_FOUND,
        Some(data) => {
            let buf = libc::malloc(data.len()) as *mut u8;
            ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
            *out = buf;
            *out_len = data.len();
            ffi::OK
        }
    }
}

fn make_sk_store(db: &mut SenderKeyDb) -> ffi::SenderKeyStore {
    ffi::SenderKeyStore {
        ud:    db as *mut SenderKeyDb as *mut c_void,
        store: Some(sk_store_cb),
        load:  Some(sk_load_cb),
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn must(rc: c_int, label: &str) {
    if rc != 0 {
        panic!("[FAIL] {}: error {}", label, rc);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

fn test_ec() {
    unsafe {
        let mut a_pub  = [0u8; 33]; let mut a_priv = [0u8; 32];
        let mut b_pub  = [0u8; 33]; let mut b_priv = [0u8; 32];
        must(ffi::libsignal_ec_keypair_generate(a_pub.as_mut_ptr(), a_priv.as_mut_ptr()), "ec_gen_a");
        must(ffi::libsignal_ec_keypair_generate(b_pub.as_mut_ptr(), b_priv.as_mut_ptr()), "ec_gen_b");

        let mut shared_a = [0u8; 32]; let mut shared_b = [0u8; 32];
        must(ffi::libsignal_ec_dh(b_pub.as_ptr(), a_priv.as_ptr(), shared_a.as_mut_ptr()), "dh_a");
        must(ffi::libsignal_ec_dh(a_pub.as_ptr(), b_priv.as_ptr(), shared_b.as_mut_ptr()), "dh_b");
        assert_eq!(shared_a, shared_b, "[FAIL] ec_dh: shared secrets differ");

        let msg = b"hello signal";
        let mut sig = [0u8; 64];
        must(ffi::libsignal_xeddsa_sign(a_priv.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()), "xeddsa_sign");
        must(ffi::libsignal_xeddsa_verify(a_pub.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()), "xeddsa_verify");
    }
    println!("EC + XEdDSA                   PASS");
}

fn test_kyber() {
    unsafe {
        let mut pk = vec![0u8; ffi::KYBER_PK];
        let mut sk = vec![0u8; ffi::KYBER_SK];
        must(ffi::libsignal_kyber1024_keypair_generate(pk.as_mut_ptr(), sk.as_mut_ptr()), "kyber_gen");

        let mut ct = vec![0u8; ffi::KYBER_CT];
        let mut ss_enc = [0u8; ffi::KYBER_SS];
        must(ffi::libsignal_kyber1024_encaps(pk.as_ptr(), ct.as_mut_ptr(), ss_enc.as_mut_ptr()), "encaps");

        let mut ss_dec = [0u8; ffi::KYBER_SS];
        must(ffi::libsignal_kyber1024_decaps(sk.as_ptr(), ct.as_ptr(), ss_dec.as_mut_ptr()), "decaps");
        assert_eq!(ss_enc, ss_dec, "[FAIL] kyber: shared secrets differ");
    }
    println!("ML-KEM-1024 (Kyber)           PASS");
}

fn test_session() {
    unsafe {
        let mut alice_id  = IdState { pub_key: [0u8; 33], priv_key: [0u8; 32], reg_id: 1001 };
        let mut bob_id    = IdState { pub_key: [0u8; 33], priv_key: [0u8; 32], reg_id: 2002 };
        must(ffi::libsignal_ec_keypair_generate(alice_id.pub_key.as_mut_ptr(), alice_id.priv_key.as_mut_ptr()), "alice_id");
        must(ffi::libsignal_ec_keypair_generate(bob_id.pub_key.as_mut_ptr(), bob_id.priv_key.as_mut_ptr()), "bob_id");

        let mut alice_pk  = PkState  { id: 0, pub_key: [0u8; 33], priv_key: [0u8; 32] };
        let mut alice_spk = SpkState { id: 0, pub_key: [0u8; 33], priv_key: [0u8; 32], sig: [0u8; 64] };
        let mut bob_pk    = PkState  { id: 1, pub_key: [0u8; 33], priv_key: [0u8; 32] };
        let mut bob_spk   = SpkState { id: 1, pub_key: [0u8; 33], priv_key: [0u8; 32], sig: [0u8; 64] };
        must(ffi::libsignal_ec_keypair_generate(bob_pk.pub_key.as_mut_ptr(), bob_pk.priv_key.as_mut_ptr()), "bob_opk");
        must(ffi::libsignal_ec_keypair_generate(bob_spk.pub_key.as_mut_ptr(), bob_spk.priv_key.as_mut_ptr()), "bob_spk_gen");
        must(ffi::libsignal_xeddsa_sign(bob_id.priv_key.as_ptr(), bob_spk.pub_key.as_ptr(), 33, bob_spk.sig.as_mut_ptr()), "spk_sig");

        let mut alice_db = SessionDb(HashMap::new());
        let mut bob_db   = SessionDb(HashMap::new());

        let alice_ctx = ffi::libsignal_ctx_new(
            b"bob\0".as_ptr() as *const c_char, 1,
            make_sess_store(&mut alice_db),
            make_id_store(&mut alice_id),
            make_pk_store(&mut alice_pk),
            make_spk_store(&mut alice_spk),
            ptr::null(),
        );
        assert!(!alice_ctx.is_null(), "[FAIL] alice ctx_new returned null");

        must(ffi::libsignal_process_prekey_bundle(
            alice_ctx, bob_id.reg_id,
            bob_pk.id, bob_pk.pub_key.as_ptr(),
            bob_spk.id, bob_spk.pub_key.as_ptr(), bob_spk.sig.as_ptr(),
            bob_id.pub_key.as_ptr(),
            0, ptr::null(), ptr::null(),
        ), "process_bundle");

        let mut ct: *mut u8 = ptr::null_mut();
        let mut ct_len = 0usize;
        let mut msg_type = 0i32;
        must(ffi::libsignal_encrypt(alice_ctx, b"hello bob".as_ptr(), 9, &mut ct, &mut ct_len, &mut msg_type), "encrypt_1");

        let bob_ctx = ffi::libsignal_ctx_new(
            b"alice\0".as_ptr() as *const c_char, 1,
            make_sess_store(&mut bob_db),
            make_id_store(&mut bob_id),
            make_pk_store(&mut bob_pk),
            make_spk_store(&mut bob_spk),
            ptr::null(),
        );
        assert!(!bob_ctx.is_null(), "[FAIL] bob ctx_new returned null");

        let mut pt: *mut u8 = ptr::null_mut();
        let mut pt_len = 0usize;
        must(ffi::libsignal_decrypt_prekey(bob_ctx, ct, ct_len, &mut pt, &mut pt_len), "decrypt_prekey");
        assert_eq!(std::slice::from_raw_parts(pt, pt_len), b"hello bob");
        libc::free(ct as *mut libc::c_void);
        libc::free(pt as *mut libc::c_void);

        // Bob replies — session established, whisper message
        let mut ct2: *mut u8 = ptr::null_mut(); let mut ct2_len = 0usize; let mut mt2 = 0i32;
        must(ffi::libsignal_encrypt(bob_ctx, b"hey alice".as_ptr(), 9, &mut ct2, &mut ct2_len, &mut mt2), "encrypt_2");
        let mut pt2: *mut u8 = ptr::null_mut(); let mut pt2_len = 0usize;
        must(ffi::libsignal_decrypt(alice_ctx, ct2, ct2_len, &mut pt2, &mut pt2_len), "decrypt_whisper");
        assert_eq!(std::slice::from_raw_parts(pt2, pt2_len), b"hey alice");
        libc::free(ct2 as *mut libc::c_void);
        libc::free(pt2 as *mut libc::c_void);

        ffi::libsignal_ctx_free(alice_ctx);
        ffi::libsignal_ctx_free(bob_ctx);
    }
    println!("X3DH + Double Ratchet         PASS");
}

fn test_group() {
    unsafe {
        let dist_id: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let mut alice_db = SenderKeyDb(HashMap::new());
        let mut bob_db   = SenderKeyDb(HashMap::new());

        let mut skdm: *mut u8 = ptr::null_mut(); let mut skdm_len = 0usize;
        must(ffi::libsignal_group_create_session(
            b"alice\0".as_ptr() as *const c_char, 1,
            dist_id.as_ptr(), make_sk_store(&mut alice_db),
            &mut skdm, &mut skdm_len,
        ), "group_create");

        must(ffi::libsignal_group_process_session(
            b"alice\0".as_ptr() as *const c_char, 1,
            skdm, skdm_len, make_sk_store(&mut bob_db),
        ), "group_process");
        libc::free(skdm as *mut libc::c_void);

        let mut ct: *mut u8 = ptr::null_mut(); let mut ct_len = 0usize;
        must(ffi::libsignal_group_encrypt(
            b"alice\0".as_ptr() as *const c_char, 1,
            dist_id.as_ptr(), b"group hello".as_ptr(), 11,
            make_sk_store(&mut alice_db),
            &mut ct, &mut ct_len,
        ), "group_encrypt");

        let mut pt: *mut u8 = ptr::null_mut(); let mut pt_len = 0usize;
        must(ffi::libsignal_group_decrypt(
            b"alice\0".as_ptr() as *const c_char, 1,
            dist_id.as_ptr(), ct, ct_len,
            make_sk_store(&mut bob_db),
            &mut pt, &mut pt_len,
        ), "group_decrypt");
        assert_eq!(std::slice::from_raw_parts(pt, pt_len), b"group hello");
        libc::free(ct as *mut libc::c_void);
        libc::free(pt as *mut libc::c_void);
    }
    println!("Sender Keys (group)           PASS");
}

fn test_sealed_sender_v1() {
    unsafe {
        let mut trust_pub  = [0u8; 33]; let mut trust_priv  = [0u8; 32];
        let mut server_pub = [0u8; 33]; let mut server_priv = [0u8; 32];
        let mut recv_pub   = [0u8; 33]; let mut recv_priv   = [0u8; 32];
        let mut sender_pub = [0u8; 33]; let mut sender_priv = [0u8; 32];
        must(ffi::libsignal_ec_keypair_generate(trust_pub.as_mut_ptr(),  trust_priv.as_mut_ptr()),  "trust_root");
        must(ffi::libsignal_ec_keypair_generate(server_pub.as_mut_ptr(), server_priv.as_mut_ptr()), "server_kp");
        must(ffi::libsignal_ec_keypair_generate(recv_pub.as_mut_ptr(),   recv_priv.as_mut_ptr()),   "recv_kp");
        must(ffi::libsignal_ec_keypair_generate(sender_pub.as_mut_ptr(), sender_priv.as_mut_ptr()), "sender_kp");
        let _ = sender_priv;

        let mut srv_cert: *mut u8 = ptr::null_mut(); let mut srv_cert_len = 0usize;
        must(ffi::libsignal_server_cert_serialize(
            1, server_pub.as_ptr(), trust_priv.as_ptr(),
            &mut srv_cert, &mut srv_cert_len,
        ), "server_cert");

        let mut snd_cert: *mut u8 = ptr::null_mut(); let mut snd_cert_len = 0usize;
        must(ffi::libsignal_sender_cert_serialize(
            b"alice-uuid\0".as_ptr() as *const c_char,
            b"+15551234567\0".as_ptr() as *const c_char,
            1, sender_pub.as_ptr(), 9_999_999_999u64,
            srv_cert, srv_cert_len, server_priv.as_ptr(),
            &mut snd_cert, &mut snd_cert_len,
        ), "sender_cert");
        libc::free(srv_cert as *mut libc::c_void);

        let msg = b"sealed v1 message";
        let mut envelope: *mut u8 = ptr::null_mut(); let mut env_len = 0usize;
        must(ffi::libsignal_sealed_sender_encrypt(
            recv_pub.as_ptr(), snd_cert, snd_cert_len,
            1, 0, ptr::null(),
            msg.as_ptr(), msg.len(),
            &mut envelope, &mut env_len,
        ), "ss_v1_encrypt");
        libc::free(snd_cert as *mut libc::c_void);

        let mut uuid_out: *mut u8 = ptr::null_mut(); let mut uuid_len = 0usize;
        let mut e164_out: *mut u8 = ptr::null_mut(); let mut e164_len = 0usize;
        let mut dev_id = 0u32; let mut ctype = 0u8;
        let mut contents: *mut u8 = ptr::null_mut(); let mut cont_len = 0usize;
        must(ffi::libsignal_sealed_sender_decrypt(
            envelope, env_len, recv_priv.as_ptr(),
            &mut uuid_out,  &mut uuid_len,
            &mut e164_out,  &mut e164_len,
            &mut dev_id, &mut ctype,
            &mut contents, &mut cont_len,
        ), "ss_v1_decrypt");
        libc::free(envelope as *mut libc::c_void);

        assert_eq!(std::slice::from_raw_parts(uuid_out, uuid_len), b"alice-uuid");
        assert_eq!(std::slice::from_raw_parts(contents, cont_len), msg);
        libc::free(uuid_out as *mut libc::c_void);
        if !e164_out.is_null() { libc::free(e164_out as *mut libc::c_void); }
        libc::free(contents as *mut libc::c_void);
    }
    println!("Sealed Sender V1              PASS");
}

fn test_sealed_sender_v2() {
    unsafe {
        let mut sender_pub = [0u8; 33]; let mut sender_priv = [0u8; 32];
        let mut recv_pub   = [0u8; 33]; let mut recv_priv   = [0u8; 32];
        must(ffi::libsignal_ec_keypair_generate(sender_pub.as_mut_ptr(), sender_priv.as_mut_ptr()), "ss2_sender");
        must(ffi::libsignal_ec_keypair_generate(recv_pub.as_mut_ptr(),   recv_priv.as_mut_ptr()),   "ss2_recv");

        let mut recip = ffi::V2Recipient {
            service_id_fixed: [0u8; 17],
            device_id:        1,
            identity_pub:     recv_pub,
        };
        recip.service_id_fixed[0] = 0x00;
        for i in 1..17usize { recip.service_id_fixed[i] = i as u8; }

        let msg = b"sealed v2 message";
        let mut sent: *mut u8 = ptr::null_mut(); let mut sent_len = 0usize;
        must(ffi::libsignal_sealed_sender_encrypt_v2(
            msg.as_ptr(), msg.len(),
            sender_priv.as_ptr(), sender_pub.as_ptr(),
            &recip, 1,
            ptr::null(), 0,
            &mut sent, &mut sent_len,
        ), "ss2_encrypt");

        let mut received: *mut u8 = ptr::null_mut(); let mut recv_len = 0usize;
        must(ffi::libsignal_sealed_sender_v2_dispatch(
            sent, sent_len,
            recip.service_id_fixed.as_ptr(), recip.device_id,
            &mut received, &mut recv_len,
        ), "ss2_dispatch");
        libc::free(sent as *mut libc::c_void);

        let mut pt: *mut u8 = ptr::null_mut(); let mut pt_len = 0usize;
        must(ffi::libsignal_sealed_sender_decrypt_v2(
            received, recv_len,
            recv_priv.as_ptr(), recv_pub.as_ptr(), sender_pub.as_ptr(),
            &mut pt, &mut pt_len,
        ), "ss2_decrypt");
        libc::free(received as *mut libc::c_void);

        assert_eq!(std::slice::from_raw_parts(pt, pt_len), msg);
        libc::free(pt as *mut libc::c_void);
    }
    println!("Sealed Sender V2              PASS");
}

fn test_fingerprint() {
    unsafe {
        let mut a_pub = [0u8; 33]; let mut a_priv = [0u8; 32];
        let mut b_pub = [0u8; 33]; let mut b_priv = [0u8; 32];
        must(ffi::libsignal_ec_keypair_generate(a_pub.as_mut_ptr(), a_priv.as_mut_ptr()), "fp_a");
        must(ffi::libsignal_ec_keypair_generate(b_pub.as_mut_ptr(), b_priv.as_mut_ptr()), "fp_b");
        let _ = (a_priv, b_priv);

        let alice_id = b"+15551234567";
        let bob_id   = b"+15559876543";
        let mut disp_a = [0u8; 60]; let mut scan_a: *mut u8 = ptr::null_mut(); let mut scan_a_len = 0usize;
        let mut disp_b = [0u8; 60]; let mut scan_b: *mut u8 = ptr::null_mut(); let mut scan_b_len = 0usize;

        must(ffi::libsignal_fingerprint_compute(
            a_pub.as_ptr(), alice_id.as_ptr(), alice_id.len(),
            b_pub.as_ptr(), bob_id.as_ptr(),   bob_id.len(),
            disp_a.as_mut_ptr(), &mut scan_a, &mut scan_a_len,
        ), "fp_compute_a");
        must(ffi::libsignal_fingerprint_compute(
            b_pub.as_ptr(), bob_id.as_ptr(),   bob_id.len(),
            a_pub.as_ptr(), alice_id.as_ptr(), alice_id.len(),
            disp_b.as_mut_ptr(), &mut scan_b, &mut scan_b_len,
        ), "fp_compute_b");
        let _ = (disp_a, disp_b);

        let mut matched = 0i32;
        must(ffi::libsignal_fingerprint_compare(
            scan_a, scan_a_len, scan_b, scan_b_len, &mut matched,
        ), "fp_compare");
        assert_eq!(matched, 1, "[FAIL] fingerprint mismatch");
        libc::free(scan_a as *mut libc::c_void);
        libc::free(scan_b as *mut libc::c_void);
    }
    println!("Fingerprints                  PASS");
}

fn test_username() {
    unsafe {
        let mut hash = [0u8; 32];
        must(ffi::libsignal_username_hash(b"alice.42\0".as_ptr() as *const c_char, hash.as_mut_ptr()), "username_hash");

        let randomness: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let mut proof = [0u8; 128];
        must(ffi::libsignal_username_proof(b"alice.42\0".as_ptr() as *const c_char, randomness.as_ptr(), proof.as_mut_ptr()), "username_proof");

        let mut valid = 0i32;
        must(ffi::libsignal_username_verify(hash.as_ptr(), proof.as_ptr(), &mut valid), "username_verify");
        assert_eq!(valid, 1, "[FAIL] username proof invalid");
    }
    println!("Username ZK proof             PASS");
}

fn test_account_keys() {
    unsafe {
        let mut pool = [0u8; 64];
        ffi::libsignal_account_entropy_pool_generate(pool.as_mut_ptr());
        must(ffi::libsignal_account_entropy_pool_parse(pool.as_ptr()), "pool_parse");

        let mut svr_key    = [0u8; 32];
        let mut backup_key = [0u8; 32];
        let mut media_key  = [0u8; 32];
        must(ffi::libsignal_account_entropy_derive_svr_key(pool.as_ptr(), svr_key.as_mut_ptr()), "svr_key");
        must(ffi::libsignal_account_entropy_derive_backup_key(pool.as_ptr(), backup_key.as_mut_ptr()), "backup_key");
        ffi::libsignal_backup_key_derive_media_key(backup_key.as_ptr(), media_key.as_mut_ptr());

        assert_ne!(svr_key, backup_key, "[FAIL] svr_key == backup_key");
        assert_ne!(backup_key, media_key, "[FAIL] backup_key == media_key");
    }
    println!("Account entropy pool          PASS");
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    test_ec();
    test_kyber();
    test_session();
    test_group();
    test_sealed_sender_v1();
    test_sealed_sender_v2();
    test_fingerprint();
    test_username();
    test_account_keys();
}
