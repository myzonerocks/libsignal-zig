/*
 * Exercises every protocol operation exported by libsignal-zig via signal_ffi.h.
 * Hand-written #[repr(C)] bindings — no bindgen. The only external crate is `libc`
 * (unused now that all memory is managed through signal_free_buffer / signal_free_string).
 *
 * Run with:  cargo run
 */

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;

// ── FFI bindings ──────────────────────────────────────────────────────────────

mod ffi {
    use std::ffi::{c_char, c_void};

    /// Two-field buffer whose memory is owned by the caller; free with
    /// signal_free_buffer(base, length).
    #[repr(C)]
    pub struct OwnedBuffer {
        pub base:   *mut u8,
        pub length: usize,
    }
    impl OwnedBuffer {
        pub const ZERO: Self = Self { base: std::ptr::null_mut(), length: 0 };
    }

    /// Two-field buffer that borrows from the caller's memory; the library
    /// does not retain a reference after the call returns.
    #[repr(C)]
    pub struct BorrowedBuffer {
        pub base:   *const u8,
        pub length: usize,
    }

    // ── Store structs ─────────────────────────────────────────────────────────
    // Field order matches signal_ffi.h exactly. All pointer handle types are
    // ABI-equivalent to *mut c_void on 64-bit platforms.

    #[repr(C)]
    pub struct SessionStore {
        pub ctx:           *mut c_void,
        pub load_session:  Option<unsafe extern "C" fn(*mut *mut c_void, *const c_void, *mut c_void) -> *mut c_void>,
        pub store_session: Option<unsafe extern "C" fn(*const c_void, *mut c_void, *mut c_void) -> *mut c_void>,
        pub destroy:       Option<unsafe extern "C" fn(*mut c_void)>,
    }

    #[repr(C)]
    pub struct IdentityKeyStore {
        pub ctx:                      *mut c_void,
        pub get_identity_key_pair:    Option<unsafe extern "C" fn(*mut *mut c_void, *mut *mut c_void, *mut c_void) -> *mut c_void>,
        pub get_local_registration_id:Option<unsafe extern "C" fn(*mut u32, *mut c_void) -> *mut c_void>,
        pub save_identity:            Option<unsafe extern "C" fn(*const c_void, *mut c_void, *mut c_void) -> *mut c_void>,
        pub is_trusted_identity:      Option<unsafe extern "C" fn(*mut bool, *const c_void, *mut c_void, u32, *mut c_void) -> *mut c_void>,
        pub get_identity:             Option<unsafe extern "C" fn(*mut *mut c_void, *const c_void, *mut c_void) -> *mut c_void>,
        pub destroy:                  Option<unsafe extern "C" fn(*mut c_void)>,
    }

    #[repr(C)]
    pub struct PreKeyStore {
        pub ctx:          *mut c_void,
        pub load_pre_key: Option<unsafe extern "C" fn(*mut *mut c_void, u32, *mut c_void) -> *mut c_void>,
        pub store_pre_key:Option<unsafe extern "C" fn(u32, *mut c_void, *mut c_void) -> *mut c_void>,
        pub remove_pre_key:Option<unsafe extern "C" fn(u32, *mut c_void) -> *mut c_void>,
        pub destroy:      Option<unsafe extern "C" fn(*mut c_void)>,
    }

    #[repr(C)]
    pub struct SignedPreKeyStore {
        pub ctx:               *mut c_void,
        pub load_signed_pre_key: Option<unsafe extern "C" fn(*mut *mut c_void, u32, *mut c_void) -> *mut c_void>,
        pub store_signed_pre_key:Option<unsafe extern "C" fn(u32, *mut c_void, *mut c_void) -> *mut c_void>,
        pub destroy:           Option<unsafe extern "C" fn(*mut c_void)>,
    }

    #[repr(C)]
    pub struct KyberPreKeyStore {
        pub ctx:                   *mut c_void,
        pub load_kyber_pre_key:    Option<unsafe extern "C" fn(*mut *mut c_void, u32, *mut c_void) -> *mut c_void>,
        pub store_kyber_pre_key:   Option<unsafe extern "C" fn(u32, *mut c_void, *mut c_void) -> *mut c_void>,
        pub mark_kyber_pre_key_used:Option<unsafe extern "C" fn(u32, *mut c_void) -> *mut c_void>,
        pub destroy:               Option<unsafe extern "C" fn(*mut c_void)>,
    }

    // store_sender_key precedes load_sender_key — matches the C struct declaration order.
    #[repr(C)]
    pub struct SenderKeyStore {
        pub ctx:             *mut c_void,
        pub store_sender_key:Option<unsafe extern "C" fn(*const c_void, *const u8, *mut c_void, *mut c_void) -> *mut c_void>,
        pub load_sender_key: Option<unsafe extern "C" fn(*mut *mut c_void, *const c_void, *const u8, *mut c_void) -> *mut c_void>,
        pub destroy:         Option<unsafe extern "C" fn(*mut c_void)>,
    }

    // ── Extern declarations ───────────────────────────────────────────────────

    extern "C" {
        // Errors and memory
        pub fn signal_error_free(e: *mut c_void);
        pub fn signal_error_get_message(out: *mut *const c_char, e: *const c_void) -> *mut c_void;
        pub fn signal_free_buffer(buf: *mut u8, len: usize);
        pub fn signal_free_string(s: *mut c_char);

        // EC keys
        pub fn signal_privatekey_generate(out: *mut *mut c_void) -> *mut c_void;
        pub fn signal_privatekey_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_privatekey_serialize(out: *mut OwnedBuffer, key: *const c_void) -> *mut c_void;
        pub fn signal_privatekey_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;
        pub fn signal_privatekey_agree(out: *mut OwnedBuffer, key: *const c_void, their_key: *const c_void) -> *mut c_void;
        pub fn signal_privatekey_sign(out: *mut OwnedBuffer, key: *const c_void, message: BorrowedBuffer) -> *mut c_void;
        pub fn signal_privatekey_get_public_key(out: *mut *mut c_void, key: *const c_void) -> *mut c_void;
        pub fn signal_publickey_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_publickey_serialize(out: *mut OwnedBuffer, key: *const c_void) -> *mut c_void;
        pub fn signal_publickey_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;
        pub fn signal_publickey_verify(out: *mut bool, key: *const c_void, msg: BorrowedBuffer, sig: BorrowedBuffer) -> *mut c_void;

        // Kyber keys
        pub fn signal_kyber_key_pair_generate(out: *mut *mut c_void) -> *mut c_void;
        pub fn signal_kyber_key_pair_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_kyber_key_pair_get_public_key(out: *mut *mut c_void, pair: *const c_void) -> *mut c_void;
        pub fn signal_kyber_key_pair_get_secret_key(out: *mut *mut c_void, pair: *const c_void) -> *mut c_void;
        pub fn signal_kyber_public_key_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_kyber_public_key_serialize(out: *mut OwnedBuffer, key: *const c_void) -> *mut c_void;
        pub fn signal_kyber_secret_key_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_kyber_secret_key_serialize(out: *mut OwnedBuffer, key: *const c_void) -> *mut c_void;

        // Kyber pre-key records
        pub fn signal_kyber_pre_key_record_new(out: *mut *mut c_void, id: u32, ts: u64, pair: *const c_void, sig: BorrowedBuffer) -> *mut c_void;
        pub fn signal_kyber_pre_key_record_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_kyber_pre_key_record_get_public_key(out: *mut *mut c_void, rec: *const c_void) -> *mut c_void;
        pub fn signal_kyber_pre_key_record_get_signature(out: *mut OwnedBuffer, rec: *const c_void) -> *mut c_void;
        pub fn signal_kyber_pre_key_record_serialize(out: *mut OwnedBuffer, rec: *const c_void) -> *mut c_void;
        pub fn signal_kyber_pre_key_record_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;

        // Pre-key records
        pub fn signal_pre_key_record_new(out: *mut *mut c_void, id: u32, pub_key: *const c_void, priv_key: *const c_void) -> *mut c_void;
        pub fn signal_pre_key_record_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_pre_key_record_get_public_key(out: *mut *mut c_void, rec: *const c_void) -> *mut c_void;
        pub fn signal_pre_key_record_serialize(out: *mut OwnedBuffer, rec: *const c_void) -> *mut c_void;
        pub fn signal_pre_key_record_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;

        // Signed pre-key records
        pub fn signal_signed_pre_key_record_new(out: *mut *mut c_void, id: u32, ts: u64, pub_key: *const c_void, priv_key: *const c_void, sig: BorrowedBuffer) -> *mut c_void;
        pub fn signal_signed_pre_key_record_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_signed_pre_key_record_get_public_key(out: *mut *mut c_void, rec: *const c_void) -> *mut c_void;
        pub fn signal_signed_pre_key_record_get_signature(out: *mut OwnedBuffer, rec: *const c_void) -> *mut c_void;
        pub fn signal_signed_pre_key_record_serialize(out: *mut OwnedBuffer, rec: *const c_void) -> *mut c_void;
        pub fn signal_signed_pre_key_record_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;

        // Sender key records
        pub fn signal_sender_key_record_serialize(out: *mut OwnedBuffer, rec: *const c_void) -> *mut c_void;
        pub fn signal_sender_key_record_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;

        // Session records
        pub fn signal_session_record_serialize(out: *mut OwnedBuffer, rec: *const c_void) -> *mut c_void;
        pub fn signal_session_record_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;

        // Protocol address
        pub fn signal_address_new(out: *mut *mut c_void, name: *const c_char, device_id: u32) -> *mut c_void;
        pub fn signal_address_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_address_get_name(out: *mut *const c_char, obj: *const c_void) -> *mut c_void;
        pub fn signal_address_get_device_id(out: *mut u32, obj: *const c_void) -> *mut c_void;

        // Pre-key bundle
        pub fn signal_pre_key_bundle_new(
            out: *mut *mut c_void,
            reg_id: u32, device_id: u32,
            opk_id: u32, has_opk: bool, opk_pub: *const c_void,
            spk_id: u32, spk_pub: *const c_void, spk_sig: BorrowedBuffer,
            id_pub: *const c_void,
            kpk_id: u32, has_kpk: bool, kpk_pub: *const c_void, kpk_sig: BorrowedBuffer,
        ) -> *mut c_void;
        pub fn signal_pre_key_bundle_destroy(p: *mut c_void) -> *mut c_void;

        // Session protocol
        pub fn signal_process_prekey_bundle(
            bundle: *const c_void, addr: *const c_void,
            sess: *const SessionStore, id: *const IdentityKeyStore,
            pk: *const PreKeyStore, spk: *const SignedPreKeyStore,
            kpk: *const KyberPreKeyStore,
        ) -> *mut c_void;
        pub fn signal_encrypt_message(
            out: *mut *mut c_void, plaintext: BorrowedBuffer, addr: *const c_void,
            sess: *const SessionStore, id: *const IdentityKeyStore,
            pk: *const PreKeyStore, spk: *const SignedPreKeyStore,
        ) -> *mut c_void;
        pub fn signal_decrypt_message(
            out: *mut OwnedBuffer, msg: *const c_void, addr: *const c_void,
            sess: *const SessionStore, id: *const IdentityKeyStore,
        ) -> *mut c_void;
        pub fn signal_decrypt_pre_key_message(
            out: *mut OwnedBuffer, msg: *const c_void, addr: *const c_void,
            sess: *const SessionStore, id: *const IdentityKeyStore,
            pk: *const PreKeyStore, spk: *const SignedPreKeyStore,
            kpk: *const KyberPreKeyStore,
        ) -> *mut c_void;

        // Ciphertext message
        pub fn signal_ciphertext_message_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_ciphertext_message_serialize(out: *mut OwnedBuffer, obj: *const c_void) -> *mut c_void;
        pub fn signal_ciphertext_message_type(out: *mut u8, obj: *const c_void) -> *mut c_void;

        // Pre-key signal message
        pub fn signal_pre_key_signal_message_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_pre_key_signal_message_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;

        // Signal message (whisper)
        pub fn signal_message_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_message_deserialize(out: *mut *mut c_void, data: BorrowedBuffer) -> *mut c_void;

        // Group / sender key
        pub fn signal_sender_key_distribution_message_create(
            out: *mut *mut c_void, sender: *const c_void,
            dist_id: BorrowedBuffer, store: *const SenderKeyStore,
        ) -> *mut c_void;
        pub fn signal_process_sender_key_distribution_message(
            sender: *const c_void, msg: *const c_void, store: *const SenderKeyStore,
        ) -> *mut c_void;
        pub fn signal_sender_key_distribution_message_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_group_encrypt_message(
            out: *mut OwnedBuffer, sender: *const c_void,
            dist_id: BorrowedBuffer, plaintext: BorrowedBuffer, store: *const SenderKeyStore,
        ) -> *mut c_void;
        pub fn signal_group_decrypt_message(
            out: *mut OwnedBuffer, sender: *const c_void,
            dist_id: BorrowedBuffer, ciphertext: BorrowedBuffer, store: *const SenderKeyStore,
        ) -> *mut c_void;

        // Fingerprints
        pub fn signal_fingerprint_new(
            out: *mut *mut c_void, iterations: u32, version: u32,
            local_id: BorrowedBuffer, local_key: *const c_void,
            remote_id: BorrowedBuffer, remote_key: *const c_void,
        ) -> *mut c_void;
        pub fn signal_fingerprint_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_fingerprint_scannable_encoding(out: *mut OwnedBuffer, obj: *const c_void) -> *mut c_void;
        pub fn signal_fingerprint_compare(out: *mut bool, obj: *const c_void, theirs: BorrowedBuffer) -> *mut c_void;

        // Username ZK proof
        pub fn signal_username_hash(out: *mut u8, username: *const c_char) -> *mut c_void;
        pub fn signal_username_proof(out: *mut OwnedBuffer, username: *const c_char) -> *mut c_void;
        pub fn signal_username_verify(out: *mut bool, hash: *const u8, proof: BorrowedBuffer) -> *mut c_void;

        // Account entropy pool
        pub fn signal_account_entropy_pool_generate(out: *mut *mut c_void) -> *mut c_void;
        pub fn signal_account_entropy_pool_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_account_entropy_pool_as_string(out: *mut *const c_char, obj: *const c_void) -> *mut c_void;
        pub fn signal_account_entropy_pool_derive_svr_key(out: *mut u8, obj: *const c_void) -> *mut c_void;
        pub fn signal_account_entropy_pool_derive_backup_key(out: *mut u8, obj: *const c_void) -> *mut c_void;

        // Backup key
        pub fn signal_backup_key_from_bytes(out: *mut *mut c_void, bytes: BorrowedBuffer) -> *mut c_void;
        pub fn signal_backup_key_destroy(p: *mut c_void) -> *mut c_void;
        pub fn signal_backup_key_derive_media_encryption_key(out: *mut u8, obj: *const c_void) -> *mut c_void;
    }
}

use ffi::{BorrowedBuffer, OwnedBuffer};

// ── Helper: error checking ────────────────────────────────────────────────────

fn die(e: *mut c_void, label: &str) -> ! {
    unsafe {
        let mut msg: *const c_char = ptr::null();
        ffi::signal_error_get_message(&mut msg, e as *const c_void);
        let s = if msg.is_null() { "(no message)".to_owned() }
                else { CStr::from_ptr(msg).to_string_lossy().into_owned() };
        ffi::signal_error_free(e);
        panic!("[FAIL] {}: {}", label, s);
    }
}

macro_rules! must {
    ($call:expr) => {{
        let e = $call;
        if !e.is_null() { die(e, stringify!($call)); }
    }};
    ($call:expr, $label:expr) => {{
        let e = $call;
        if !e.is_null() { die(e, $label); }
    }};
}

fn borrow(data: &[u8]) -> BorrowedBuffer {
    BorrowedBuffer { base: data.as_ptr(), length: data.len() }
}

/// Read an OwnedBuffer into a Vec and free the buffer.
unsafe fn read_owned(b: OwnedBuffer) -> Vec<u8> {
    let v = std::slice::from_raw_parts(b.base, b.length).to_vec();
    ffi::signal_free_buffer(b.base, b.length);
    v
}

// ── Helper: address key ───────────────────────────────────────────────────────

unsafe fn addr_key(addr: *const c_void) -> String {
    let mut name: *const c_char = ptr::null();
    let mut dev: u32 = 0;
    must!(ffi::signal_address_get_name(&mut name, addr), "addr_get_name");
    must!(ffi::signal_address_get_device_id(&mut dev, addr), "addr_get_dev");
    format!("{}:{}", CStr::from_ptr(name).to_string_lossy(), dev)
}

/// Sender key store key: "name:dev:hexdist_id".
unsafe fn sk_key(sender: *const c_void, dist_id: *const u8) -> String {
    let base = addr_key(sender);
    let dist = std::slice::from_raw_parts(dist_id, 16);
    let hex: String = dist.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}:{}", base, hex)
}

// ── Helper: sign bytes ────────────────────────────────────────────────────────

/// Sign `data` with a 32-byte serialized private key; return signature bytes.
unsafe fn sign_bytes(priv32: &[u8], data: &[u8]) -> Vec<u8> {
    let mut pk: *mut c_void = ptr::null_mut();
    must!(ffi::signal_privatekey_deserialize(&mut pk, borrow(priv32)), "sign_bytes:deser");
    let mut sig = OwnedBuffer::ZERO;
    must!(ffi::signal_privatekey_sign(&mut sig, pk as *const c_void, borrow(data)), "sign_bytes:sign");
    ffi::signal_privatekey_destroy(pk);
    read_owned(sig)
}

// ── Store data types ──────────────────────────────────────────────────────────

struct KvDb(HashMap<String, Vec<u8>>);

struct IdDb {
    priv_bytes: Vec<u8>,
    reg_id:     u32,
    trusted:    KvDb,
}

// ── Session store callbacks ───────────────────────────────────────────────────

unsafe extern "C" fn sess_load(
    out: *mut *mut c_void, addr: *const c_void, ctx: *mut c_void,
) -> *mut c_void {
    let db = &*(ctx as *const KvDb);
    let key = addr_key(addr);
    match db.0.get(&key) {
        None => { *out = ptr::null_mut(); ptr::null_mut() }
        Some(data) => ffi::signal_session_record_deserialize(out, borrow(data)),
    }
}

unsafe extern "C" fn sess_store(
    addr: *const c_void, rec: *mut c_void, ctx: *mut c_void,
) -> *mut c_void {
    let db = &mut *(ctx as *mut KvDb);
    let key = addr_key(addr);
    let mut bytes = OwnedBuffer::ZERO;
    let e = ffi::signal_session_record_serialize(&mut bytes, rec as *const c_void);
    if !e.is_null() { return e; }
    db.0.insert(key, read_owned(bytes));
    ptr::null_mut()
}

fn make_sess_store(db: &mut KvDb) -> ffi::SessionStore {
    ffi::SessionStore {
        ctx: db as *mut KvDb as *mut c_void,
        load_session:  Some(sess_load),
        store_session: Some(sess_store),
        destroy: None,
    }
}

// ── Identity store callbacks ──────────────────────────────────────────────────

unsafe extern "C" fn id_get_kp(
    out_pub: *mut *mut c_void, out_priv: *mut *mut c_void, ctx: *mut c_void,
) -> *mut c_void {
    let s = &*(ctx as *const IdDb);
    let e = ffi::signal_privatekey_deserialize(out_priv, borrow(&s.priv_bytes));
    if !e.is_null() { return e; }
    ffi::signal_privatekey_get_public_key(out_pub, *out_priv as *const c_void)
}

unsafe extern "C" fn id_get_reg(out: *mut u32, ctx: *mut c_void) -> *mut c_void {
    *out = (*(ctx as *const IdDb)).reg_id;
    ptr::null_mut()
}

unsafe extern "C" fn id_save(
    addr: *const c_void, key: *mut c_void, ctx: *mut c_void,
) -> *mut c_void {
    let s = &mut *(ctx as *mut IdDb);
    let k = addr_key(addr);
    let mut bytes = OwnedBuffer::ZERO;
    let e = ffi::signal_publickey_serialize(&mut bytes, key as *const c_void);
    if !e.is_null() { return e; }
    s.trusted.0.insert(k, read_owned(bytes));
    ptr::null_mut()
}

unsafe extern "C" fn id_trusted(
    out: *mut bool, _addr: *const c_void, _key: *mut c_void, _dir: u32, _ctx: *mut c_void,
) -> *mut c_void {
    *out = true;
    ptr::null_mut()
}

unsafe extern "C" fn id_get(
    out: *mut *mut c_void, addr: *const c_void, ctx: *mut c_void,
) -> *mut c_void {
    let s = &*(ctx as *const IdDb);
    let k = addr_key(addr);
    match s.trusted.0.get(&k) {
        None => { *out = ptr::null_mut(); ptr::null_mut() }
        Some(data) => ffi::signal_publickey_deserialize(out, borrow(data)),
    }
}

fn make_id_store(db: &mut IdDb) -> ffi::IdentityKeyStore {
    ffi::IdentityKeyStore {
        ctx: db as *mut IdDb as *mut c_void,
        get_identity_key_pair:     Some(id_get_kp),
        get_local_registration_id: Some(id_get_reg),
        save_identity:             Some(id_save),
        is_trusted_identity:       Some(id_trusted),
        get_identity:              Some(id_get),
        destroy: None,
    }
}

// ── Pre-key store callbacks ───────────────────────────────────────────────────

unsafe extern "C" fn pk_load(
    out: *mut *mut c_void, id: u32, ctx: *mut c_void,
) -> *mut c_void {
    let db = &*(ctx as *const KvDb);
    match db.0.get(&id.to_string()) {
        None => { *out = ptr::null_mut(); ptr::null_mut() }
        Some(data) => ffi::signal_pre_key_record_deserialize(out, borrow(data)),
    }
}

unsafe extern "C" fn pk_store(id: u32, rec: *mut c_void, ctx: *mut c_void) -> *mut c_void {
    let db = &mut *(ctx as *mut KvDb);
    let mut bytes = OwnedBuffer::ZERO;
    let e = ffi::signal_pre_key_record_serialize(&mut bytes, rec as *const c_void);
    if !e.is_null() { return e; }
    db.0.insert(id.to_string(), read_owned(bytes));
    ptr::null_mut()
}

unsafe extern "C" fn pk_remove(_id: u32, _ctx: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}

fn make_pk_store(db: &mut KvDb) -> ffi::PreKeyStore {
    ffi::PreKeyStore {
        ctx: db as *mut KvDb as *mut c_void,
        load_pre_key:  Some(pk_load),
        store_pre_key: Some(pk_store),
        remove_pre_key:Some(pk_remove),
        destroy: None,
    }
}

// ── Signed pre-key store callbacks ───────────────────────────────────────────

unsafe extern "C" fn spk_load(
    out: *mut *mut c_void, id: u32, ctx: *mut c_void,
) -> *mut c_void {
    let db = &*(ctx as *const KvDb);
    match db.0.get(&id.to_string()) {
        None => { *out = ptr::null_mut(); ptr::null_mut() }
        Some(data) => ffi::signal_signed_pre_key_record_deserialize(out, borrow(data)),
    }
}

unsafe extern "C" fn spk_store(id: u32, rec: *mut c_void, ctx: *mut c_void) -> *mut c_void {
    let db = &mut *(ctx as *mut KvDb);
    let mut bytes = OwnedBuffer::ZERO;
    let e = ffi::signal_signed_pre_key_record_serialize(&mut bytes, rec as *const c_void);
    if !e.is_null() { return e; }
    db.0.insert(id.to_string(), read_owned(bytes));
    ptr::null_mut()
}

fn make_spk_store(db: &mut KvDb) -> ffi::SignedPreKeyStore {
    ffi::SignedPreKeyStore {
        ctx: db as *mut KvDb as *mut c_void,
        load_signed_pre_key:  Some(spk_load),
        store_signed_pre_key: Some(spk_store),
        destroy: None,
    }
}

// ── Kyber pre-key store callbacks ─────────────────────────────────────────────

unsafe extern "C" fn kpk_load(
    out: *mut *mut c_void, id: u32, ctx: *mut c_void,
) -> *mut c_void {
    let db = &*(ctx as *const KvDb);
    match db.0.get(&id.to_string()) {
        None => { *out = ptr::null_mut(); ptr::null_mut() }
        Some(data) => ffi::signal_kyber_pre_key_record_deserialize(out, borrow(data)),
    }
}

unsafe extern "C" fn kpk_store(id: u32, rec: *mut c_void, ctx: *mut c_void) -> *mut c_void {
    let db = &mut *(ctx as *mut KvDb);
    let mut bytes = OwnedBuffer::ZERO;
    let e = ffi::signal_kyber_pre_key_record_serialize(&mut bytes, rec as *const c_void);
    if !e.is_null() { return e; }
    db.0.insert(id.to_string(), read_owned(bytes));
    ptr::null_mut()
}

unsafe extern "C" fn kpk_mark_used(_id: u32, _ctx: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}

fn make_kpk_store(db: &mut KvDb) -> ffi::KyberPreKeyStore {
    ffi::KyberPreKeyStore {
        ctx: db as *mut KvDb as *mut c_void,
        load_kyber_pre_key:    Some(kpk_load),
        store_kyber_pre_key:   Some(kpk_store),
        mark_kyber_pre_key_used: Some(kpk_mark_used),
        destroy: None,
    }
}

// ── Sender key store callbacks ────────────────────────────────────────────────

unsafe extern "C" fn sk_store(
    sender: *const c_void, dist_id: *const u8, rec: *mut c_void, ctx: *mut c_void,
) -> *mut c_void {
    let db = &mut *(ctx as *mut KvDb);
    let key = sk_key(sender, dist_id);
    let mut bytes = OwnedBuffer::ZERO;
    let e = ffi::signal_sender_key_record_serialize(&mut bytes, rec as *const c_void);
    if !e.is_null() { return e; }
    db.0.insert(key, read_owned(bytes));
    ptr::null_mut()
}

unsafe extern "C" fn sk_load(
    out: *mut *mut c_void, sender: *const c_void, dist_id: *const u8, ctx: *mut c_void,
) -> *mut c_void {
    let db = &*(ctx as *const KvDb);
    let key = sk_key(sender, dist_id);
    match db.0.get(&key) {
        None => { *out = ptr::null_mut(); ptr::null_mut() }
        Some(data) => ffi::signal_sender_key_record_deserialize(out, borrow(data)),
    }
}

fn make_sk_store(db: &mut KvDb) -> ffi::SenderKeyStore {
    ffi::SenderKeyStore {
        ctx: db as *mut KvDb as *mut c_void,
        store_sender_key: Some(sk_store),
        load_sender_key:  Some(sk_load),
        destroy: None,
    }
}

// ── Bob key setup ─────────────────────────────────────────────────────────────

struct BobKeys {
    id_priv: Vec<u8>,
    reg_id:  u32,
    opk_id:  u32,
    spk_id:  u32,
    kpk_id:  u32,
}

unsafe fn setup_bob(pk_db: &mut KvDb, spk_db: &mut KvDb, kpk_db: &mut KvDb) -> BobKeys {
    // Identity key
    let mut id_priv: *mut c_void = ptr::null_mut();
    must!(ffi::signal_privatekey_generate(&mut id_priv), "bob_id_gen");
    let mut id_priv_bytes = OwnedBuffer::ZERO;
    must!(ffi::signal_privatekey_serialize(&mut id_priv_bytes, id_priv as *const c_void));
    let id_priv_vec = read_owned(id_priv_bytes);
    ffi::signal_privatekey_destroy(id_priv);

    // One-time pre-key
    let opk_id = 1u32;
    {
        let mut opk_priv: *mut c_void = ptr::null_mut();
        let mut opk_pub:  *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_generate(&mut opk_priv));
        must!(ffi::signal_privatekey_get_public_key(&mut opk_pub, opk_priv as *const c_void));
        let mut rec: *mut c_void = ptr::null_mut();
        must!(ffi::signal_pre_key_record_new(&mut rec, opk_id, opk_pub as *const c_void, opk_priv as *const c_void));
        ffi::signal_privatekey_destroy(opk_priv);
        ffi::signal_publickey_destroy(opk_pub);
        pk_store(opk_id, rec, pk_db as *mut KvDb as *mut c_void);
        ffi::signal_pre_key_record_destroy(rec);
    }

    // Signed pre-key
    let spk_id = 1u32;
    {
        let mut spk_priv: *mut c_void = ptr::null_mut();
        let mut spk_pub:  *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_generate(&mut spk_priv));
        must!(ffi::signal_privatekey_get_public_key(&mut spk_pub, spk_priv as *const c_void));
        let mut pub_bytes = OwnedBuffer::ZERO;
        must!(ffi::signal_publickey_serialize(&mut pub_bytes, spk_pub as *const c_void));
        let sig = sign_bytes(&id_priv_vec, std::slice::from_raw_parts(pub_bytes.base, pub_bytes.length));
        ffi::signal_free_buffer(pub_bytes.base, pub_bytes.length);
        let mut rec: *mut c_void = ptr::null_mut();
        must!(ffi::signal_signed_pre_key_record_new(
            &mut rec, spk_id, 1700000000,
            spk_pub as *const c_void, spk_priv as *const c_void, borrow(&sig)));
        ffi::signal_privatekey_destroy(spk_priv);
        ffi::signal_publickey_destroy(spk_pub);
        spk_store(spk_id, rec, spk_db as *mut KvDb as *mut c_void);
        ffi::signal_signed_pre_key_record_destroy(rec);
    }

    // Kyber pre-key
    let kpk_id = 1u32;
    {
        let mut kpk: *mut c_void = ptr::null_mut();
        must!(ffi::signal_kyber_key_pair_generate(&mut kpk));
        let mut kpk_pub_h: *mut c_void = ptr::null_mut();
        must!(ffi::signal_kyber_key_pair_get_public_key(&mut kpk_pub_h, kpk as *const c_void));
        let mut pub_bytes = OwnedBuffer::ZERO;
        must!(ffi::signal_kyber_public_key_serialize(&mut pub_bytes, kpk_pub_h as *const c_void));
        let sig = sign_bytes(&id_priv_vec, std::slice::from_raw_parts(pub_bytes.base, pub_bytes.length));
        ffi::signal_free_buffer(pub_bytes.base, pub_bytes.length);
        ffi::signal_kyber_public_key_destroy(kpk_pub_h);
        let mut rec: *mut c_void = ptr::null_mut();
        must!(ffi::signal_kyber_pre_key_record_new(&mut rec, kpk_id, 1700000000, kpk as *const c_void, borrow(&sig)));
        ffi::signal_kyber_key_pair_destroy(kpk);
        kpk_store(kpk_id, rec, kpk_db as *mut KvDb as *mut c_void);
        ffi::signal_kyber_pre_key_record_destroy(rec);
    }

    BobKeys { id_priv: id_priv_vec, reg_id: 2002, opk_id, spk_id, kpk_id }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

fn test_ec_keys() {
    unsafe {
        let mut pa: *mut c_void = ptr::null_mut();
        let mut pb: *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_generate(&mut pa));
        must!(ffi::signal_privatekey_generate(&mut pb));

        let mut qa: *mut c_void = ptr::null_mut();
        let mut qb: *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_get_public_key(&mut qa, pa as *const c_void));
        must!(ffi::signal_privatekey_get_public_key(&mut qb, pb as *const c_void));

        let mut dh_a = OwnedBuffer::ZERO;
        let mut dh_b = OwnedBuffer::ZERO;
        must!(ffi::signal_privatekey_agree(&mut dh_a, pa as *const c_void, qb as *const c_void));
        must!(ffi::signal_privatekey_agree(&mut dh_b, pb as *const c_void, qa as *const c_void));
        assert_eq!(
            std::slice::from_raw_parts(dh_a.base, dh_a.length),
            std::slice::from_raw_parts(dh_b.base, dh_b.length),
            "[FAIL] DH secrets differ"
        );
        ffi::signal_free_buffer(dh_a.base, dh_a.length);
        ffi::signal_free_buffer(dh_b.base, dh_b.length);

        let msg = b"hello signal";
        let mut sig = OwnedBuffer::ZERO;
        must!(ffi::signal_privatekey_sign(&mut sig, pa as *const c_void, borrow(msg)));
        let mut ok = false;
        must!(ffi::signal_publickey_verify(&mut ok, qa as *const c_void, borrow(msg),
            BorrowedBuffer { base: sig.base, length: sig.length }));
        assert!(ok, "[FAIL] XEdDSA verify failed");
        ffi::signal_free_buffer(sig.base, sig.length);

        ffi::signal_privatekey_destroy(pa); ffi::signal_privatekey_destroy(pb);
        ffi::signal_publickey_destroy(qa);  ffi::signal_publickey_destroy(qb);
    }
    println!("EC + XEdDSA                   PASS");
}

fn test_kyber_keys() {
    unsafe {
        let mut kp: *mut c_void = ptr::null_mut();
        must!(ffi::signal_kyber_key_pair_generate(&mut kp));

        let mut pub_h: *mut c_void = ptr::null_mut();
        let mut sec_h: *mut c_void = ptr::null_mut();
        must!(ffi::signal_kyber_key_pair_get_public_key(&mut pub_h, kp as *const c_void));
        must!(ffi::signal_kyber_key_pair_get_secret_key(&mut sec_h, kp as *const c_void));

        let mut pub_b = OwnedBuffer::ZERO;
        let mut sec_b = OwnedBuffer::ZERO;
        must!(ffi::signal_kyber_public_key_serialize(&mut pub_b, pub_h as *const c_void));
        must!(ffi::signal_kyber_secret_key_serialize(&mut sec_b, sec_h as *const c_void));

        assert_eq!(pub_b.length, 1568, "[FAIL] Kyber public key size");
        assert_eq!(sec_b.length, 3168, "[FAIL] Kyber secret key size");

        ffi::signal_free_buffer(pub_b.base, pub_b.length);
        ffi::signal_free_buffer(sec_b.base, sec_b.length);
        ffi::signal_kyber_key_pair_destroy(kp);
        ffi::signal_kyber_public_key_destroy(pub_h);
        ffi::signal_kyber_secret_key_destroy(sec_h);
    }
    println!("ML-KEM-1024 (Kyber)           PASS");
}

fn test_session() {
    unsafe {
        // Alice's identity
        let mut alice_id_priv: *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_generate(&mut alice_id_priv));
        let mut alice_id_priv_bytes = OwnedBuffer::ZERO;
        must!(ffi::signal_privatekey_serialize(&mut alice_id_priv_bytes, alice_id_priv as *const c_void));
        let alice_priv_vec = read_owned(alice_id_priv_bytes);
        ffi::signal_privatekey_destroy(alice_id_priv);

        // Bob's stores and key material
        let mut bob_sess_db = KvDb(HashMap::new());
        let mut bob_pk_db   = KvDb(HashMap::new());
        let mut bob_spk_db  = KvDb(HashMap::new());
        let mut bob_kpk_db  = KvDb(HashMap::new());
        let bob = setup_bob(&mut bob_pk_db, &mut bob_spk_db, &mut bob_kpk_db);

        // Reconstruct Bob's public key components for the bundle
        let mut opk_rec: *mut c_void = ptr::null_mut();
        pk_load(&mut opk_rec, bob.opk_id, &mut bob_pk_db as *mut KvDb as *mut c_void);
        let mut opk_pub: *mut c_void = ptr::null_mut();
        must!(ffi::signal_pre_key_record_get_public_key(&mut opk_pub, opk_rec as *const c_void));
        ffi::signal_pre_key_record_destroy(opk_rec);

        let mut spk_rec: *mut c_void = ptr::null_mut();
        spk_load(&mut spk_rec, bob.spk_id, &mut bob_spk_db as *mut KvDb as *mut c_void);
        let mut spk_pub: *mut c_void = ptr::null_mut();
        must!(ffi::signal_signed_pre_key_record_get_public_key(&mut spk_pub, spk_rec as *const c_void));
        let mut spk_sig = OwnedBuffer::ZERO;
        must!(ffi::signal_signed_pre_key_record_get_signature(&mut spk_sig, spk_rec as *const c_void));
        ffi::signal_signed_pre_key_record_destroy(spk_rec);

        let mut kpk_rec: *mut c_void = ptr::null_mut();
        kpk_load(&mut kpk_rec, bob.kpk_id, &mut bob_kpk_db as *mut KvDb as *mut c_void);
        let mut kpk_pub: *mut c_void = ptr::null_mut();
        must!(ffi::signal_kyber_pre_key_record_get_public_key(&mut kpk_pub, kpk_rec as *const c_void));
        let mut kpk_sig = OwnedBuffer::ZERO;
        must!(ffi::signal_kyber_pre_key_record_get_signature(&mut kpk_sig, kpk_rec as *const c_void));
        ffi::signal_kyber_pre_key_record_destroy(kpk_rec);

        let mut bob_id_priv_h: *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_deserialize(&mut bob_id_priv_h, borrow(&bob.id_priv)));
        let mut bob_id_pub: *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_get_public_key(&mut bob_id_pub, bob_id_priv_h as *const c_void));
        ffi::signal_privatekey_destroy(bob_id_priv_h);

        let mut bundle: *mut c_void = ptr::null_mut();
        must!(ffi::signal_pre_key_bundle_new(
            &mut bundle,
            bob.reg_id, 1,
            bob.opk_id, true,  opk_pub as *const c_void,
            bob.spk_id,        spk_pub as *const c_void,
            BorrowedBuffer { base: spk_sig.base, length: spk_sig.length },
            bob_id_pub as *const c_void,
            bob.kpk_id, true,  kpk_pub as *const c_void,
            BorrowedBuffer { base: kpk_sig.base, length: kpk_sig.length },
        ));
        ffi::signal_publickey_destroy(opk_pub); ffi::signal_publickey_destroy(spk_pub);
        ffi::signal_free_buffer(spk_sig.base, spk_sig.length);
        ffi::signal_kyber_public_key_destroy(kpk_pub);
        ffi::signal_free_buffer(kpk_sig.base, kpk_sig.length);
        ffi::signal_publickey_destroy(bob_id_pub);

        // Alice's stores
        let mut alice_sess_db = KvDb(HashMap::new());
        let mut alice_pk_db   = KvDb(HashMap::new());
        let mut alice_spk_db  = KvDb(HashMap::new());
        let mut alice_kpk_db  = KvDb(HashMap::new());
        let mut alice_id_db   = IdDb { priv_bytes: alice_priv_vec, reg_id: 1001, trusted: KvDb(HashMap::new()) };
        let mut bob_id_db     = IdDb { priv_bytes: bob.id_priv.clone(), reg_id: bob.reg_id, trusted: KvDb(HashMap::new()) };

        let mut bob_addr: *mut c_void = ptr::null_mut();
        let bob_name = CString::new("bob").unwrap();
        must!(ffi::signal_address_new(&mut bob_addr, bob_name.as_ptr(), 1));
        let mut alice_addr: *mut c_void = ptr::null_mut();
        let alice_name = CString::new("alice").unwrap();
        must!(ffi::signal_address_new(&mut alice_addr, alice_name.as_ptr(), 1));

        let a_ss  = make_sess_store(&mut alice_sess_db);
        let a_is  = make_id_store(&mut alice_id_db);
        let a_pks = make_pk_store(&mut alice_pk_db);
        let a_sks = make_spk_store(&mut alice_spk_db);
        let a_kks = make_kpk_store(&mut alice_kpk_db);

        must!(ffi::signal_process_prekey_bundle(
            bundle as *const c_void, bob_addr as *const c_void,
            &a_ss, &a_is, &a_pks, &a_sks, &a_kks,
        ));
        ffi::signal_pre_key_bundle_destroy(bundle);

        // Alice encrypts — first message is PreKeySignalMessage (type 3)
        let pt1 = b"hello bob";
        let mut ct1: *mut c_void = ptr::null_mut();
        must!(ffi::signal_encrypt_message(
            &mut ct1, borrow(pt1), bob_addr as *const c_void,
            &a_ss, &a_is, &a_pks, &a_sks,
        ));
        let mut ct1_type: u8 = 0;
        must!(ffi::signal_ciphertext_message_type(&mut ct1_type, ct1 as *const c_void));
        let mut ct1_bytes = OwnedBuffer::ZERO;
        must!(ffi::signal_ciphertext_message_serialize(&mut ct1_bytes, ct1 as *const c_void));
        ffi::signal_ciphertext_message_destroy(ct1);
        assert_eq!(ct1_type, 3, "[FAIL] expected PreKey msg type 3, got {}", ct1_type);

        // Bob decrypts the pre-key message
        let b_ss  = make_sess_store(&mut bob_sess_db);
        let b_is  = make_id_store(&mut bob_id_db);
        let b_pks = make_pk_store(&mut bob_pk_db);
        let b_sks = make_spk_store(&mut bob_spk_db);
        let b_kks = make_kpk_store(&mut bob_kpk_db);

        let mut pkmsg: *mut c_void = ptr::null_mut();
        must!(ffi::signal_pre_key_signal_message_deserialize(
            &mut pkmsg, BorrowedBuffer { base: ct1_bytes.base, length: ct1_bytes.length }));
        ffi::signal_free_buffer(ct1_bytes.base, ct1_bytes.length);

        let mut dec1 = OwnedBuffer::ZERO;
        must!(ffi::signal_decrypt_pre_key_message(
            &mut dec1, pkmsg as *const c_void, alice_addr as *const c_void,
            &b_ss, &b_is, &b_pks, &b_sks, &b_kks,
        ));
        ffi::signal_pre_key_signal_message_destroy(pkmsg);
        assert_eq!(std::slice::from_raw_parts(dec1.base, dec1.length), pt1.as_ref(), "[FAIL] pre-key plaintext");
        ffi::signal_free_buffer(dec1.base, dec1.length);

        // Bob replies — now a regular whisper message (type 2)
        let pt2 = b"hey alice";
        let mut ct2: *mut c_void = ptr::null_mut();
        must!(ffi::signal_encrypt_message(
            &mut ct2, borrow(pt2), alice_addr as *const c_void,
            &b_ss, &b_is, &b_pks, &b_sks,
        ));
        let mut ct2_type: u8 = 0;
        must!(ffi::signal_ciphertext_message_type(&mut ct2_type, ct2 as *const c_void));
        let mut ct2_bytes = OwnedBuffer::ZERO;
        must!(ffi::signal_ciphertext_message_serialize(&mut ct2_bytes, ct2 as *const c_void));
        ffi::signal_ciphertext_message_destroy(ct2);
        assert_eq!(ct2_type, 2, "[FAIL] expected whisper msg type 2, got {}", ct2_type);

        let mut whisper: *mut c_void = ptr::null_mut();
        must!(ffi::signal_message_deserialize(
            &mut whisper, BorrowedBuffer { base: ct2_bytes.base, length: ct2_bytes.length }));
        ffi::signal_free_buffer(ct2_bytes.base, ct2_bytes.length);

        let mut dec2 = OwnedBuffer::ZERO;
        must!(ffi::signal_decrypt_message(
            &mut dec2, whisper as *const c_void, bob_addr as *const c_void,
            &a_ss, &a_is,
        ));
        ffi::signal_message_destroy(whisper);
        assert_eq!(std::slice::from_raw_parts(dec2.base, dec2.length), pt2.as_ref(), "[FAIL] whisper plaintext");
        ffi::signal_free_buffer(dec2.base, dec2.length);

        ffi::signal_address_destroy(bob_addr);
        ffi::signal_address_destroy(alice_addr);
    }
    println!("X3DH + PQXDH + Double Ratchet PASS");
}

fn test_group() {
    let dist_id: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    unsafe {
        let mut alice_sk_db = KvDb(HashMap::new());
        let mut bob_sk_db   = KvDb(HashMap::new());
        let a_store = make_sk_store(&mut alice_sk_db);
        let b_store = make_sk_store(&mut bob_sk_db);

        let mut alice_addr: *mut c_void = ptr::null_mut();
        let alice_name = CString::new("alice").unwrap();
        must!(ffi::signal_address_new(&mut alice_addr, alice_name.as_ptr(), 1));
        let ca = alice_addr as *const c_void;

        let mut skdm: *mut c_void = ptr::null_mut();
        must!(ffi::signal_sender_key_distribution_message_create(&mut skdm, ca,
            BorrowedBuffer { base: dist_id.as_ptr(), length: dist_id.len() }, &a_store));
        must!(ffi::signal_process_sender_key_distribution_message(ca, skdm as *const c_void, &b_store));
        ffi::signal_sender_key_distribution_message_destroy(skdm);

        let msg = b"group hello";
        let mut enc = OwnedBuffer::ZERO;
        must!(ffi::signal_group_encrypt_message(&mut enc, ca,
            BorrowedBuffer { base: dist_id.as_ptr(), length: dist_id.len() }, borrow(msg), &a_store));

        let mut dec = OwnedBuffer::ZERO;
        must!(ffi::signal_group_decrypt_message(
            &mut dec, ca,
            BorrowedBuffer { base: dist_id.as_ptr(), length: dist_id.len() },
            BorrowedBuffer { base: enc.base, length: enc.length }, &b_store));
        ffi::signal_free_buffer(enc.base, enc.length);

        assert_eq!(std::slice::from_raw_parts(dec.base, dec.length), msg.as_ref(), "[FAIL] group plaintext");
        ffi::signal_free_buffer(dec.base, dec.length);
        ffi::signal_address_destroy(alice_addr);
    }
    println!("Sender Keys (group)           PASS");
}

fn test_fingerprint() {
    unsafe {
        let mut pa: *mut c_void = ptr::null_mut();
        let mut pb: *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_generate(&mut pa));
        must!(ffi::signal_privatekey_generate(&mut pb));
        let mut qa: *mut c_void = ptr::null_mut();
        let mut qb: *mut c_void = ptr::null_mut();
        must!(ffi::signal_privatekey_get_public_key(&mut qa, pa as *const c_void));
        must!(ffi::signal_privatekey_get_public_key(&mut qb, pb as *const c_void));
        ffi::signal_privatekey_destroy(pa); ffi::signal_privatekey_destroy(pb);

        let alice_id = b"+15551234567";
        let bob_id   = b"+15559876543";

        let mut fp_a: *mut c_void = ptr::null_mut();
        let mut fp_b: *mut c_void = ptr::null_mut();
        must!(ffi::signal_fingerprint_new(&mut fp_a, 5200, 0, borrow(alice_id), qa as *const c_void, borrow(bob_id), qb as *const c_void));
        must!(ffi::signal_fingerprint_new(&mut fp_b, 5200, 0, borrow(bob_id), qb as *const c_void, borrow(alice_id), qa as *const c_void));
        ffi::signal_publickey_destroy(qa); ffi::signal_publickey_destroy(qb);

        let mut scan_b = OwnedBuffer::ZERO;
        must!(ffi::signal_fingerprint_scannable_encoding(&mut scan_b, fp_b as *const c_void));

        let mut matched = false;
        must!(ffi::signal_fingerprint_compare(
            &mut matched, fp_a as *const c_void,
            BorrowedBuffer { base: scan_b.base, length: scan_b.length }));
        assert!(matched, "[FAIL] fingerprint mismatch");
        ffi::signal_free_buffer(scan_b.base, scan_b.length);
        ffi::signal_fingerprint_destroy(fp_a); ffi::signal_fingerprint_destroy(fp_b);
    }
    println!("Fingerprints                  PASS");
}

fn test_username() {
    unsafe {
        let name = CString::new("alice.42").unwrap();
        let mut hash = [0u8; 32];
        must!(ffi::signal_username_hash(hash.as_mut_ptr(), name.as_ptr()));

        let mut proof = OwnedBuffer::ZERO;
        must!(ffi::signal_username_proof(&mut proof, name.as_ptr()));

        let mut valid = false;
        must!(ffi::signal_username_verify(&mut valid, hash.as_ptr(),
            BorrowedBuffer { base: proof.base, length: proof.length }));
        assert!(valid, "[FAIL] username proof invalid");
        ffi::signal_free_buffer(proof.base, proof.length);
    }
    println!("Username ZK proof             PASS");
}

fn test_account_keys() {
    unsafe {
        let mut pool: *mut c_void = ptr::null_mut();
        must!(ffi::signal_account_entropy_pool_generate(&mut pool));
        let cp = pool as *const c_void;

        let mut s: *const c_char = ptr::null();
        must!(ffi::signal_account_entropy_pool_as_string(&mut s, cp));
        println!("  Entropy pool: {:.16}…", CStr::from_ptr(s).to_string_lossy());
        ffi::signal_free_string(s as *mut c_char);

        let mut svr    = [0u8; 32];
        let mut bk_raw = [0u8; 32];
        must!(ffi::signal_account_entropy_pool_derive_svr_key(svr.as_mut_ptr(), cp));
        must!(ffi::signal_account_entropy_pool_derive_backup_key(bk_raw.as_mut_ptr(), cp));
        ffi::signal_account_entropy_pool_destroy(pool);
        assert_ne!(svr, bk_raw, "[FAIL] svr_key == backup_key");

        let mut bk: *mut c_void = ptr::null_mut();
        must!(ffi::signal_backup_key_from_bytes(&mut bk, borrow(&bk_raw)));
        let mut media = [0u8; 32];
        must!(ffi::signal_backup_key_derive_media_encryption_key(media.as_mut_ptr(), bk as *const c_void));
        ffi::signal_backup_key_destroy(bk);
        assert_ne!(bk_raw, media, "[FAIL] backup_key == media_key");
    }
    println!("Account entropy pool          PASS");
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    test_ec_keys();
    test_kyber_keys();
    test_session();
    test_group();
    test_fingerprint();
    test_username();
    test_account_keys();
    println!("\nAll signal_ffi tests PASSED.");
}
