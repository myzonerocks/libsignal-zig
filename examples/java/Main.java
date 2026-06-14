// examples/java/Main.java — signal_ffi.h round-trip exerciser (Java + JNA)
//
// Each section exercises a real-world roundtrip through the signal_ffi API.
// Run with:  ./run.sh
import com.sun.jna.*;
import com.sun.jna.ptr.*;
import java.util.*;
import java.nio.file.*;

public class Main {

    static final String LIB_DIR = Paths.get(
        System.getProperty("user.dir"), "..", "..", "zig-out", "lib"
    ).toAbsolutePath().normalize().toString();

    // ── OwnedBuffer / BorrowedBuffer ──────────────────────────────────────────
    // signal_ffi.h passes these structs by value.  JNA ByValue subclasses handle that.

    @Structure.FieldOrder({"base", "length"})
    public static class OwnedBuffer extends Structure {
        public Pointer base;
        public long    length;   // size_t
        public static class ByValue extends OwnedBuffer implements Structure.ByValue {}
        public static class ByRef   extends OwnedBuffer implements Structure.ByReference {}
    }

    @Structure.FieldOrder({"base", "length"})
    public static class BorrowedBuffer extends Structure {
        public Pointer base;
        public long    length;
        public static class ByValue extends BorrowedBuffer implements Structure.ByValue {}
    }

    static BorrowedBuffer.ByValue borrow(byte[] bytes) {
        Memory m = new Memory(bytes.length);
        m.write(0, bytes, 0, bytes.length);
        BorrowedBuffer.ByValue b = new BorrowedBuffer.ByValue();
        b.base   = m;
        b.length = bytes.length;
        return b;
    }

    // ── Store callback interfaces ─────────────────────────────────────────────
    // All Signal{Mut,Const}Pointer<T> structs contain exactly one pointer field.
    // On arm64/x86-64 they are ABI-equivalent to a bare Pointer.

    interface SessLoadCb  extends Callback { Pointer invoke(Pointer out, Pointer addr, Pointer ud); }
    interface SessStoreCb extends Callback { Pointer invoke(Pointer addr, Pointer rec, Pointer ud); }
    interface IdGetKpCb   extends Callback { Pointer invoke(Pointer outPub, Pointer outPriv, Pointer ud); }
    interface IdGetRegCb  extends Callback { Pointer invoke(Pointer out, Pointer ud); }
    interface IdSaveCb    extends Callback { Pointer invoke(Pointer addr, Pointer key, Pointer ud); }
    interface IdTrustedCb extends Callback { Pointer invoke(Pointer out, Pointer addr, Pointer key, int dir, Pointer ud); }
    interface IdGetIdCb   extends Callback { Pointer invoke(Pointer out, Pointer addr, Pointer ud); }
    interface PkLoadCb    extends Callback { Pointer invoke(Pointer out, int id, Pointer ud); }
    interface PkStoreCb   extends Callback { Pointer invoke(int id, Pointer rec, Pointer ud); }
    interface PkRemoveCb  extends Callback { Pointer invoke(int id, Pointer ud); }
    interface SpkLoadCb   extends Callback { Pointer invoke(Pointer out, int id, Pointer ud); }
    interface SpkStoreCb  extends Callback { Pointer invoke(int id, Pointer rec, Pointer ud); }
    interface KpkLoadCb   extends Callback { Pointer invoke(Pointer out, int id, Pointer ud); }
    interface KpkStoreCb  extends Callback { Pointer invoke(int id, Pointer rec, Pointer ud); }
    interface KpkMarkCb   extends Callback { Pointer invoke(int id, Pointer ud); }
    interface SkStoreCb   extends Callback { Pointer invoke(Pointer addr, Pointer dist, Pointer rec, Pointer ud); }
    interface SkLoadCb    extends Callback { Pointer invoke(Pointer out, Pointer addr, Pointer dist, Pointer ud); }

    // ── Library interface ─────────────────────────────────────────────────────

    interface Lib extends Library {
        // Error
        Pointer signal_error_get_message(PointerByReference out, Pointer err);
        void    signal_error_free(Pointer err);
        void    signal_free_buffer(Pointer buf, long len);
        void    signal_free_string(Pointer s);

        // EC keys
        Pointer signal_privatekey_generate(PointerByReference out);
        Pointer signal_privatekey_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_privatekey_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_privatekey_get_public_key(PointerByReference out, Pointer obj);
        Pointer signal_privatekey_agree(OwnedBuffer.ByRef out, Pointer priv, Pointer pub);
        Pointer signal_privatekey_sign(OwnedBuffer.ByRef out, Pointer priv, BorrowedBuffer.ByValue msg);
        Pointer signal_privatekey_destroy(Pointer obj);
        Pointer signal_publickey_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_publickey_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_publickey_verify(ByteByReference out, Pointer pub, BorrowedBuffer.ByValue msg, BorrowedBuffer.ByValue sig);
        Pointer signal_publickey_destroy(Pointer obj);

        // Address
        Pointer signal_address_new(PointerByReference out, String name, int device_id);
        Pointer signal_address_get_name(PointerByReference out, Pointer addr);
        Pointer signal_address_get_device_id(IntByReference out, Pointer addr);
        Pointer signal_address_destroy(Pointer obj);

        // Pre-key records
        Pointer signal_pre_key_record_new(PointerByReference out, int id, Pointer pub, Pointer priv);
        Pointer signal_pre_key_record_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_pre_key_record_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_pre_key_record_get_public_key(PointerByReference out, Pointer obj);
        Pointer signal_pre_key_record_destroy(Pointer obj);

        // Signed pre-key records
        Pointer signal_signed_pre_key_record_new(PointerByReference out, int id, long ts,
                    Pointer pub, Pointer priv, BorrowedBuffer.ByValue sig);
        Pointer signal_signed_pre_key_record_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_signed_pre_key_record_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_signed_pre_key_record_get_public_key(PointerByReference out, Pointer obj);
        Pointer signal_signed_pre_key_record_get_signature(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_signed_pre_key_record_destroy(Pointer obj);

        // Kyber keys and records
        Pointer signal_kyber_key_pair_generate(PointerByReference out);
        Pointer signal_kyber_key_pair_get_public_key(PointerByReference out, Pointer kp);
        Pointer signal_kyber_key_pair_get_secret_key(PointerByReference out, Pointer kp);
        Pointer signal_kyber_key_pair_destroy(Pointer obj);
        Pointer signal_kyber_public_key_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_kyber_public_key_destroy(Pointer obj);
        Pointer signal_kyber_secret_key_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_kyber_secret_key_destroy(Pointer obj);
        Pointer signal_kyber_pre_key_record_new(PointerByReference out, int id, long ts,
                    Pointer kp, BorrowedBuffer.ByValue sig);
        Pointer signal_kyber_pre_key_record_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_kyber_pre_key_record_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_kyber_pre_key_record_get_public_key(PointerByReference out, Pointer obj);
        Pointer signal_kyber_pre_key_record_get_signature(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_kyber_pre_key_record_destroy(Pointer obj);

        // Session record
        Pointer signal_session_record_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_session_record_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);

        // Sender key record
        Pointer signal_sender_key_record_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_sender_key_record_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);

        // Pre-key bundle
        Pointer signal_pre_key_bundle_new(PointerByReference out,
                    int reg_id, int device_id,
                    int opk_id, boolean has_opk, Pointer opk_pub,
                    int spk_id, Pointer spk_pub, BorrowedBuffer.ByValue spk_sig,
                    Pointer id_pub,
                    int kpk_id, boolean has_kpk, Pointer kpk_pub,
                    BorrowedBuffer.ByValue kpk_sig);
        Pointer signal_pre_key_bundle_destroy(Pointer obj);

        // Session protocol
        Pointer signal_process_prekey_bundle(Pointer bundle, Pointer addr,
                    Pointer ss, Pointer is, Pointer pks, Pointer sks, Pointer kks);
        Pointer signal_encrypt_message(PointerByReference out, BorrowedBuffer.ByValue pt,
                    Pointer addr, Pointer ss, Pointer is, Pointer pks, Pointer sks);
        Pointer signal_ciphertext_message_serialize(OwnedBuffer.ByRef out, Pointer obj);
        Pointer signal_ciphertext_message_destroy(Pointer obj);
        Pointer signal_pre_key_signal_message_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_pre_key_signal_message_destroy(Pointer obj);
        Pointer signal_decrypt_pre_key_message(OwnedBuffer.ByRef out, Pointer msg, Pointer addr,
                    Pointer ss, Pointer is, Pointer pks, Pointer sks, Pointer kks);
        Pointer signal_message_deserialize(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_message_destroy(Pointer obj);
        Pointer signal_decrypt_message(OwnedBuffer.ByRef out, Pointer msg, Pointer addr,
                    Pointer ss, Pointer is);

        // Group
        Pointer signal_sender_key_distribution_message_create(PointerByReference out,
                    Pointer addr, BorrowedBuffer.ByValue dist_id, Pointer sk_store);
        Pointer signal_process_sender_key_distribution_message(Pointer addr, Pointer skdm, Pointer sk_store);
        Pointer signal_group_encrypt_message(OwnedBuffer.ByRef out, Pointer addr,
                    BorrowedBuffer.ByValue dist_id, BorrowedBuffer.ByValue pt, Pointer sk_store);
        Pointer signal_group_decrypt_message(OwnedBuffer.ByRef out, Pointer addr,
                    BorrowedBuffer.ByValue dist_id, BorrowedBuffer.ByValue ct, Pointer sk_store);
        Pointer signal_sender_key_distribution_message_destroy(Pointer obj);

        // Fingerprint
        Pointer signal_fingerprint_new(PointerByReference out, int iterations, int version,
                    BorrowedBuffer.ByValue local_id, Pointer local_key,
                    BorrowedBuffer.ByValue remote_id, Pointer remote_key);
        Pointer signal_fingerprint_scannable_encoding(OwnedBuffer.ByRef out, Pointer fp);
        Pointer signal_fingerprint_compare(ByteByReference out, Pointer fp,
                    BorrowedBuffer.ByValue their_scannable);
        Pointer signal_fingerprint_destroy(Pointer obj);

        // Username
        Pointer signal_username_hash(Pointer hash_out32, String username);
        Pointer signal_username_proof(OwnedBuffer.ByRef out, String username);
        Pointer signal_username_verify(ByteByReference out, Pointer hash, BorrowedBuffer.ByValue proof);

        // Account keys
        Pointer signal_account_entropy_pool_generate(PointerByReference out);
        Pointer signal_account_entropy_pool_as_string(PointerByReference out, Pointer pool);
        Pointer signal_account_entropy_pool_derive_svr_key(Pointer out32, Pointer pool);
        Pointer signal_account_entropy_pool_derive_backup_key(Pointer out32, Pointer pool);
        Pointer signal_account_entropy_pool_destroy(Pointer obj);
        Pointer signal_backup_key_from_bytes(PointerByReference out, BorrowedBuffer.ByValue bytes);
        Pointer signal_backup_key_derive_media_encryption_key(Pointer out32, Pointer bk);
        Pointer signal_backup_key_destroy(Pointer obj);
    }

    static Lib lib;

    // ── Helpers ───────────────────────────────────────────────────────────────

    static void must(Pointer err, String label) {
        if (err == null) return;
        PointerByReference msgPP = new PointerByReference();
        lib.signal_error_get_message(msgPP, err);
        Pointer msgP = msgPP.getValue();
        String msg = msgP != null ? msgP.getString(0) : "(no message)";
        lib.signal_error_free(err);
        throw new RuntimeException("[FAIL] " + label + ": " + msg);
    }

    static byte[] readOwned(OwnedBuffer.ByRef b) {
        byte[] data = b.base.getByteArray(0, (int) b.length);
        lib.signal_free_buffer(b.base, b.length);
        return data;
    }

    static String addrKey(Pointer addr) {
        PointerByReference namePP = new PointerByReference();
        IntByReference     devP   = new IntByReference();
        must(lib.signal_address_get_name(namePP, addr),      "addr_get_name");
        must(lib.signal_address_get_device_id(devP, addr),   "addr_get_dev");
        return namePP.getValue().getString(0) + ":" + devP.getValue();
    }

    static byte[] signBytes(byte[] priv32, byte[] data) {
        PointerByReference privOut = new PointerByReference();
        must(lib.signal_privatekey_deserialize(privOut, borrow(priv32)), "sb_deser");
        OwnedBuffer.ByRef sig = new OwnedBuffer.ByRef();
        must(lib.signal_privatekey_sign(sig, privOut.getValue(), borrow(data)), "sb_sign");
        lib.signal_privatekey_destroy(privOut.getValue());
        return readOwned(sig);
    }

    // ── Store structs (8-pointer layout: ptr + up to 7 callbacks) ────────────
    // Each signal_ffi store struct is: {user_data, cb0, cb1, ..., reserved=null}
    // We allocate a pointer array and fill it in.

    static Pointer makeSessionStore(Map<String, byte[]> db,
                                     SessLoadCb load, SessStoreCb store) {
        Pointer p = new Memory(4 * Native.POINTER_SIZE);
        p.setPointer(0, null);
        p.setPointer(Native.POINTER_SIZE,     CallbackReference.getFunctionPointer(load));
        p.setPointer(2 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(store));
        p.setPointer(3 * Native.POINTER_SIZE, null);
        return p;
    }
    static Pointer makeIdentityStore(IdGetKpCb gkp, IdGetRegCb grg, IdSaveCb sv,
                                      IdTrustedCb tr, IdGetIdCb gi) {
        Pointer p = new Memory(7 * Native.POINTER_SIZE);
        p.setPointer(0,                       null);
        p.setPointer(Native.POINTER_SIZE,     CallbackReference.getFunctionPointer(gkp));
        p.setPointer(2 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(grg));
        p.setPointer(3 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(sv));
        p.setPointer(4 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(tr));
        p.setPointer(5 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(gi));
        p.setPointer(6 * Native.POINTER_SIZE, null);
        return p;
    }
    static Pointer makePreKeyStore(PkLoadCb ld, PkStoreCb st, PkRemoveCb rm) {
        Pointer p = new Memory(5 * Native.POINTER_SIZE);
        p.setPointer(0,                       null);
        p.setPointer(Native.POINTER_SIZE,     CallbackReference.getFunctionPointer(ld));
        p.setPointer(2 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(st));
        p.setPointer(3 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(rm));
        p.setPointer(4 * Native.POINTER_SIZE, null);
        return p;
    }
    static Pointer makeSignedPreKeyStore(SpkLoadCb ld, SpkStoreCb st) {
        Pointer p = new Memory(4 * Native.POINTER_SIZE);
        p.setPointer(0,                       null);
        p.setPointer(Native.POINTER_SIZE,     CallbackReference.getFunctionPointer(ld));
        p.setPointer(2 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(st));
        p.setPointer(3 * Native.POINTER_SIZE, null);
        return p;
    }
    static Pointer makeKyberStore(KpkLoadCb ld, KpkStoreCb st, KpkMarkCb mk) {
        Pointer p = new Memory(5 * Native.POINTER_SIZE);
        p.setPointer(0,                       null);
        p.setPointer(Native.POINTER_SIZE,     CallbackReference.getFunctionPointer(ld));
        p.setPointer(2 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(st));
        p.setPointer(3 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(mk));
        p.setPointer(4 * Native.POINTER_SIZE, null);
        return p;
    }
    static Pointer makeSenderKeyStore(SkStoreCb st, SkLoadCb ld) {
        Pointer p = new Memory(4 * Native.POINTER_SIZE);
        p.setPointer(0,                       null);
        p.setPointer(Native.POINTER_SIZE,     CallbackReference.getFunctionPointer(st));
        p.setPointer(2 * Native.POINTER_SIZE, CallbackReference.getFunctionPointer(ld));
        p.setPointer(3 * Native.POINTER_SIZE, null);
        return p;
    }

    // ── Test helpers — build store objects that call back into signal_ffi ─────

    static class SessDB {
        final Map<String, byte[]> db = new HashMap<>();
        final SessLoadCb  load;
        final SessStoreCb store;
        final Pointer     ptr;

        SessDB() {
            load = (out, addr, ud) -> {
                byte[] data = db.get(addrKey(addr));
                if (data == null) { out.setPointer(0, null); return null; }
                PointerByReference recOut = new PointerByReference();
                // call library from within callback — works in JNA
                out.setPointer(0, null);
                Pointer e = lib.signal_session_record_deserialize(recOut, borrow(data));
                if (e != null) return e;
                out.setPointer(0, recOut.getValue());
                return null;
            };
            store = (addr, rec, ud) -> {
                OwnedBuffer.ByRef b = new OwnedBuffer.ByRef();
                Pointer e = lib.signal_session_record_serialize(b, rec);
                if (e != null) return e;
                db.put(addrKey(addr), b.base.getByteArray(0, (int) b.length));
                lib.signal_free_buffer(b.base, b.length);
                return null;
            };
            ptr = makeSessionStore(db, load, store);
        }
    }

    static class IdDB {
        final byte[]      privBytes;
        final int         regId;
        final Map<String, byte[]> trusted = new HashMap<>();
        final IdGetKpCb   getKp;
        final IdGetRegCb  getReg;
        final IdSaveCb    save;
        final IdTrustedCb isTrusted;
        final IdGetIdCb   getId;
        final Pointer     ptr;

        IdDB(byte[] privBytes, int regId) {
            this.privBytes = privBytes;
            this.regId     = regId;
            getKp = (outPub, outPriv, ud) -> {
                PointerByReference privOut = new PointerByReference();
                Pointer e = lib.signal_privatekey_deserialize(privOut, borrow(privBytes));
                if (e != null) return e;
                PointerByReference pubOut = new PointerByReference();
                e = lib.signal_privatekey_get_public_key(pubOut, privOut.getValue());
                if (e != null) return e;
                outPriv.setPointer(0, privOut.getValue());
                outPub.setPointer(0, pubOut.getValue());
                return null;
            };
            getReg    = (out, ud) -> { out.setInt(0, regId); return null; };
            save      = (addr, key, ud) -> {
                OwnedBuffer.ByRef b = new OwnedBuffer.ByRef();
                Pointer e = lib.signal_publickey_serialize(b, key);
                if (e != null) return e;
                trusted.put(addrKey(addr), b.base.getByteArray(0, (int) b.length));
                lib.signal_free_buffer(b.base, b.length);
                return null;
            };
            isTrusted = (out, addr, key, dir, ud) -> { out.setByte(0, (byte) 1); return null; };
            getId     = (out, addr, ud) -> {
                byte[] data = trusted.get(addrKey(addr));
                if (data == null) { out.setPointer(0, null); return null; }
                PointerByReference pubOut = new PointerByReference();
                Pointer e = lib.signal_publickey_deserialize(pubOut, borrow(data));
                if (e != null) return e;
                out.setPointer(0, pubOut.getValue());
                return null;
            };
            ptr = makeIdentityStore(getKp, getReg, save, isTrusted, getId);
        }
    }

    static class PkDB {
        final Map<Integer, byte[]> db = new HashMap<>();
        final PkLoadCb   load;
        final PkStoreCb  store;
        final PkRemoveCb remove;
        final Pointer    ptr;

        PkDB() {
            load = (out, id, ud) -> {
                byte[] data = db.get(id);
                if (data == null) { out.setPointer(0, null); return null; }
                PointerByReference recOut = new PointerByReference();
                Pointer e = lib.signal_pre_key_record_deserialize(recOut, borrow(data));
                if (e != null) return e;
                out.setPointer(0, recOut.getValue());
                return null;
            };
            store = (id, rec, ud) -> {
                OwnedBuffer.ByRef b = new OwnedBuffer.ByRef();
                Pointer e = lib.signal_pre_key_record_serialize(b, rec);
                if (e != null) return e;
                db.put(id, b.base.getByteArray(0, (int) b.length));
                lib.signal_free_buffer(b.base, b.length);
                return null;
            };
            remove = (id, ud) -> null;
            ptr = makePreKeyStore(load, store, remove);
        }
    }

    static class SpkDB {
        final Map<Integer, byte[]> db = new HashMap<>();
        final SpkLoadCb  load;
        final SpkStoreCb store;
        final Pointer    ptr;

        SpkDB() {
            load = (out, id, ud) -> {
                byte[] data = db.get(id);
                if (data == null) { out.setPointer(0, null); return null; }
                PointerByReference recOut = new PointerByReference();
                Pointer e = lib.signal_signed_pre_key_record_deserialize(recOut, borrow(data));
                if (e != null) return e;
                out.setPointer(0, recOut.getValue());
                return null;
            };
            store = (id, rec, ud) -> {
                OwnedBuffer.ByRef b = new OwnedBuffer.ByRef();
                Pointer e = lib.signal_signed_pre_key_record_serialize(b, rec);
                if (e != null) return e;
                db.put(id, b.base.getByteArray(0, (int) b.length));
                lib.signal_free_buffer(b.base, b.length);
                return null;
            };
            ptr = makeSignedPreKeyStore(load, store);
        }
    }

    static class KpkDB {
        final Map<Integer, byte[]> db = new HashMap<>();
        final KpkLoadCb  load;
        final KpkStoreCb store;
        final KpkMarkCb  mark;
        final Pointer    ptr;

        KpkDB() {
            load = (out, id, ud) -> {
                byte[] data = db.get(id);
                if (data == null) { out.setPointer(0, null); return null; }
                PointerByReference recOut = new PointerByReference();
                Pointer e = lib.signal_kyber_pre_key_record_deserialize(recOut, borrow(data));
                if (e != null) return e;
                out.setPointer(0, recOut.getValue());
                return null;
            };
            store = (id, rec, ud) -> {
                OwnedBuffer.ByRef b = new OwnedBuffer.ByRef();
                Pointer e = lib.signal_kyber_pre_key_record_serialize(b, rec);
                if (e != null) return e;
                db.put(id, b.base.getByteArray(0, (int) b.length));
                lib.signal_free_buffer(b.base, b.length);
                return null;
            };
            mark = (id, ud) -> null;
            ptr  = makeKyberStore(load, store, mark);
        }
    }

    static class SkDB {
        final Map<String, byte[]> db = new HashMap<>();
        final SkStoreCb store;
        final SkLoadCb  load;
        final Pointer   ptr;

        static String skKey(Pointer addr, Pointer dist) {
            StringBuilder sb = new StringBuilder(addrKey(addr)).append(":");
            byte[] d = dist.getByteArray(0, 16);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        }

        SkDB() {
            store = (addr, dist, rec, ud) -> {
                OwnedBuffer.ByRef b = new OwnedBuffer.ByRef();
                Pointer e = lib.signal_sender_key_record_serialize(b, rec);
                if (e != null) return e;
                db.put(skKey(addr, dist), b.base.getByteArray(0, (int) b.length));
                lib.signal_free_buffer(b.base, b.length);
                return null;
            };
            load = (out, addr, dist, ud) -> {
                byte[] data = db.get(skKey(addr, dist));
                if (data == null) { out.setPointer(0, null); return null; }
                PointerByReference recOut = new PointerByReference();
                Pointer e = lib.signal_sender_key_record_deserialize(recOut, borrow(data));
                if (e != null) return e;
                out.setPointer(0, recOut.getValue());
                return null;
            };
            ptr = makeSenderKeyStore(store, load);
        }
    }

    // ── Bob setup ─────────────────────────────────────────────────────────────

    static class BobKeys {
        byte[] idPriv; int regId = 2002; int opkId = 1, spkId = 1, kpkId = 1;
    }

    static BobKeys setupBob(PkDB pkDb, SpkDB spkDb, KpkDB kpkDb) {
        BobKeys b = new BobKeys();

        PointerByReference idPrivOut = new PointerByReference();
        must(lib.signal_privatekey_generate(idPrivOut), "bob_id_gen");
        OwnedBuffer.ByRef idBytes = new OwnedBuffer.ByRef();
        must(lib.signal_privatekey_serialize(idBytes, idPrivOut.getValue()), "bob_id_ser");
        b.idPriv = readOwned(idBytes);
        lib.signal_privatekey_destroy(idPrivOut.getValue());

        // OPK
        PointerByReference opkPriv = new PointerByReference(), opkPub = new PointerByReference();
        must(lib.signal_privatekey_generate(opkPriv), "opk_gen");
        must(lib.signal_privatekey_get_public_key(opkPub, opkPriv.getValue()), "opk_pub");
        PointerByReference opkRec = new PointerByReference();
        must(lib.signal_pre_key_record_new(opkRec, b.opkId, opkPub.getValue(), opkPriv.getValue()), "opk_rec");
        lib.signal_privatekey_destroy(opkPriv.getValue());
        lib.signal_publickey_destroy(opkPub.getValue());
        OwnedBuffer.ByRef opkSer = new OwnedBuffer.ByRef();
        must(lib.signal_pre_key_record_serialize(opkSer, opkRec.getValue()), "opk_ser");
        pkDb.db.put(b.opkId, readOwned(opkSer));
        lib.signal_pre_key_record_destroy(opkRec.getValue());

        // SPK
        PointerByReference spkPriv = new PointerByReference(), spkPub = new PointerByReference();
        must(lib.signal_privatekey_generate(spkPriv), "spk_gen");
        must(lib.signal_privatekey_get_public_key(spkPub, spkPriv.getValue()), "spk_pub");
        OwnedBuffer.ByRef spkPubSer = new OwnedBuffer.ByRef();
        must(lib.signal_publickey_serialize(spkPubSer, spkPub.getValue()), "spk_pub_ser");
        byte[] spkSigBytes = signBytes(b.idPriv, readOwned(spkPubSer));
        PointerByReference spkRec = new PointerByReference();
        must(lib.signal_signed_pre_key_record_new(spkRec, b.spkId, 1700000000L,
                spkPub.getValue(), spkPriv.getValue(), borrow(spkSigBytes)), "spk_rec");
        lib.signal_privatekey_destroy(spkPriv.getValue());
        lib.signal_publickey_destroy(spkPub.getValue());
        OwnedBuffer.ByRef spkSer = new OwnedBuffer.ByRef();
        must(lib.signal_signed_pre_key_record_serialize(spkSer, spkRec.getValue()), "spk_ser");
        spkDb.db.put(b.spkId, readOwned(spkSer));
        lib.signal_signed_pre_key_record_destroy(spkRec.getValue());

        // KPK
        PointerByReference kpk = new PointerByReference(), kpkPub = new PointerByReference();
        must(lib.signal_kyber_key_pair_generate(kpk), "kpk_gen");
        must(lib.signal_kyber_key_pair_get_public_key(kpkPub, kpk.getValue()), "kpk_pub");
        OwnedBuffer.ByRef kpkPubSer = new OwnedBuffer.ByRef();
        must(lib.signal_kyber_public_key_serialize(kpkPubSer, kpkPub.getValue()), "kpk_pub_ser");
        byte[] kpkSigBytes = signBytes(b.idPriv, readOwned(kpkPubSer));
        lib.signal_kyber_public_key_destroy(kpkPub.getValue());
        PointerByReference kpkRec = new PointerByReference();
        must(lib.signal_kyber_pre_key_record_new(kpkRec, b.kpkId, 1700000000L,
                kpk.getValue(), borrow(kpkSigBytes)), "kpk_rec");
        lib.signal_kyber_key_pair_destroy(kpk.getValue());
        OwnedBuffer.ByRef kpkSer = new OwnedBuffer.ByRef();
        must(lib.signal_kyber_pre_key_record_serialize(kpkSer, kpkRec.getValue()), "kpk_ser");
        kpkDb.db.put(b.kpkId, readOwned(kpkSer));
        lib.signal_kyber_pre_key_record_destroy(kpkRec.getValue());
        return b;
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    static void testEC() {
        PointerByReference pa = new PointerByReference(), pb = new PointerByReference();
        must(lib.signal_privatekey_generate(pa), "gen_a");
        must(lib.signal_privatekey_generate(pb), "gen_b");
        PointerByReference qa = new PointerByReference(), qb = new PointerByReference();
        must(lib.signal_privatekey_get_public_key(qa, pa.getValue()), "pub_a");
        must(lib.signal_privatekey_get_public_key(qb, pb.getValue()), "pub_b");

        OwnedBuffer.ByRef dhA = new OwnedBuffer.ByRef(), dhB = new OwnedBuffer.ByRef();
        must(lib.signal_privatekey_agree(dhA, pa.getValue(), qb.getValue()), "dh_a");
        must(lib.signal_privatekey_agree(dhB, pb.getValue(), qa.getValue()), "dh_b");
        if (!Arrays.equals(readOwned(dhA), readOwned(dhB)))
            throw new RuntimeException("[FAIL] DH secrets differ");

        byte[] msg = "hello signal".getBytes();
        OwnedBuffer.ByRef sig = new OwnedBuffer.ByRef();
        must(lib.signal_privatekey_sign(sig, pa.getValue(), borrow(msg)), "sign");
        byte[] sigBytes = readOwned(sig);
        ByteByReference ok = new ByteByReference();
        must(lib.signal_publickey_verify(ok, qa.getValue(), borrow(msg), borrow(sigBytes)), "verify");
        if (ok.getValue() == 0) throw new RuntimeException("[FAIL] XEdDSA verify failed");

        lib.signal_privatekey_destroy(pa.getValue()); lib.signal_privatekey_destroy(pb.getValue());
        lib.signal_publickey_destroy(qa.getValue());   lib.signal_publickey_destroy(qb.getValue());
        System.out.println("EC + XEdDSA                   PASS");
    }

    static void testKyber() {
        PointerByReference kp = new PointerByReference();
        must(lib.signal_kyber_key_pair_generate(kp), "kyber_gen");
        PointerByReference pub = new PointerByReference(), sec = new PointerByReference();
        must(lib.signal_kyber_key_pair_get_public_key(pub, kp.getValue()), "kyber_pub");
        must(lib.signal_kyber_key_pair_get_secret_key(sec, kp.getValue()), "kyber_sec");
        OwnedBuffer.ByRef pubB = new OwnedBuffer.ByRef(), secB = new OwnedBuffer.ByRef();
        must(lib.signal_kyber_public_key_serialize(pubB, pub.getValue()), "kyber_pub_ser");
        must(lib.signal_kyber_secret_key_serialize(secB, sec.getValue()), "kyber_sec_ser");
        if (pubB.length != 1568) throw new RuntimeException("[FAIL] Kyber pub size " + pubB.length);
        if (secB.length != 3168) throw new RuntimeException("[FAIL] Kyber sec size " + secB.length);
        lib.signal_free_buffer(pubB.base, pubB.length);
        lib.signal_free_buffer(secB.base, secB.length);
        lib.signal_kyber_key_pair_destroy(kp.getValue());
        lib.signal_kyber_public_key_destroy(pub.getValue());
        lib.signal_kyber_secret_key_destroy(sec.getValue());
        System.out.println("ML-KEM-1024 (Kyber)           PASS");
    }

    static void testSession() {
        // Alice identity
        PointerByReference alicePrivOut = new PointerByReference();
        must(lib.signal_privatekey_generate(alicePrivOut), "alice_id_gen");
        OwnedBuffer.ByRef aliceIdB = new OwnedBuffer.ByRef();
        must(lib.signal_privatekey_serialize(aliceIdB, alicePrivOut.getValue()), "alice_id_ser");
        byte[] aliceIdPriv = readOwned(aliceIdB);
        lib.signal_privatekey_destroy(alicePrivOut.getValue());

        // Bob's stores and key material
        PkDB  bobPk  = new PkDB();
        SpkDB bobSpk = new SpkDB();
        KpkDB bobKpk = new KpkDB();
        BobKeys bob  = setupBob(bobPk, bobSpk, bobKpk);

        // Bob's identity public key
        PointerByReference bobPrivObj = new PointerByReference();
        must(lib.signal_privatekey_deserialize(bobPrivObj, borrow(bob.idPriv)), "bob_id_deser");
        PointerByReference bobIdPub = new PointerByReference();
        must(lib.signal_privatekey_get_public_key(bobIdPub, bobPrivObj.getValue()), "bob_id_pub");
        lib.signal_privatekey_destroy(bobPrivObj.getValue());

        // Load public keys + sigs from stores for the bundle
        PointerByReference opkRec = new PointerByReference();
        must(lib.signal_pre_key_record_deserialize(opkRec, borrow(bobPk.db.get(bob.opkId))), "opk_load");
        PointerByReference opkPub = new PointerByReference();
        must(lib.signal_pre_key_record_get_public_key(opkPub, opkRec.getValue()), "opk_pub");
        lib.signal_pre_key_record_destroy(opkRec.getValue());

        PointerByReference spkRec = new PointerByReference();
        must(lib.signal_signed_pre_key_record_deserialize(spkRec, borrow(bobSpk.db.get(bob.spkId))), "spk_load");
        PointerByReference spkPub = new PointerByReference();
        must(lib.signal_signed_pre_key_record_get_public_key(spkPub, spkRec.getValue()), "spk_pub");
        OwnedBuffer.ByRef spkSigB = new OwnedBuffer.ByRef();
        must(lib.signal_signed_pre_key_record_get_signature(spkSigB, spkRec.getValue()), "spk_sig");
        byte[] spkSig = readOwned(spkSigB);
        lib.signal_signed_pre_key_record_destroy(spkRec.getValue());

        PointerByReference kpkRec = new PointerByReference();
        must(lib.signal_kyber_pre_key_record_deserialize(kpkRec, borrow(bobKpk.db.get(bob.kpkId))), "kpk_load");
        PointerByReference kpkPub = new PointerByReference();
        must(lib.signal_kyber_pre_key_record_get_public_key(kpkPub, kpkRec.getValue()), "kpk_pub");
        OwnedBuffer.ByRef kpkSigB = new OwnedBuffer.ByRef();
        must(lib.signal_kyber_pre_key_record_get_signature(kpkSigB, kpkRec.getValue()), "kpk_sig");
        byte[] kpkSig = readOwned(kpkSigB);
        lib.signal_kyber_pre_key_record_destroy(kpkRec.getValue());

        PointerByReference bundle = new PointerByReference();
        must(lib.signal_pre_key_bundle_new(bundle,
                bob.regId, 1,
                bob.opkId, true, opkPub.getValue(),
                bob.spkId, spkPub.getValue(), borrow(spkSig),
                bobIdPub.getValue(),
                bob.kpkId, true, kpkPub.getValue(), borrow(kpkSig)), "bundle_new");
        lib.signal_publickey_destroy(opkPub.getValue());
        lib.signal_publickey_destroy(spkPub.getValue());
        lib.signal_kyber_public_key_destroy(kpkPub.getValue());
        lib.signal_publickey_destroy(bobIdPub.getValue());

        // Addresses + Alice's stores
        PointerByReference bobAddr   = new PointerByReference();
        PointerByReference aliceAddr = new PointerByReference();
        must(lib.signal_address_new(bobAddr,   "bob",   1), "bob_addr");
        must(lib.signal_address_new(aliceAddr, "alice", 1), "alice_addr");

        SessDB aliceSS  = new SessDB();
        IdDB   aliceIS  = new IdDB(aliceIdPriv, 1001);
        PkDB   alicePKS = new PkDB();
        SpkDB  aliceSKS = new SpkDB();
        KpkDB  aliceKKS = new KpkDB();

        must(lib.signal_process_prekey_bundle(bundle.getValue(), bobAddr.getValue(),
                aliceSS.ptr, aliceIS.ptr, alicePKS.ptr, aliceSKS.ptr, aliceKKS.ptr), "proc_bundle");
        lib.signal_pre_key_bundle_destroy(bundle.getValue());

        // Alice encrypts
        byte[] pt1 = "hello bob".getBytes();
        PointerByReference ct1Out = new PointerByReference();
        must(lib.signal_encrypt_message(ct1Out, borrow(pt1), bobAddr.getValue(),
                aliceSS.ptr, aliceIS.ptr, alicePKS.ptr, aliceSKS.ptr), "enc_1");
        OwnedBuffer.ByRef ct1B = new OwnedBuffer.ByRef();
        must(lib.signal_ciphertext_message_serialize(ct1B, ct1Out.getValue()), "ct1_ser");
        byte[] ct1Bytes = readOwned(ct1B);
        lib.signal_ciphertext_message_destroy(ct1Out.getValue());

        // Bob decrypts the pre-key message
        SessDB bobSS = new SessDB();
        IdDB   bobIS = new IdDB(bob.idPriv, bob.regId);

        PointerByReference pksmOut = new PointerByReference();
        must(lib.signal_pre_key_signal_message_deserialize(pksmOut, borrow(ct1Bytes)), "pksm_deser");
        OwnedBuffer.ByRef dec1 = new OwnedBuffer.ByRef();
        must(lib.signal_decrypt_pre_key_message(dec1, pksmOut.getValue(), aliceAddr.getValue(),
                bobSS.ptr, bobIS.ptr, bobPk.ptr, bobSpk.ptr, bobKpk.ptr), "dec_prekey");
        lib.signal_pre_key_signal_message_destroy(pksmOut.getValue());
        if (!Arrays.equals(readOwned(dec1), pt1))
            throw new RuntimeException("[FAIL] pre-key plaintext mismatch");

        // Bob replies (whisper)
        byte[] pt2 = "hey alice".getBytes();
        PointerByReference ct2Out = new PointerByReference();
        must(lib.signal_encrypt_message(ct2Out, borrow(pt2), aliceAddr.getValue(),
                bobSS.ptr, bobIS.ptr, bobPk.ptr, bobSpk.ptr), "enc_2");
        OwnedBuffer.ByRef ct2B = new OwnedBuffer.ByRef();
        must(lib.signal_ciphertext_message_serialize(ct2B, ct2Out.getValue()), "ct2_ser");
        byte[] ct2Bytes = readOwned(ct2B);
        lib.signal_ciphertext_message_destroy(ct2Out.getValue());

        PointerByReference whisperOut = new PointerByReference();
        must(lib.signal_message_deserialize(whisperOut, borrow(ct2Bytes)), "whisper_deser");
        OwnedBuffer.ByRef dec2 = new OwnedBuffer.ByRef();
        must(lib.signal_decrypt_message(dec2, whisperOut.getValue(), bobAddr.getValue(),
                aliceSS.ptr, aliceIS.ptr), "dec_whisper");
        lib.signal_message_destroy(whisperOut.getValue());
        if (!Arrays.equals(readOwned(dec2), pt2))
            throw new RuntimeException("[FAIL] whisper plaintext mismatch");

        lib.signal_address_destroy(bobAddr.getValue());
        lib.signal_address_destroy(aliceAddr.getValue());
        System.out.println("X3DH + PQXDH + Double Ratchet PASS");
    }

    static void testGroup() {
        byte[] distId = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                         0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
        BorrowedBuffer.ByValue distBuf = borrow(distId);

        PointerByReference aliceAddr = new PointerByReference();
        must(lib.signal_address_new(aliceAddr, "alice", 1), "addr");

        SkDB aliceSK = new SkDB(), bobSK = new SkDB();

        PointerByReference skdm = new PointerByReference();
        must(lib.signal_sender_key_distribution_message_create(skdm, aliceAddr.getValue(),
                distBuf, aliceSK.ptr), "skdm_create");
        must(lib.signal_process_sender_key_distribution_message(aliceAddr.getValue(),
                skdm.getValue(), bobSK.ptr), "skdm_proc");
        lib.signal_sender_key_distribution_message_destroy(skdm.getValue());

        byte[] msg = "group hello".getBytes();
        OwnedBuffer.ByRef enc = new OwnedBuffer.ByRef();
        must(lib.signal_group_encrypt_message(enc, aliceAddr.getValue(), distBuf,
                borrow(msg), aliceSK.ptr), "group_enc");
        byte[] encBytes = readOwned(enc);

        OwnedBuffer.ByRef dec = new OwnedBuffer.ByRef();
        must(lib.signal_group_decrypt_message(dec, aliceAddr.getValue(),
                distBuf, borrow(encBytes), bobSK.ptr), "group_dec");
        if (!Arrays.equals(readOwned(dec), msg))
            throw new RuntimeException("[FAIL] group plaintext mismatch");
        lib.signal_address_destroy(aliceAddr.getValue());
        System.out.println("Sender Keys (group)           PASS");
    }

    static void testFingerprint() {
        PointerByReference pa = new PointerByReference(), pb = new PointerByReference();
        must(lib.signal_privatekey_generate(pa), "gen_a");
        must(lib.signal_privatekey_generate(pb), "gen_b");
        PointerByReference qa = new PointerByReference(), qb = new PointerByReference();
        must(lib.signal_privatekey_get_public_key(qa, pa.getValue()), "pub_a");
        must(lib.signal_privatekey_get_public_key(qb, pb.getValue()), "pub_b");
        lib.signal_privatekey_destroy(pa.getValue()); lib.signal_privatekey_destroy(pb.getValue());

        byte[] aId = "+15551234567".getBytes(), bId = "+15559876543".getBytes();
        PointerByReference fpA = new PointerByReference(), fpB = new PointerByReference();
        must(lib.signal_fingerprint_new(fpA, 5200, 0, borrow(aId), qa.getValue(),
                borrow(bId), qb.getValue()), "fp_new_a");
        must(lib.signal_fingerprint_new(fpB, 5200, 0, borrow(bId), qb.getValue(),
                borrow(aId), qa.getValue()), "fp_new_b");
        lib.signal_publickey_destroy(qa.getValue()); lib.signal_publickey_destroy(qb.getValue());

        OwnedBuffer.ByRef scanB = new OwnedBuffer.ByRef();
        must(lib.signal_fingerprint_scannable_encoding(scanB, fpB.getValue()), "fp_scan_b");
        byte[] scanBBytes = readOwned(scanB);

        ByteByReference match = new ByteByReference();
        must(lib.signal_fingerprint_compare(match, fpA.getValue(), borrow(scanBBytes)), "fp_compare");
        if (match.getValue() == 0) throw new RuntimeException("[FAIL] fingerprint mismatch");

        lib.signal_fingerprint_destroy(fpA.getValue());
        lib.signal_fingerprint_destroy(fpB.getValue());
        System.out.println("Fingerprints                  PASS");
    }

    static void testUsername() {
        Memory hash = new Memory(32);
        must(lib.signal_username_hash(hash, "alice.42"), "hash");
        OwnedBuffer.ByRef proof = new OwnedBuffer.ByRef();
        must(lib.signal_username_proof(proof, "alice.42"), "proof");
        byte[] proofBytes = readOwned(proof);
        ByteByReference valid = new ByteByReference();
        must(lib.signal_username_verify(valid, hash, borrow(proofBytes)), "verify");
        if (valid.getValue() == 0) throw new RuntimeException("[FAIL] username invalid");
        System.out.println("Username ZK proof             PASS");
    }

    static void testAccountKeys() {
        PointerByReference pool = new PointerByReference();
        must(lib.signal_account_entropy_pool_generate(pool), "pool_gen");

        PointerByReference strPP = new PointerByReference();
        must(lib.signal_account_entropy_pool_as_string(strPP, pool.getValue()), "pool_str");
        String s = strPP.getValue().getString(0);
        System.out.println("  Entropy pool: " + s.substring(0, Math.min(16, s.length())) + "…");
        lib.signal_free_string(strPP.getValue());

        Memory svr = new Memory(32), bk = new Memory(32);
        must(lib.signal_account_entropy_pool_derive_svr_key(svr, pool.getValue()),    "svr_key");
        must(lib.signal_account_entropy_pool_derive_backup_key(bk, pool.getValue()), "bk_key");
        lib.signal_account_entropy_pool_destroy(pool.getValue());
        if (Arrays.equals(svr.getByteArray(0, 32), bk.getByteArray(0, 32)))
            throw new RuntimeException("[FAIL] svr==backup");

        PointerByReference bkObj = new PointerByReference();
        must(lib.signal_backup_key_from_bytes(bkObj, borrow(bk.getByteArray(0, 32))), "bk_from_bytes");
        Memory media = new Memory(32);
        must(lib.signal_backup_key_derive_media_encryption_key(media, bkObj.getValue()), "media_key");
        lib.signal_backup_key_destroy(bkObj.getValue());
        if (Arrays.equals(bk.getByteArray(0, 32), media.getByteArray(0, 32)))
            throw new RuntimeException("[FAIL] backup==media");
        System.out.println("Account entropy pool          PASS");
    }

    // ── Main ──────────────────────────────────────────────────────────────────

    public static void main(String[] args) {
        String ext     = System.getProperty("os.name").toLowerCase().contains("mac") ? "dylib" : "so";
        String libPath = LIB_DIR + "/libsignal_ffi." + ext;
        lib = Native.load(libPath, Lib.class, Collections.emptyMap());

        testEC();
        testKyber();
        testSession();
        testGroup();
        testFingerprint();
        testUsername();
        testAccountKeys();
        System.out.println("\nAll signal_ffi tests PASSED.");
    }
}
