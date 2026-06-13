// Every C FFI function exported by libsignal-zig.
// Each section exercises a real-world roundtrip: generate → use → verify.
// Run with: ./run.sh
import com.sun.jna.*;
import com.sun.jna.ptr.*;
import java.util.*;
import java.nio.file.*;

public class Main {

    // ── Library path ─────────────────────────────────────────────────────────

    static final String LIB_DIR = Paths.get(
        System.getProperty("user.dir"), "..", "..", "zig-out", "lib"
    ).toAbsolutePath().normalize().toString();

    // ── Callback interfaces (C function pointer types) ────────────────────────

    interface SessLoadCb extends Callback {
        int invoke(Pointer ud, String name, int dev,
                   PointerByReference out, LongByReference outLen);
    }
    interface SessStoreCb extends Callback {
        int invoke(Pointer ud, String name, int dev, Pointer data, long len);
    }
    interface IdGetKpCb extends Callback {
        int invoke(Pointer ud, Pointer pubOut, Pointer privOut);
    }
    interface IdGetRegCb extends Callback {
        int invoke(Pointer ud, IntByReference out);
    }
    interface IdSaveCb extends Callback {
        int invoke(Pointer ud, String name, int dev, Pointer pub);
    }
    interface IdTrustedCb extends Callback {
        int invoke(Pointer ud, String name, int dev, Pointer pub, int direction);
    }
    interface PkLoadCb extends Callback {
        int invoke(Pointer ud, int id, Pointer pubOut, Pointer privOut);
    }
    interface PkRemoveCb extends Callback {
        int invoke(Pointer ud, int id);
    }
    interface SpkLoadCb extends Callback {
        int invoke(Pointer ud, int id, Pointer pubOut, Pointer privOut,
                   Pointer sigOut, LongByReference tsOut);
    }
    interface SkStoreCb extends Callback {
        int invoke(Pointer ud, String name, int dev,
                   Pointer dist, Pointer data, long len);
    }
    interface SkLoadCb extends Callback {
        int invoke(Pointer ud, String name, int dev, Pointer dist,
                   PointerByReference out, LongByReference outLen);
    }

    // ── Store structs ─────────────────────────────────────────────────────────

    @Structure.FieldOrder({"ud", "load", "store"})
    public static class SessionStore extends Structure {
        public Pointer    ud;
        public SessLoadCb load;
        public SessStoreCb store;
        public static class ByValue extends SessionStore implements Structure.ByValue {}
    }

    @Structure.FieldOrder({"ud", "get_keypair", "get_registration_id", "save_identity", "is_trusted"})
    public static class IdentityStore extends Structure {
        public Pointer    ud;
        public IdGetKpCb  get_keypair;
        public IdGetRegCb get_registration_id;
        public IdSaveCb   save_identity;
        public IdTrustedCb is_trusted;
        public static class ByValue extends IdentityStore implements Structure.ByValue {}
    }

    @Structure.FieldOrder({"ud", "load", "remove"})
    public static class PreKeyStore extends Structure {
        public Pointer   ud;
        public PkLoadCb  load;
        public PkRemoveCb remove;
        public static class ByValue extends PreKeyStore implements Structure.ByValue {}
    }

    @Structure.FieldOrder({"ud", "load"})
    public static class SignedPreKeyStore extends Structure {
        public Pointer   ud;
        public SpkLoadCb load;
        public static class ByValue extends SignedPreKeyStore implements Structure.ByValue {}
    }

    @Structure.FieldOrder({"ud", "store", "load"})
    public static class SenderKeyStore extends Structure {
        public Pointer  ud;
        public SkStoreCb store;
        public SkLoadCb  load;
        public static class ByValue extends SenderKeyStore implements Structure.ByValue {}
    }

    @Structure.FieldOrder({"service_id_fixed", "device_id", "identity_pub"})
    public static class V2Recipient extends Structure {
        public byte[] service_id_fixed = new byte[17];
        public byte   device_id;
        public byte[] identity_pub     = new byte[33];
    }

    // ── Library interface ─────────────────────────────────────────────────────

    interface Lib extends Library {
        int libsignal_ec_keypair_generate(Pointer pub_out, Pointer priv_out);
        int libsignal_ec_dh(Pointer their_pub, Pointer our_priv, Pointer shared_out);
        int libsignal_xeddsa_sign(Pointer priv, Pointer msg, long msg_len, Pointer sig_out);
        int libsignal_xeddsa_verify(Pointer pub, Pointer msg, long msg_len, Pointer sig);

        int libsignal_kyber1024_keypair_generate(Pointer pub_out, Pointer sec_out);
        int libsignal_kyber1024_encaps(Pointer pub, Pointer ct_out, Pointer ss_out);
        int libsignal_kyber1024_decaps(Pointer sec, Pointer ct, Pointer ss_out);

        Pointer libsignal_ctx_new(
            String remote_name, int remote_device_id,
            SessionStore.ByValue sess, IdentityStore.ByValue id,
            PreKeyStore.ByValue pk, SignedPreKeyStore.ByValue spk,
            Pointer kyber_store);
        void libsignal_ctx_free(Pointer ctx);

        int libsignal_process_prekey_bundle(
            Pointer ctx, int registration_id,
            int pre_key_id, Pointer pre_key_pub,
            int signed_pre_key_id, Pointer spk_pub, Pointer spk_sig,
            Pointer identity_pub,
            int kyber_id, Pointer kyber_pub, Pointer kyber_sig);

        int libsignal_encrypt(
            Pointer ctx, Pointer plaintext, long len,
            PointerByReference ct_out, LongByReference ct_len_out,
            IntByReference msg_type_out);
        int libsignal_decrypt_prekey(
            Pointer ctx, Pointer ct, long len,
            PointerByReference pt_out, LongByReference pt_len_out);
        int libsignal_decrypt(
            Pointer ctx, Pointer ct, long len,
            PointerByReference pt_out, LongByReference pt_len_out);

        int libsignal_group_create_session(
            String sender_name, int sender_device_id, Pointer distribution_id,
            SenderKeyStore.ByValue sk_store,
            PointerByReference skdm_out, LongByReference skdm_len_out);
        int libsignal_group_process_session(
            String sender_name, int sender_device_id,
            Pointer skdm_bytes, long skdm_len,
            SenderKeyStore.ByValue sk_store);
        int libsignal_group_encrypt(
            String sender_name, int sender_device_id, Pointer distribution_id,
            Pointer plaintext, long len,
            SenderKeyStore.ByValue sk_store,
            PointerByReference ct_out, LongByReference ct_len_out);
        int libsignal_group_decrypt(
            String sender_name, int sender_device_id, Pointer distribution_id,
            Pointer ciphertext, long len,
            SenderKeyStore.ByValue sk_store,
            PointerByReference pt_out, LongByReference pt_len_out);

        int libsignal_server_cert_serialize(
            int key_id, Pointer key_pub, Pointer trust_root_priv,
            PointerByReference out, LongByReference out_len);
        int libsignal_sender_cert_serialize(
            String sender_uuid, String sender_e164, int sender_device_id,
            Pointer sender_key_pub, long expiration,
            Pointer server_cert_bytes, long server_cert_len,
            Pointer server_key_priv,
            PointerByReference out, LongByReference out_len);
        int libsignal_sealed_sender_encrypt(
            Pointer recipient_pub,
            Pointer sender_cert_bytes, long sender_cert_len,
            byte msg_type, byte content_hint, String group_id,
            Pointer plaintext, long plaintext_len,
            PointerByReference out, LongByReference out_len);
        int libsignal_sealed_sender_decrypt(
            Pointer data, long data_len, Pointer our_priv,
            PointerByReference sender_uuid_out, LongByReference uuid_len_out,
            PointerByReference sender_e164_out, LongByReference e164_len_out,
            IntByReference sender_device_id_out,
            ByteByReference content_type_out,
            PointerByReference contents_out, LongByReference contents_len_out);

        int libsignal_sealed_sender_encrypt_v2(
            Pointer message, long message_len,
            Pointer sender_priv, Pointer sender_pub,
            V2Recipient recipients, long recipient_count,
            Pointer excluded_sids, long excluded_count,
            PointerByReference out, LongByReference out_len);
        int libsignal_sealed_sender_v2_dispatch(
            Pointer sent, long sent_len,
            Pointer service_id_fixed, byte device_id,
            PointerByReference out, LongByReference out_len);
        int libsignal_sealed_sender_decrypt_v2(
            Pointer received, long received_len,
            Pointer our_priv, Pointer our_pub, Pointer sender_pub,
            PointerByReference out, LongByReference out_len);

        int libsignal_fingerprint_compute(
            Pointer local_pub, Pointer local_stable_id, long local_stable_id_len,
            Pointer remote_pub, Pointer remote_stable_id, long remote_stable_id_len,
            Pointer displayable_out,
            PointerByReference scannable_out, LongByReference scannable_len_out);
        int libsignal_fingerprint_compare(
            Pointer local_scannable, long local_len,
            Pointer their_scannable, long their_len,
            IntByReference match_out);

        int libsignal_username_hash(String username_z, Pointer hash_out);
        int libsignal_username_proof(String username_z, Pointer randomness, Pointer proof_out);
        int libsignal_username_verify(Pointer username_hash, Pointer proof, IntByReference valid_out);

        void libsignal_account_entropy_pool_generate(Pointer pool_out);
        int  libsignal_account_entropy_pool_parse(Pointer pool_str);
        int  libsignal_account_entropy_derive_svr_key(Pointer pool_str, Pointer key_out);
        int  libsignal_account_entropy_derive_backup_key(Pointer pool_str, Pointer key_out);
        void libsignal_backup_key_derive_media_key(Pointer backup_key, Pointer key_out);
    }

    static Lib lib;

    // ── Helpers ───────────────────────────────────────────────────────────────

    static void must(int rc, String label) {
        if (rc != 0) throw new RuntimeException("FAIL " + label + ": error " + rc);
    }

    static Memory[] genKeypair() {
        Memory pub  = new Memory(33);
        Memory priv = new Memory(32);
        must(lib.libsignal_ec_keypair_generate(pub, priv), "ec_keypair_generate");
        return new Memory[]{pub, priv};
    }

    // Read a C malloc'd buffer from a PointerByReference + LongByReference and free it.
    static byte[] readOut(PointerByReference ptr, LongByReference len) {
        Pointer p = ptr.getValue();
        int    n = (int) len.getValue();
        byte[] b = p.getByteArray(0, n);
        Native.free(Pointer.nativeValue(p));
        return b;
    }

    // Allocate a C malloc buffer from a Java byte array so C can free() it.
    static Pointer mallocCopy(byte[] src) {
        long addr = Native.malloc(src.length);
        Pointer p = new Pointer(addr);
        p.write(0, src, 0, src.length);
        return p;
    }

    // ── In-memory stores ──────────────────────────────────────────────────────

    static SessionStore.ByValue makeSessionStore(Map<String, byte[]> db) {
        SessionStore s = new SessionStore();
        s.ud = null;
        s.load = (ud, name, dev, out, outLen) -> {
            byte[] data = db.get(name + ":" + dev);
            if (data == null) return -6;
            out.setValue(mallocCopy(data));
            outLen.setValue(data.length);
            return 0;
        };
        s.store = (ud, name, dev, data, len) -> {
            db.put(name + ":" + dev, data.getByteArray(0, (int) len));
            return 0;
        };
        SessionStore.ByValue bv = new SessionStore.ByValue();
        bv.ud    = s.ud;
        bv.load  = s.load;
        bv.store = s.store;
        return bv;
    }

    static IdentityStore.ByValue makeIdentityStore(byte[] pub, byte[] priv, int regId) {
        IdentityStore s = new IdentityStore();
        s.ud = null;
        s.get_keypair = (ud, pubOut, privOut) -> {
            pubOut.write(0, pub, 0, 33);
            privOut.write(0, priv, 0, 32);
            return 0;
        };
        s.get_registration_id = (ud, out) -> { out.setValue(regId); return 0; };
        s.save_identity       = (ud, name, dev, p)         -> 0;
        s.is_trusted          = (ud, name, dev, p, dir)    -> 1;
        IdentityStore.ByValue bv = new IdentityStore.ByValue();
        bv.ud                  = s.ud;
        bv.get_keypair         = s.get_keypair;
        bv.get_registration_id = s.get_registration_id;
        bv.save_identity       = s.save_identity;
        bv.is_trusted          = s.is_trusted;
        return bv;
    }

    static PreKeyStore.ByValue makePreKeyStore(int id, byte[] pub, byte[] priv) {
        PreKeyStore s = new PreKeyStore();
        s.ud = null;
        s.load = (ud, keyId, pubOut, privOut) -> {
            if (keyId != id) return -6;
            pubOut.write(0, pub, 0, 33);
            privOut.write(0, priv, 0, 32);
            return 0;
        };
        s.remove = (ud, keyId) -> 0;
        PreKeyStore.ByValue bv = new PreKeyStore.ByValue();
        bv.ud     = s.ud;
        bv.load   = s.load;
        bv.remove = s.remove;
        return bv;
    }

    static SignedPreKeyStore.ByValue makeSignedPreKeyStore(int id, byte[] pub, byte[] priv, byte[] sig) {
        SignedPreKeyStore s = new SignedPreKeyStore();
        s.ud = null;
        s.load = (ud, keyId, pubOut, privOut, sigOut, tsOut) -> {
            if (keyId != id) return -6;
            pubOut.write(0, pub, 0, 33);
            privOut.write(0, priv, 0, 32);
            sigOut.write(0, sig, 0, 64);
            tsOut.setValue(1700000000L);
            return 0;
        };
        SignedPreKeyStore.ByValue bv = new SignedPreKeyStore.ByValue();
        bv.ud   = s.ud;
        bv.load = s.load;
        return bv;
    }

    static SenderKeyStore.ByValue makeSenderKeyStore(Map<String, byte[]> db) {
        SenderKeyStore s = new SenderKeyStore();
        s.ud = null;
        s.store = (ud, name, dev, dist, data, len) -> {
            String key = name + ":" + dev + ":" + hex(dist.getByteArray(0, 16));
            db.put(key, data.getByteArray(0, (int) len));
            return 0;
        };
        s.load = (ud, name, dev, dist, out, outLen) -> {
            String key  = name + ":" + dev + ":" + hex(dist.getByteArray(0, 16));
            byte[] data = db.get(key);
            if (data == null) return -6;
            out.setValue(mallocCopy(data));
            outLen.setValue(data.length);
            return 0;
        };
        SenderKeyStore.ByValue bv = new SenderKeyStore.ByValue();
        bv.ud    = s.ud;
        bv.store = s.store;
        bv.load  = s.load;
        return bv;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    static void testEC() {
        Memory[] a = genKeypair();
        Memory[] b = genKeypair();

        Memory sharedA = new Memory(32), sharedB = new Memory(32);
        must(lib.libsignal_ec_dh(b[0], a[1], sharedA), "ec_dh_a");
        must(lib.libsignal_ec_dh(a[0], b[1], sharedB), "ec_dh_b");
        if (!Arrays.equals(sharedA.getByteArray(0, 32), sharedB.getByteArray(0, 32)))
            throw new RuntimeException("FAIL ec_dh mismatch");

        byte[] msg    = "hello signal".getBytes();
        Memory msgMem = new Memory(msg.length);
        msgMem.write(0, msg, 0, msg.length);
        Memory sig = new Memory(64);
        must(lib.libsignal_xeddsa_sign(a[1], msgMem, msg.length, sig), "xeddsa_sign");
        must(lib.libsignal_xeddsa_verify(a[0], msgMem, msg.length, sig), "xeddsa_verify");

        System.out.println("EC + XEdDSA                   PASS");
    }

    static void testKyber() {
        Memory pk = new Memory(1568), sk = new Memory(3168);
        must(lib.libsignal_kyber1024_keypair_generate(pk, sk), "kyber_keygen");

        Memory ct = new Memory(1568), ssEnc = new Memory(32);
        must(lib.libsignal_kyber1024_encaps(pk, ct, ssEnc), "kyber_encaps");

        Memory ssDec = new Memory(32);
        must(lib.libsignal_kyber1024_decaps(sk, ct, ssDec), "kyber_decaps");
        if (!Arrays.equals(ssEnc.getByteArray(0, 32), ssDec.getByteArray(0, 32)))
            throw new RuntimeException("FAIL kyber ss mismatch");

        System.out.println("ML-KEM-1024 (Kyber)           PASS");
    }

    static void testSession() {
        Memory[] aliceKp = genKeypair();
        Memory[] bobKp   = genKeypair();
        Memory[] bobOpk  = genKeypair();
        Memory[] bobSpk  = genKeypair();

        Memory bobSpkSig = new Memory(64);
        must(lib.libsignal_xeddsa_sign(bobKp[1], bobSpk[0], 33, bobSpkSig), "bob_spk_sig");

        Map<String, byte[]> aliceSessDB = new HashMap<>(), bobSessDB = new HashMap<>();
        SessionStore.ByValue      aliceSess = makeSessionStore(aliceSessDB);
        IdentityStore.ByValue     aliceId   = makeIdentityStore(aliceKp[0].getByteArray(0,33), aliceKp[1].getByteArray(0,32), 1001);
        PreKeyStore.ByValue       alicePk   = makePreKeyStore(0, new byte[33], new byte[32]);
        SignedPreKeyStore.ByValue  aliceSpk  = makeSignedPreKeyStore(0, new byte[33], new byte[32], new byte[64]);

        Pointer aliceCtx = lib.libsignal_ctx_new("bob", 1, aliceSess, aliceId, alicePk, aliceSpk, null);
        if (aliceCtx == null) throw new RuntimeException("FAIL alice ctx_new");

        must(lib.libsignal_process_prekey_bundle(aliceCtx, 2002,
            1, bobOpk[0], 1, bobSpk[0], bobSpkSig, bobKp[0], 0, null, null
        ), "process_bundle");

        byte[] helloBytes = "hello bob".getBytes();
        Memory helloMem = new Memory(helloBytes.length);
        helloMem.write(0, helloBytes, 0, helloBytes.length);
        PointerByReference ctPP   = new PointerByReference();
        LongByReference    ctLen  = new LongByReference();
        IntByReference     mtP    = new IntByReference();
        must(lib.libsignal_encrypt(aliceCtx, helloMem, helloBytes.length, ctPP, ctLen, mtP), "encrypt_1");
        byte[] ct = readOut(ctPP, ctLen);

        SessionStore.ByValue      bobSess = makeSessionStore(bobSessDB);
        IdentityStore.ByValue     bobId   = makeIdentityStore(bobKp[0].getByteArray(0,33), bobKp[1].getByteArray(0,32), 2002);
        PreKeyStore.ByValue       bobPk   = makePreKeyStore(1, bobOpk[0].getByteArray(0,33), bobOpk[1].getByteArray(0,32));
        SignedPreKeyStore.ByValue  bobSpkS = makeSignedPreKeyStore(1, bobSpk[0].getByteArray(0,33), bobSpk[1].getByteArray(0,32), bobSpkSig.getByteArray(0,64));

        Pointer bobCtx = lib.libsignal_ctx_new("alice", 1, bobSess, bobId, bobPk, bobSpkS, null);
        if (bobCtx == null) throw new RuntimeException("FAIL bob ctx_new");

        Memory ctMem = new Memory(ct.length);
        ctMem.write(0, ct, 0, ct.length);
        PointerByReference ptPP  = new PointerByReference();
        LongByReference    ptLen = new LongByReference();
        must(lib.libsignal_decrypt_prekey(bobCtx, ctMem, ct.length, ptPP, ptLen), "decrypt_prekey");
        byte[] pt = readOut(ptPP, ptLen);
        if (!Arrays.equals(pt, "hello bob".getBytes()))
            throw new RuntimeException("FAIL session plaintext: " + new String(pt));

        lib.libsignal_ctx_free(aliceCtx);
        lib.libsignal_ctx_free(bobCtx);
        System.out.println("X3DH + Double Ratchet         PASS");
    }

    static void testGroup() {
        byte[] distId = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
        Memory distMem = new Memory(16);
        distMem.write(0, distId, 0, 16);

        Map<String, byte[]> aliceSkDB = new HashMap<>(), bobSkDB = new HashMap<>();
        SenderKeyStore.ByValue aliceSk = makeSenderKeyStore(aliceSkDB);
        SenderKeyStore.ByValue bobSk   = makeSenderKeyStore(bobSkDB);

        PointerByReference skdmPP  = new PointerByReference();
        LongByReference    skdmLen = new LongByReference();
        must(lib.libsignal_group_create_session("alice", 1, distMem, aliceSk, skdmPP, skdmLen), "group_create");
        byte[] skdm = readOut(skdmPP, skdmLen);

        Memory skdmMem = new Memory(skdm.length);
        skdmMem.write(0, skdm, 0, skdm.length);
        must(lib.libsignal_group_process_session("alice", 1, skdmMem, skdm.length, bobSk), "group_process");

        byte[] msg = "group hello".getBytes();
        Memory msgMem = new Memory(msg.length);
        msgMem.write(0, msg, 0, msg.length);
        PointerByReference ctPP  = new PointerByReference();
        LongByReference    ctLen = new LongByReference();
        must(lib.libsignal_group_encrypt("alice", 1, distMem, msgMem, msg.length, aliceSk, ctPP, ctLen), "group_encrypt");
        byte[] ct = readOut(ctPP, ctLen);

        Memory ctMem = new Memory(ct.length);
        ctMem.write(0, ct, 0, ct.length);
        PointerByReference ptPP  = new PointerByReference();
        LongByReference    ptLen = new LongByReference();
        must(lib.libsignal_group_decrypt("alice", 1, distMem, ctMem, ct.length, bobSk, ptPP, ptLen), "group_decrypt");
        byte[] pt = readOut(ptPP, ptLen);
        if (!Arrays.equals(pt, "group hello".getBytes()))
            throw new RuntimeException("FAIL group plaintext: " + new String(pt));

        System.out.println("Sender Keys (group)           PASS");
    }

    static void testSealedSenderV1() {
        Memory[] trustKp  = genKeypair();
        Memory[] serverKp = genKeypair();
        Memory[] recvKp   = genKeypair();
        Memory[] senderKp = genKeypair();

        PointerByReference srvCertPP  = new PointerByReference();
        LongByReference    srvCertLen = new LongByReference();
        must(lib.libsignal_server_cert_serialize(1, serverKp[0], trustKp[1], srvCertPP, srvCertLen), "server_cert");
        byte[] srvCert = readOut(srvCertPP, srvCertLen);

        Memory srvCertMem = new Memory(srvCert.length);
        srvCertMem.write(0, srvCert, 0, srvCert.length);
        PointerByReference sndCertPP  = new PointerByReference();
        LongByReference    sndCertLen = new LongByReference();
        must(lib.libsignal_sender_cert_serialize(
            "alice-uuid", "+15551234567", 1, senderKp[0],
            9_999_999_999L, srvCertMem, srvCert.length, serverKp[1],
            sndCertPP, sndCertLen), "sender_cert");
        byte[] sndCert = readOut(sndCertPP, sndCertLen);

        byte[] msg = "sealed v1 message".getBytes();
        Memory msgMem     = new Memory(msg.length);
        Memory sndCertMem = new Memory(sndCert.length);
        msgMem.write(0, msg, 0, msg.length);
        sndCertMem.write(0, sndCert, 0, sndCert.length);
        PointerByReference envPP  = new PointerByReference();
        LongByReference    envLen = new LongByReference();
        must(lib.libsignal_sealed_sender_encrypt(
            recvKp[0], sndCertMem, sndCert.length,
            (byte) 1, (byte) 0, null,
            msgMem, msg.length, envPP, envLen), "ss_v1_encrypt");
        byte[] envelope = readOut(envPP, envLen);

        Memory envMem = new Memory(envelope.length);
        envMem.write(0, envelope, 0, envelope.length);
        PointerByReference uuidPP   = new PointerByReference();
        LongByReference    uuidLen  = new LongByReference();
        PointerByReference e164PP   = new PointerByReference();
        LongByReference    e164Len  = new LongByReference();
        IntByReference     devOut   = new IntByReference();
        ByteByReference    ctypeOut = new ByteByReference();
        PointerByReference contPP   = new PointerByReference();
        LongByReference    contLen  = new LongByReference();
        must(lib.libsignal_sealed_sender_decrypt(
            envMem, envelope.length, recvKp[1],
            uuidPP, uuidLen, e164PP, e164Len,
            devOut, ctypeOut, contPP, contLen), "ss_v1_decrypt");

        byte[] uuid = readOut(uuidPP, uuidLen);
        Pointer e164Ptr = e164PP.getValue();
        if (e164Ptr != null) Native.free(Pointer.nativeValue(e164Ptr));
        byte[] contents = readOut(contPP, contLen);

        if (!new String(uuid).equals("alice-uuid"))
            throw new RuntimeException("FAIL ss_v1 uuid: " + new String(uuid));
        if (!Arrays.equals(contents, msg))
            throw new RuntimeException("FAIL ss_v1 contents");

        System.out.println("Sealed Sender V1              PASS");
    }

    static void testSealedSenderV2() {
        Memory[] senderKp = genKeypair();
        Memory[] recvKp   = genKeypair();

        V2Recipient recip = new V2Recipient();
        recip.service_id_fixed[0] = 0x00; // ACI
        for (int i = 1; i < 17; i++) recip.service_id_fixed[i] = (byte) i;
        recip.device_id = 1;
        byte[] recvPubBytes = recvKp[0].getByteArray(0, 33);
        System.arraycopy(recvPubBytes, 0, recip.identity_pub, 0, 33);

        byte[] msg = "sealed v2 message".getBytes();
        Memory msgMem = new Memory(msg.length);
        msgMem.write(0, msg, 0, msg.length);
        PointerByReference sentPP  = new PointerByReference();
        LongByReference    sentLen = new LongByReference();
        must(lib.libsignal_sealed_sender_encrypt_v2(
            msgMem, msg.length,
            senderKp[1], senderKp[0],
            recip, 1,
            null, 0,
            sentPP, sentLen), "ss2_encrypt");
        byte[] sent = readOut(sentPP, sentLen);

        Memory sentMem = new Memory(sent.length);
        sentMem.write(0, sent, 0, sent.length);
        Memory sidMem = new Memory(17);
        sidMem.write(0, recip.service_id_fixed, 0, 17);
        PointerByReference recvPP  = new PointerByReference();
        LongByReference    recvLen = new LongByReference();
        must(lib.libsignal_sealed_sender_v2_dispatch(
            sentMem, sent.length, sidMem, (byte) 1, recvPP, recvLen), "ss2_dispatch");
        byte[] received = readOut(recvPP, recvLen);

        Memory rcvMem = new Memory(received.length);
        rcvMem.write(0, received, 0, received.length);
        PointerByReference ptPP  = new PointerByReference();
        LongByReference    ptLen = new LongByReference();
        must(lib.libsignal_sealed_sender_decrypt_v2(
            rcvMem, received.length,
            recvKp[1], recvKp[0], senderKp[0],
            ptPP, ptLen), "ss2_decrypt");
        byte[] pt = readOut(ptPP, ptLen);
        if (!Arrays.equals(pt, msg))
            throw new RuntimeException("FAIL ss2 contents: " + new String(pt));

        System.out.println("Sealed Sender V2              PASS");
    }

    static void testFingerprint() {
        Memory[] a = genKeypair();
        Memory[] b = genKeypair();

        byte[] aliceId = "+15551234567".getBytes();
        byte[] bobId   = "+15559876543".getBytes();
        Memory aliceIdMem = new Memory(aliceId.length); aliceIdMem.write(0, aliceId, 0, aliceId.length);
        Memory bobIdMem   = new Memory(bobId.length);   bobIdMem.write(0, bobId, 0, bobId.length);

        Memory dispA = new Memory(60), dispB = new Memory(60);
        PointerByReference scanAPP  = new PointerByReference(); LongByReference scanALen = new LongByReference();
        PointerByReference scanBPP  = new PointerByReference(); LongByReference scanBLen = new LongByReference();

        must(lib.libsignal_fingerprint_compute(
            a[0], aliceIdMem, aliceId.length, b[0], bobIdMem, bobId.length,
            dispA, scanAPP, scanALen), "fp_compute_a");
        byte[] scanA = readOut(scanAPP, scanALen);

        must(lib.libsignal_fingerprint_compute(
            b[0], bobIdMem, bobId.length, a[0], aliceIdMem, aliceId.length,
            dispB, scanBPP, scanBLen), "fp_compute_b");
        byte[] scanB = readOut(scanBPP, scanBLen);

        Memory scanAMem = new Memory(scanA.length); scanAMem.write(0, scanA, 0, scanA.length);
        Memory scanBMem = new Memory(scanB.length); scanBMem.write(0, scanB, 0, scanB.length);
        IntByReference match = new IntByReference();
        must(lib.libsignal_fingerprint_compare(
            scanAMem, scanA.length, scanBMem, scanB.length, match), "fp_compare");
        if (match.getValue() != 1) throw new RuntimeException("FAIL fingerprint mismatch");

        System.out.println("Fingerprints                  PASS");
    }

    static void testUsername() {
        Memory hash = new Memory(32);
        must(lib.libsignal_username_hash("alice.42", hash), "username_hash");

        Memory randomness = new Memory(32);
        for (int i = 0; i < 32; i++) randomness.setByte(i, (byte)((i * 7 + 3) & 0xff));

        Memory proof = new Memory(128);
        must(lib.libsignal_username_proof("alice.42", randomness, proof), "username_proof");

        IntByReference valid = new IntByReference();
        must(lib.libsignal_username_verify(hash, proof, valid), "username_verify");
        if (valid.getValue() != 1) throw new RuntimeException("FAIL username invalid");

        System.out.println("Username ZK proof             PASS");
    }

    static void testAccountKeys() {
        Memory pool = new Memory(64);
        lib.libsignal_account_entropy_pool_generate(pool);
        must(lib.libsignal_account_entropy_pool_parse(pool), "entropy_pool_parse");

        Memory svrKey    = new Memory(32);
        Memory backupKey = new Memory(32);
        Memory mediaKey  = new Memory(32);
        must(lib.libsignal_account_entropy_derive_svr_key(pool, svrKey), "svr_key");
        must(lib.libsignal_account_entropy_derive_backup_key(pool, backupKey), "backup_key");
        lib.libsignal_backup_key_derive_media_key(backupKey, mediaKey);

        if (Arrays.equals(svrKey.getByteArray(0,32), backupKey.getByteArray(0,32)))
            throw new RuntimeException("FAIL svr==backup");
        if (Arrays.equals(backupKey.getByteArray(0,32), mediaKey.getByteArray(0,32)))
            throw new RuntimeException("FAIL backup==media");

        System.out.println("Account entropy pool          PASS");
    }

    // ── Main ──────────────────────────────────────────────────────────────────

    public static void main(String[] args) {
        String libExt  = System.getProperty("os.name").toLowerCase().contains("mac") ? "dylib" : "so";
        String libPath = LIB_DIR + "/libsignal." + libExt;

        Map<String, Object> opts = new HashMap<>();
        lib = Native.load(libPath, Lib.class, opts);

        testEC();
        testKyber();
        testSession();
        testGroup();
        testSealedSenderV1();
        testSealedSenderV2();
        testFingerprint();
        testUsername();
        testAccountKeys();
    }
}
