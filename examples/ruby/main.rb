#!/usr/bin/env ruby
# Every C FFI function exported by libsignal-zig.
# Each section exercises a real-world roundtrip: generate → use → verify.
# Run with: bundle exec ruby main.rb
require "ffi"

LIB_DIR = File.expand_path("../../zig-out/lib", __dir__)
INC_DIR = File.expand_path("../../include", __dir__)

module LibSignal
  extend FFI::Library
  ffi_lib File.join(LIB_DIR, "libsignal.dylib")

  # ── Error constants ─────────────────────────────────────────────────────────
  OK              =  0
  ERR_NOT_FOUND   = -6

  # ── EC / XEdDSA ─────────────────────────────────────────────────────────────
  attach_function :libsignal_ec_keypair_generate,
    [:pointer, :pointer], :int
  attach_function :libsignal_ec_dh,
    [:pointer, :pointer, :pointer], :int
  attach_function :libsignal_xeddsa_sign,
    [:pointer, :pointer, :size_t, :pointer], :int
  attach_function :libsignal_xeddsa_verify,
    [:pointer, :pointer, :size_t, :pointer], :int

  # ── ML-KEM-1024 ─────────────────────────────────────────────────────────────
  attach_function :libsignal_kyber1024_keypair_generate,
    [:pointer, :pointer], :int
  attach_function :libsignal_kyber1024_encaps,
    [:pointer, :pointer, :pointer], :int
  attach_function :libsignal_kyber1024_decaps,
    [:pointer, :pointer, :pointer], :int

  # ── Store structs ────────────────────────────────────────────────────────────
  # All store structs are passed by value to libsignal_ctx_new.
  # We build them as FFI::Struct, then pass a layout-compatible blob.

  class SessionStore < FFI::Struct
    layout :ud,    :pointer,
           :load,  :pointer,
           :store, :pointer
  end

  class IdentityStore < FFI::Struct
    layout :ud,                  :pointer,
           :get_keypair,         :pointer,
           :get_registration_id, :pointer,
           :save_identity,       :pointer,
           :is_trusted,          :pointer
  end

  class PreKeyStore < FFI::Struct
    layout :ud,     :pointer,
           :load,   :pointer,
           :remove, :pointer
  end

  class SignedPreKeyStore < FFI::Struct
    layout :ud,   :pointer,
           :load, :pointer
  end

  class SenderKeyStore < FFI::Struct
    layout :ud,    :pointer,
           :store, :pointer,
           :load,  :pointer
  end

  # ── Session context ─────────────────────────────────────────────────────────
  # libsignal_ctx_new takes all stores by value. We pass pointers to our struct
  # memory by reading them as raw bytes and inlining into a C-level varargs-safe
  # call via a helper we define below.
  # The cleanest approach with ruby-ffi: use :buffer_in for struct-by-value
  # by casting the struct pointer to :pointer and reading bytes.

  attach_function :libsignal_ctx_new, [
    :string, :uint32,
    SessionStore.by_value,
    IdentityStore.by_value,
    PreKeyStore.by_value,
    SignedPreKeyStore.by_value,
    :pointer   # nullable kyber store
  ], :pointer

  attach_function :libsignal_ctx_free, [:pointer], :void

  attach_function :libsignal_process_prekey_bundle, [
    :pointer,           # ctx
    :uint32,            # reg_id
    :uint32, :pointer,  # pre_key_id, pre_key_pub (nullable)
    :uint32, :pointer, :pointer,  # spk_id, spk_pub, spk_sig
    :pointer,           # identity_pub
    :uint32, :pointer, :pointer   # kyber_id, kyber_pub, kyber_sig (all nullable)
  ], :int

  attach_function :libsignal_encrypt, [
    :pointer, :pointer, :size_t, :pointer, :pointer, :pointer
  ], :int

  attach_function :libsignal_decrypt_prekey, [
    :pointer, :pointer, :size_t, :pointer, :pointer
  ], :int

  attach_function :libsignal_decrypt, [
    :pointer, :pointer, :size_t, :pointer, :pointer
  ], :int

  # ── Group ───────────────────────────────────────────────────────────────────
  attach_function :libsignal_group_create_session, [
    :string, :uint32, :pointer,
    SenderKeyStore.by_value,
    :pointer, :pointer
  ], :int

  attach_function :libsignal_group_process_session, [
    :string, :uint32, :pointer, :size_t,
    SenderKeyStore.by_value
  ], :int

  attach_function :libsignal_group_encrypt, [
    :string, :uint32, :pointer,
    :pointer, :size_t,
    SenderKeyStore.by_value,
    :pointer, :pointer
  ], :int

  attach_function :libsignal_group_decrypt, [
    :string, :uint32, :pointer,
    :pointer, :size_t,
    SenderKeyStore.by_value,
    :pointer, :pointer
  ], :int

  # ── Sealed Sender V1 ────────────────────────────────────────────────────────
  attach_function :libsignal_server_cert_serialize, [
    :uint32, :pointer, :pointer, :pointer, :pointer
  ], :int

  attach_function :libsignal_sender_cert_serialize, [
    :string, :string, :uint32, :pointer,
    :uint64, :pointer, :size_t, :pointer,
    :pointer, :pointer
  ], :int

  attach_function :libsignal_sealed_sender_encrypt, [
    :pointer, :pointer, :size_t,
    :uint8, :uint8, :string,
    :pointer, :size_t,
    :pointer, :pointer
  ], :int

  attach_function :libsignal_sealed_sender_decrypt, [
    :pointer, :size_t, :pointer,
    :pointer, :pointer,
    :pointer, :pointer,
    :pointer, :pointer,
    :pointer, :pointer
  ], :int

  # ── Sealed Sender V2 ────────────────────────────────────────────────────────
  class V2Recipient < FFI::Struct
    layout :service_id_fixed, [:uint8, 17],
           :device_id,        :uint8,
           :identity_pub,     [:uint8, 33]
  end

  attach_function :libsignal_sealed_sender_encrypt_v2, [
    :pointer, :size_t,
    :pointer, :pointer,  # sender_priv, sender_pub
    :pointer, :size_t,   # recipients array, count
    :pointer, :size_t,   # excluded sids
    :pointer, :pointer   # out, out_len
  ], :int

  attach_function :libsignal_sealed_sender_v2_dispatch, [
    :pointer, :size_t,
    :pointer, :uint8,    # service_id_fixed, device_id
    :pointer, :pointer   # out, out_len
  ], :int

  attach_function :libsignal_sealed_sender_decrypt_v2, [
    :pointer, :size_t,
    :pointer, :pointer,  # our_priv, our_pub
    :pointer,            # sender_pub
    :pointer, :pointer   # out, out_len
  ], :int

  # ── Fingerprint ─────────────────────────────────────────────────────────────
  attach_function :libsignal_fingerprint_compute, [
    :pointer, :pointer, :size_t,
    :pointer, :pointer, :size_t,
    :pointer, :pointer, :pointer
  ], :int

  attach_function :libsignal_fingerprint_compare, [
    :pointer, :size_t, :pointer, :size_t, :pointer
  ], :int

  # ── Username ─────────────────────────────────────────────────────────────────
  attach_function :libsignal_username_hash,   [:string, :pointer], :int
  attach_function :libsignal_username_proof,  [:string, :pointer, :pointer], :int
  attach_function :libsignal_username_verify, [:pointer, :pointer, :pointer], :int

  # ── Account keys ─────────────────────────────────────────────────────────────
  attach_function :libsignal_account_entropy_pool_generate, [:pointer], :void
  attach_function :libsignal_account_entropy_pool_parse,    [:pointer], :int
  attach_function :libsignal_account_entropy_derive_svr_key,    [:pointer, :pointer], :int
  attach_function :libsignal_account_entropy_derive_backup_key, [:pointer, :pointer], :int
  attach_function :libsignal_backup_key_derive_media_key,       [:pointer, :pointer], :void
end

# ── Helpers ──────────────────────────────────────────────────────────────────

def must(rc, label)
  raise "FAIL #{label}: error #{rc}" unless rc == LibSignal::OK
end

def gen_keypair
  pub  = FFI::MemoryPointer.new(:uint8, 33)
  priv = FFI::MemoryPointer.new(:uint8, 32)
  must(LibSignal.libsignal_ec_keypair_generate(pub, priv), "ec_keypair_generate")
  [pub, priv]
end

# Read a malloc'd *out / *out_len pair back as a Ruby String, then free the pointer.
def read_out(ptr_ptr, len_ptr)
  ptr = ptr_ptr.read_pointer
  len = len_ptr.read(:size_t)
  bytes = ptr.read_bytes(len)
  FFI::LibC.free(ptr)
  bytes
end

module FFI::LibC
  extend FFI::Library
  ffi_lib FFI::Library::LIBC
  attach_function :free, [:pointer], :void
end

# ── In-memory stores ─────────────────────────────────────────────────────────
# Each store is a Ruby hash acting as the backing store.
# Callbacks are FFI::Function objects kept alive as instance variables.

class MemSessionStore
  attr_reader :ffi_struct

  def initialize
    @db = {}   # [name, dev] => bytes
    @callbacks = []  # keep alive

    ud_ptr = FFI::Pointer.new(object_id)

    @load_cb = FFI::Function.new(:int, [:pointer, :string, :uint32, :pointer, :pointer]) do |_ud, name, dev, out_pp, out_len_p|
      key = [name, dev]
      if (data = @db[key])
        buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
        buf.put_bytes(0, data)
        buf.autorelease = false
        out_pp.put_pointer(0, buf)
        out_len_p.put(:size_t, 0, data.bytesize)
        0
      else
        LibSignal::ERR_NOT_FOUND
      end
    end

    @store_cb = FFI::Function.new(:int, [:pointer, :string, :uint32, :pointer, :size_t]) do |_ud, name, dev, data_ptr, len|
      @db[[name, dev]] = data_ptr.read_bytes(len)
      0
    end

    @ffi_struct = LibSignal::SessionStore.new
    @ffi_struct[:ud]    = FFI::Pointer::NULL
    @ffi_struct[:load]  = @load_cb
    @ffi_struct[:store] = @store_cb
  end
end

class MemIdentityStore
  attr_reader :ffi_struct

  def initialize(pub_bytes, priv_bytes, reg_id)
    @pub  = pub_bytes
    @priv = priv_bytes

    @get_kp_cb = FFI::Function.new(:int, [:pointer, :pointer, :pointer]) do |_ud, pub_out, priv_out|
      pub_out.put_bytes(0, @pub)
      priv_out.put_bytes(0, @priv)
      0
    end

    @get_reg_cb = FFI::Function.new(:int, [:pointer, :pointer]) do |_ud, out|
      out.put(:uint32, 0, reg_id)
      0
    end

    @save_cb = FFI::Function.new(:int, [:pointer, :string, :uint32, :pointer]) do |*|
      0
    end

    @trusted_cb = FFI::Function.new(:int, [:pointer, :string, :uint32, :pointer, :int]) do |*|
      1
    end

    @ffi_struct = LibSignal::IdentityStore.new
    @ffi_struct[:ud]                  = FFI::Pointer::NULL
    @ffi_struct[:get_keypair]         = @get_kp_cb
    @ffi_struct[:get_registration_id] = @get_reg_cb
    @ffi_struct[:save_identity]       = @save_cb
    @ffi_struct[:is_trusted]          = @trusted_cb
  end
end

class MemPreKeyStore
  attr_reader :ffi_struct

  def initialize(id, pub_bytes, priv_bytes)
    @id   = id
    @pub  = pub_bytes
    @priv = priv_bytes

    @load_cb = FFI::Function.new(:int, [:pointer, :uint32, :pointer, :pointer]) do |_ud, key_id, pub_out, priv_out|
      if key_id == @id
        pub_out.put_bytes(0, @pub)
        priv_out.put_bytes(0, @priv)
        0
      else
        LibSignal::ERR_NOT_FOUND
      end
    end

    @remove_cb = FFI::Function.new(:int, [:pointer, :uint32]) { |*| 0 }

    @ffi_struct = LibSignal::PreKeyStore.new
    @ffi_struct[:ud]     = FFI::Pointer::NULL
    @ffi_struct[:load]   = @load_cb
    @ffi_struct[:remove] = @remove_cb
  end
end

class MemSignedPreKeyStore
  attr_reader :ffi_struct

  def initialize(id, pub_bytes, priv_bytes, sig_bytes)
    @id   = id
    @pub  = pub_bytes
    @priv = priv_bytes
    @sig  = sig_bytes

    @load_cb = FFI::Function.new(:int, [:pointer, :uint32, :pointer, :pointer, :pointer, :pointer]) do |_ud, key_id, pub_out, priv_out, sig_out, ts_out|
      if key_id == @id
        pub_out.put_bytes(0, @pub)
        priv_out.put_bytes(0, @priv)
        sig_out.put_bytes(0, @sig)
        ts_out.put(:uint64, 0, 1_700_000_000)
        0
      else
        LibSignal::ERR_NOT_FOUND
      end
    end

    @ffi_struct = LibSignal::SignedPreKeyStore.new
    @ffi_struct[:ud]   = FFI::Pointer::NULL
    @ffi_struct[:load] = @load_cb
  end
end

class MemSenderKeyStore
  attr_reader :ffi_struct

  def initialize
    @db = {}   # [name, dev, dist_id_bytes] => bytes

    @store_cb = FFI::Function.new(:int, [:pointer, :string, :uint32, :pointer, :pointer, :size_t]) do |_ud, name, dev, dist, data_ptr, len|
      key = [name, dev, dist.read_bytes(16)]
      @db[key] = data_ptr.read_bytes(len)
      0
    end

    @load_cb = FFI::Function.new(:int, [:pointer, :string, :uint32, :pointer, :pointer, :pointer]) do |_ud, name, dev, dist, out_pp, out_len_p|
      key = [name, dev, dist.read_bytes(16)]
      if (data = @db[key])
        buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
        buf.put_bytes(0, data)
        buf.autorelease = false
        out_pp.put_pointer(0, buf)
        out_len_p.put(:size_t, 0, data.bytesize)
        0
      else
        LibSignal::ERR_NOT_FOUND
      end
    end

    @ffi_struct = LibSignal::SenderKeyStore.new
    @ffi_struct[:ud]    = FFI::Pointer::NULL
    @ffi_struct[:store] = @store_cb
    @ffi_struct[:load]  = @load_cb
  end
end

# ── Tests ─────────────────────────────────────────────────────────────────────

def test_ec
  pub_a, priv_a = gen_keypair
  pub_b, priv_b = gen_keypair

  shared_a = FFI::MemoryPointer.new(:uint8, 32)
  shared_b = FFI::MemoryPointer.new(:uint8, 32)
  must(LibSignal.libsignal_ec_dh(pub_b, priv_a, shared_a), "ec_dh_a")
  must(LibSignal.libsignal_ec_dh(pub_a, priv_b, shared_b), "ec_dh_b")
  raise "FAIL ec_dh match" unless shared_a.read_bytes(32) == shared_b.read_bytes(32)

  msg = "hello signal"
  msg_ptr = FFI::MemoryPointer.from_string(msg)
  sig = FFI::MemoryPointer.new(:uint8, 64)
  must(LibSignal.libsignal_xeddsa_sign(priv_a, msg_ptr, msg.bytesize, sig), "xeddsa_sign")
  must(LibSignal.libsignal_xeddsa_verify(pub_a, msg_ptr, msg.bytesize, sig), "xeddsa_verify")

  puts "EC + XEdDSA                   PASS"
end

def test_kyber
  pk = FFI::MemoryPointer.new(:uint8, 1568)
  sk = FFI::MemoryPointer.new(:uint8, 3168)
  must(LibSignal.libsignal_kyber1024_keypair_generate(pk, sk), "kyber_keygen")

  ct     = FFI::MemoryPointer.new(:uint8, 1568)
  ss_enc = FFI::MemoryPointer.new(:uint8, 32)
  must(LibSignal.libsignal_kyber1024_encaps(pk, ct, ss_enc), "kyber_encaps")

  ss_dec = FFI::MemoryPointer.new(:uint8, 32)
  must(LibSignal.libsignal_kyber1024_decaps(sk, ct, ss_dec), "kyber_decaps")
  raise "FAIL kyber ss match" unless ss_enc.read_bytes(32) == ss_dec.read_bytes(32)

  puts "ML-KEM-1024 (Kyber)           PASS"
end

def test_session
  alice_pub, alice_priv = gen_keypair
  bob_pub, bob_priv     = gen_keypair

  bob_opk_pub, bob_opk_priv = gen_keypair
  bob_spk_pub, bob_spk_priv = gen_keypair

  bob_spk_sig = FFI::MemoryPointer.new(:uint8, 64)
  must(LibSignal.libsignal_xeddsa_sign(bob_priv, bob_spk_pub, 33, bob_spk_sig), "bob_spk_sig")

  alice_id  = MemIdentityStore.new(alice_pub.read_bytes(33), alice_priv.read_bytes(32), 1001)
  alice_ss  = MemSessionStore.new
  alice_pk  = MemPreKeyStore.new(0, "\x00"*33, "\x00"*32)
  alice_spk = MemSignedPreKeyStore.new(0, "\x00"*33, "\x00"*32, "\x00"*64)

  alice_ctx = LibSignal.libsignal_ctx_new(
    "bob", 1,
    alice_ss.ffi_struct, alice_id.ffi_struct,
    alice_pk.ffi_struct, alice_spk.ffi_struct,
    nil
  )
  raise "FAIL alice_ctx_new" if alice_ctx.null?

  must(LibSignal.libsignal_process_prekey_bundle(
    alice_ctx, 2002,
    1, bob_opk_pub,
    1, bob_spk_pub, bob_spk_sig,
    bob_pub,
    0, nil, nil
  ), "process_bundle")

  ct_pp  = FFI::MemoryPointer.new(:pointer)
  ct_len = FFI::MemoryPointer.new(:size_t)
  mt_p   = FFI::MemoryPointer.new(:int)
  must(LibSignal.libsignal_encrypt(alice_ctx,
    FFI::MemoryPointer.from_string("hello bob"), 9,
    ct_pp, ct_len, mt_p), "encrypt_1")

  ct_ptr = ct_pp.read_pointer
  ct_bytes = ct_len.read(:size_t)

  bob_id  = MemIdentityStore.new(bob_pub.read_bytes(33), bob_priv.read_bytes(32), 2002)
  bob_ss  = MemSessionStore.new
  bob_pk  = MemPreKeyStore.new(1, bob_opk_pub.read_bytes(33), bob_opk_priv.read_bytes(32))
  bob_spk_store = MemSignedPreKeyStore.new(1, bob_spk_pub.read_bytes(33), bob_spk_priv.read_bytes(32), bob_spk_sig.read_bytes(64))

  bob_ctx = LibSignal.libsignal_ctx_new(
    "alice", 1,
    bob_ss.ffi_struct, bob_id.ffi_struct,
    bob_pk.ffi_struct, bob_spk_store.ffi_struct,
    nil
  )
  raise "FAIL bob_ctx_new" if bob_ctx.null?

  pt_pp  = FFI::MemoryPointer.new(:pointer)
  pt_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_decrypt_prekey(bob_ctx, ct_ptr, ct_bytes, pt_pp, pt_len), "decrypt_prekey")
  FFI::LibC.free(ct_ptr)

  pt = pt_pp.read_pointer.read_bytes(pt_len.read(:size_t))
  FFI::LibC.free(pt_pp.read_pointer)
  raise "FAIL session plaintext" unless pt == "hello bob"

  LibSignal.libsignal_ctx_free(alice_ctx)
  LibSignal.libsignal_ctx_free(bob_ctx)
  puts "X3DH + Double Ratchet         PASS"
end

def test_group
  dist_id = FFI::MemoryPointer.new(:uint8, 16)
  dist_id.put_bytes(0, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")

  alice_skdb = MemSenderKeyStore.new
  bob_skdb   = MemSenderKeyStore.new

  skdm_pp  = FFI::MemoryPointer.new(:pointer)
  skdm_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_group_create_session(
    "alice", 1, dist_id, alice_skdb.ffi_struct, skdm_pp, skdm_len
  ), "group_create")

  skdm_ptr   = skdm_pp.read_pointer
  skdm_bytes = skdm_len.read(:size_t)
  must(LibSignal.libsignal_group_process_session(
    "alice", 1, skdm_ptr, skdm_bytes, bob_skdb.ffi_struct
  ), "group_process")
  FFI::LibC.free(skdm_ptr)

  ct_pp  = FFI::MemoryPointer.new(:pointer)
  ct_len = FFI::MemoryPointer.new(:size_t)
  msg    = FFI::MemoryPointer.from_string("group hello")
  must(LibSignal.libsignal_group_encrypt(
    "alice", 1, dist_id, msg, 11, alice_skdb.ffi_struct, ct_pp, ct_len
  ), "group_encrypt")

  ct_ptr = ct_pp.read_pointer
  ct_bytes = ct_len.read(:size_t)

  pt_pp  = FFI::MemoryPointer.new(:pointer)
  pt_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_group_decrypt(
    "alice", 1, dist_id, ct_ptr, ct_bytes, bob_skdb.ffi_struct, pt_pp, pt_len
  ), "group_decrypt")
  FFI::LibC.free(ct_ptr)

  pt = pt_pp.read_pointer.read_bytes(pt_len.read(:size_t))
  FFI::LibC.free(pt_pp.read_pointer)
  raise "FAIL group plaintext" unless pt == "group hello"

  puts "Sender Keys (group)           PASS"
end

def test_sealed_sender_v1
  trust_pub, trust_priv = gen_keypair
  server_pub, server_priv = gen_keypair
  recv_pub, recv_priv  = gen_keypair
  sender_pub, _         = gen_keypair

  srv_cert_pp  = FFI::MemoryPointer.new(:pointer)
  srv_cert_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_server_cert_serialize(
    1, server_pub, trust_priv, srv_cert_pp, srv_cert_len
  ), "server_cert")

  srv_cert_ptr   = srv_cert_pp.read_pointer
  srv_cert_bytes = srv_cert_len.read(:size_t)

  snd_cert_pp  = FFI::MemoryPointer.new(:pointer)
  snd_cert_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_sender_cert_serialize(
    "alice-uuid", "+15551234567", 1,
    sender_pub, 9_999_999_999,
    srv_cert_ptr, srv_cert_bytes, server_priv,
    snd_cert_pp, snd_cert_len
  ), "sender_cert")
  FFI::LibC.free(srv_cert_ptr)

  snd_cert_ptr   = snd_cert_pp.read_pointer
  snd_cert_bytes = snd_cert_len.read(:size_t)

  msg    = "sealed v1 message"
  msg_ptr = FFI::MemoryPointer.from_string(msg)
  env_pp  = FFI::MemoryPointer.new(:pointer)
  env_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_sealed_sender_encrypt(
    recv_pub, snd_cert_ptr, snd_cert_bytes,
    1, 0, nil,
    msg_ptr, msg.bytesize,
    env_pp, env_len
  ), "ss_v1_encrypt")
  FFI::LibC.free(snd_cert_ptr)

  env_ptr   = env_pp.read_pointer
  env_bytes = env_len.read(:size_t)

  uuid_pp  = FFI::MemoryPointer.new(:pointer)
  uuid_len = FFI::MemoryPointer.new(:size_t)
  e164_pp  = FFI::MemoryPointer.new(:pointer)
  e164_len = FFI::MemoryPointer.new(:size_t)
  dev_out  = FFI::MemoryPointer.new(:uint32)
  ct_out   = FFI::MemoryPointer.new(:uint8)
  cont_pp  = FFI::MemoryPointer.new(:pointer)
  cont_len = FFI::MemoryPointer.new(:size_t)

  must(LibSignal.libsignal_sealed_sender_decrypt(
    env_ptr, env_bytes, recv_priv,
    uuid_pp, uuid_len, e164_pp, e164_len,
    dev_out, ct_out, cont_pp, cont_len
  ), "ss_v1_decrypt")
  FFI::LibC.free(env_ptr)

  uuid = uuid_pp.read_pointer.read_bytes(uuid_len.read(:size_t))
  FFI::LibC.free(uuid_pp.read_pointer)
  e164_ptr_val = e164_pp.read_pointer
  FFI::LibC.free(e164_ptr_val) unless e164_ptr_val.null?
  contents = cont_pp.read_pointer.read_bytes(cont_len.read(:size_t))
  FFI::LibC.free(cont_pp.read_pointer)

  raise "FAIL ss_v1 uuid" unless uuid == "alice-uuid"
  raise "FAIL ss_v1 contents" unless contents == msg

  puts "Sealed Sender V1              PASS"
end

def test_sealed_sender_v2
  sender_pub, sender_priv = gen_keypair
  recv_pub, recv_priv     = gen_keypair

  recip = LibSignal::V2Recipient.new
  service_id = "\x00" + (1..16).map(&:chr).join
  recip[:service_id_fixed].to_ptr.put_bytes(0, service_id)
  recip[:device_id] = 1
  recip[:identity_pub].to_ptr.put_bytes(0, recv_pub.read_bytes(33))

  msg     = "sealed v2 message"
  msg_ptr = FFI::MemoryPointer.from_string(msg)
  sent_pp  = FFI::MemoryPointer.new(:pointer)
  sent_len = FFI::MemoryPointer.new(:size_t)

  must(LibSignal.libsignal_sealed_sender_encrypt_v2(
    msg_ptr, msg.bytesize,
    sender_priv, sender_pub,
    recip, 1,
    nil, 0,
    sent_pp, sent_len
  ), "ss2_encrypt")

  sent_ptr   = sent_pp.read_pointer
  sent_bytes = sent_len.read(:size_t)

  sid_ptr = FFI::MemoryPointer.new(:uint8, 17)
  sid_ptr.put_bytes(0, service_id)

  recv_pp  = FFI::MemoryPointer.new(:pointer)
  recv_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_sealed_sender_v2_dispatch(
    sent_ptr, sent_bytes, sid_ptr, 1, recv_pp, recv_len
  ), "ss2_dispatch")
  FFI::LibC.free(sent_ptr)

  recv_ptr   = recv_pp.read_pointer
  recv_bytes = recv_len.read(:size_t)

  pt_pp  = FFI::MemoryPointer.new(:pointer)
  pt_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_sealed_sender_decrypt_v2(
    recv_ptr, recv_bytes,
    recv_priv, recv_pub, sender_pub,
    pt_pp, pt_len
  ), "ss2_decrypt")
  FFI::LibC.free(recv_ptr)

  pt = pt_pp.read_pointer.read_bytes(pt_len.read(:size_t))
  FFI::LibC.free(pt_pp.read_pointer)
  raise "FAIL ss2 contents" unless pt == msg

  puts "Sealed Sender V2              PASS"
end

def test_fingerprint
  a_pub, a_priv = gen_keypair
  b_pub, b_priv = gen_keypair
  (a_priv; b_priv)  # used only to silence unused warning

  alice_id = "+15551234567"
  bob_id   = "+15559876543"

  disp_a  = FFI::MemoryPointer.new(:uint8, 60)
  scan_a_pp  = FFI::MemoryPointer.new(:pointer)
  scan_a_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_fingerprint_compute(
    a_pub, FFI::MemoryPointer.from_string(alice_id), alice_id.bytesize,
    b_pub, FFI::MemoryPointer.from_string(bob_id),   bob_id.bytesize,
    disp_a, scan_a_pp, scan_a_len
  ), "fp_compute_a")

  disp_b  = FFI::MemoryPointer.new(:uint8, 60)
  scan_b_pp  = FFI::MemoryPointer.new(:pointer)
  scan_b_len = FFI::MemoryPointer.new(:size_t)
  must(LibSignal.libsignal_fingerprint_compute(
    b_pub, FFI::MemoryPointer.from_string(bob_id),   bob_id.bytesize,
    a_pub, FFI::MemoryPointer.from_string(alice_id), alice_id.bytesize,
    disp_b, scan_b_pp, scan_b_len
  ), "fp_compute_b")

  match = FFI::MemoryPointer.new(:int)
  must(LibSignal.libsignal_fingerprint_compare(
    scan_a_pp.read_pointer, scan_a_len.read(:size_t),
    scan_b_pp.read_pointer, scan_b_len.read(:size_t),
    match
  ), "fp_compare")
  raise "FAIL fp match" unless match.read(:int) == 1

  FFI::LibC.free(scan_a_pp.read_pointer)
  FFI::LibC.free(scan_b_pp.read_pointer)
  puts "Fingerprints                  PASS"
end

def test_username
  username   = "alice.42"
  hash       = FFI::MemoryPointer.new(:uint8, 32)
  must(LibSignal.libsignal_username_hash(username, hash), "username_hash")

  randomness = FFI::MemoryPointer.new(:uint8, 32)
  32.times { |i| randomness.put_uint8(i, (i * 7 + 3) & 0xff) }

  proof = FFI::MemoryPointer.new(:uint8, 128)
  must(LibSignal.libsignal_username_proof(username, randomness, proof), "username_proof")

  valid = FFI::MemoryPointer.new(:int)
  must(LibSignal.libsignal_username_verify(hash, proof, valid), "username_verify")
  raise "FAIL username valid" unless valid.read(:int) == 1

  puts "Username ZK proof             PASS"
end

def test_account_keys
  pool = FFI::MemoryPointer.new(:uint8, 64)
  LibSignal.libsignal_account_entropy_pool_generate(pool)
  must(LibSignal.libsignal_account_entropy_pool_parse(pool), "entropy_pool_parse")

  svr_key    = FFI::MemoryPointer.new(:uint8, 32)
  backup_key = FFI::MemoryPointer.new(:uint8, 32)
  media_key  = FFI::MemoryPointer.new(:uint8, 32)

  must(LibSignal.libsignal_account_entropy_derive_svr_key(pool, svr_key), "svr_key")
  must(LibSignal.libsignal_account_entropy_derive_backup_key(pool, backup_key), "backup_key")
  LibSignal.libsignal_backup_key_derive_media_key(backup_key, media_key)

  raise "FAIL keys svr==backup" if svr_key.read_bytes(32) == backup_key.read_bytes(32)
  raise "FAIL keys backup==media" if backup_key.read_bytes(32) == media_key.read_bytes(32)

  puts "Account entropy pool          PASS"
end

# ── Main ──────────────────────────────────────────────────────────────────────

test_ec
test_kyber
test_session
test_group
test_sealed_sender_v1
test_sealed_sender_v2
test_fingerprint
test_username
test_account_keys
