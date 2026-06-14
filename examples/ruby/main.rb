#!/usr/bin/env ruby
# examples/ruby/main.rb — signal_ffi.h round-trip exerciser (Ruby FFI)
#
# Each section exercises a real-world roundtrip through the signal_ffi API.
# Run with:  bundle exec ruby main.rb
require "ffi"

LIB_DIR = File.expand_path("../../zig-out/lib", __dir__)

# ── libc free ────────────────────────────────────────────────────────────────

module LibC
  extend FFI::Library
  ffi_lib FFI::Library::LIBC
  attach_function :free, [:pointer], :void
end

# ── signal_ffi bindings ───────────────────────────────────────────────────────

module Sig
  extend FFI::Library
  ffi_lib File.join(LIB_DIR, "libsignal_ffi.dylib")

  # Struct-by-value types used across the API.
  # Signal{Mut,Const}Pointer<T> structs contain exactly one pointer field.
  # On arm64/x86-64 they are ABI-equivalent to a bare pointer, so we declare
  # them as :pointer.  SignalBorrowedBuffer / SignalOwnedBuffer have two fields
  # and require struct-by-value treatment.

  class BorrowedBuffer < FFI::Struct
    layout :base,   :pointer,
           :length, :size_t
  end

  class OwnedBuffer < FFI::Struct
    layout :base,   :pointer,
           :length, :size_t
  end

  # Error
  attach_function :signal_error_get_message, [:pointer, :pointer], :pointer
  attach_function :signal_error_free,        [:pointer],           :void
  attach_function :signal_free_buffer,       [:pointer, :size_t],  :void
  attach_function :signal_free_string,       [:pointer],           :void

  # EC keys
  attach_function :signal_privatekey_generate,    [:pointer],                        :pointer
  attach_function :signal_privatekey_deserialize, [:pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_privatekey_serialize,   [:pointer, :pointer],              :pointer
  attach_function :signal_privatekey_get_public_key, [:pointer, :pointer],           :pointer
  attach_function :signal_privatekey_agree,        [:pointer, :pointer, :pointer],   :pointer
  attach_function :signal_privatekey_sign,         [:pointer, :pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_privatekey_destroy,      [:pointer],                       :pointer
  attach_function :signal_publickey_deserialize,   [:pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_publickey_serialize,     [:pointer, :pointer],             :pointer
  attach_function :signal_publickey_verify,        [:pointer, :pointer, BorrowedBuffer.by_value, BorrowedBuffer.by_value], :pointer
  attach_function :signal_publickey_destroy,       [:pointer],                       :pointer

  # Address
  attach_function :signal_address_new,          [:pointer, :string, :uint32], :pointer
  attach_function :signal_address_get_name,     [:pointer, :pointer],         :pointer
  attach_function :signal_address_get_device_id,[:pointer, :pointer],         :pointer
  attach_function :signal_address_destroy,      [:pointer],                   :pointer

  # Pre-key records
  attach_function :signal_pre_key_record_new,        [:pointer, :uint32, :pointer, :pointer], :pointer
  attach_function :signal_pre_key_record_serialize,  [:pointer, :pointer],                    :pointer
  attach_function :signal_pre_key_record_deserialize,[:pointer, BorrowedBuffer.by_value],     :pointer
  attach_function :signal_pre_key_record_get_public_key, [:pointer, :pointer],                :pointer
  attach_function :signal_pre_key_record_destroy,    [:pointer],                              :pointer

  # Signed pre-key records
  attach_function :signal_signed_pre_key_record_new,
    [:pointer, :uint32, :uint64, :pointer, :pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_signed_pre_key_record_serialize,
    [:pointer, :pointer], :pointer
  attach_function :signal_signed_pre_key_record_deserialize,
    [:pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_signed_pre_key_record_get_public_key,
    [:pointer, :pointer], :pointer
  attach_function :signal_signed_pre_key_record_get_signature,
    [:pointer, :pointer], :pointer
  attach_function :signal_signed_pre_key_record_destroy, [:pointer], :pointer

  # Kyber keys and pre-key records
  attach_function :signal_kyber_key_pair_generate,      [:pointer],          :pointer
  attach_function :signal_kyber_key_pair_get_public_key,[:pointer, :pointer],:pointer
  attach_function :signal_kyber_key_pair_get_secret_key,[:pointer, :pointer],:pointer
  attach_function :signal_kyber_key_pair_destroy,       [:pointer],          :pointer
  attach_function :signal_kyber_public_key_serialize,   [:pointer, :pointer],:pointer
  attach_function :signal_kyber_public_key_destroy,     [:pointer],          :pointer
  attach_function :signal_kyber_secret_key_serialize,   [:pointer, :pointer],:pointer
  attach_function :signal_kyber_secret_key_destroy,     [:pointer],          :pointer
  attach_function :signal_kyber_pre_key_record_new,
    [:pointer, :uint32, :uint64, :pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_kyber_pre_key_record_serialize,
    [:pointer, :pointer], :pointer
  attach_function :signal_kyber_pre_key_record_deserialize,
    [:pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_kyber_pre_key_record_get_public_key, [:pointer, :pointer], :pointer
  attach_function :signal_kyber_pre_key_record_get_signature,  [:pointer, :pointer], :pointer
  attach_function :signal_kyber_pre_key_record_destroy, [:pointer], :pointer

  # Session record
  attach_function :signal_session_record_serialize,
    [:pointer, :pointer], :pointer
  attach_function :signal_session_record_deserialize,
    [:pointer, BorrowedBuffer.by_value], :pointer

  # Sender key record
  attach_function :signal_sender_key_record_serialize,
    [:pointer, :pointer], :pointer
  attach_function :signal_sender_key_record_deserialize,
    [:pointer, BorrowedBuffer.by_value], :pointer

  # Pre-key bundle
  attach_function :signal_pre_key_bundle_new, [
    :pointer,                        # out
    :uint32, :uint32,                # reg_id, device_id
    :uint32, :bool, :pointer,        # opk_id, has_opk, opk_pub
    :uint32, :pointer,               # spk_id, spk_pub
    BorrowedBuffer.by_value,         # spk_sig
    :pointer,                        # id_pub
    :uint32, :bool, :pointer,        # kpk_id, has_kpk, kpk_pub
    BorrowedBuffer.by_value          # kpk_sig
  ], :pointer
  attach_function :signal_pre_key_bundle_destroy, [:pointer], :pointer

  # Session protocol
  attach_function :signal_process_prekey_bundle,
    [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :pointer
  attach_function :signal_encrypt_message,
    [:pointer, BorrowedBuffer.by_value, :pointer, :pointer, :pointer, :pointer, :pointer], :pointer
  attach_function :signal_decrypt_pre_key_message,
    [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :pointer
  attach_function :signal_decrypt_message,
    [:pointer, :pointer, :pointer, :pointer, :pointer], :pointer

  attach_function :signal_ciphertext_message_serialize, [:pointer, :pointer],  :pointer
  attach_function :signal_ciphertext_message_destroy,   [:pointer],             :pointer
  attach_function :signal_pre_key_signal_message_deserialize,
    [:pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_pre_key_signal_message_destroy, [:pointer], :pointer
  attach_function :signal_message_deserialize,
    [:pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_message_destroy, [:pointer], :pointer

  # Group
  attach_function :signal_sender_key_distribution_message_create,
    [:pointer, :pointer, BorrowedBuffer.by_value, :pointer], :pointer
  attach_function :signal_process_sender_key_distribution_message,
    [:pointer, :pointer, :pointer], :pointer
  attach_function :signal_group_encrypt_message,
    [:pointer, :pointer, BorrowedBuffer.by_value, BorrowedBuffer.by_value, :pointer], :pointer
  attach_function :signal_group_decrypt_message,
    [:pointer, :pointer, BorrowedBuffer.by_value, BorrowedBuffer.by_value, :pointer], :pointer
  attach_function :signal_sender_key_distribution_message_destroy, [:pointer], :pointer

  # Fingerprint
  attach_function :signal_fingerprint_new,
    [:pointer, :uint32, :uint32, BorrowedBuffer.by_value, :pointer,
     BorrowedBuffer.by_value, :pointer], :pointer
  attach_function :signal_fingerprint_scannable_encoding, [:pointer, :pointer], :pointer
  attach_function :signal_fingerprint_compare,
    [:pointer, :pointer, BorrowedBuffer.by_value], :pointer
  attach_function :signal_fingerprint_destroy, [:pointer], :pointer

  # Username
  attach_function :signal_username_hash,   [:pointer, :string], :pointer
  attach_function :signal_username_proof,  [:pointer, :string], :pointer
  attach_function :signal_username_verify, [:pointer, :pointer, BorrowedBuffer.by_value], :pointer

  # Account keys
  attach_function :signal_account_entropy_pool_generate, [:pointer],          :pointer
  attach_function :signal_account_entropy_pool_as_string,[:pointer, :pointer],:pointer
  attach_function :signal_account_entropy_pool_derive_svr_key,    [:pointer, :pointer], :pointer
  attach_function :signal_account_entropy_pool_derive_backup_key, [:pointer, :pointer], :pointer
  attach_function :signal_account_entropy_pool_destroy,           [:pointer],            :pointer
  attach_function :signal_backup_key_from_bytes, [:pointer, BorrowedBuffer.by_value],   :pointer
  attach_function :signal_backup_key_derive_media_encryption_key, [:pointer, :pointer], :pointer
  attach_function :signal_backup_key_destroy,    [:pointer],                             :pointer
end

# ── Helpers ──────────────────────────────────────────────────────────────────

def die(e, label)
  msg_pp = FFI::MemoryPointer.new(:pointer)
  Sig.signal_error_get_message(msg_pp, e)
  msg = msg_pp.read_pointer.null? ? "(no message)" : msg_pp.read_pointer.read_string
  Sig.signal_error_free(e)
  abort "[FAIL] #{label}: #{msg}"
end

def must(e, label = "unknown")
  die(e, label) unless e.null?
end

def borrow(bytes)
  buf = Sig::BorrowedBuffer.new
  ptr = FFI::MemoryPointer.new(:uint8, bytes.bytesize)
  ptr.put_bytes(0, bytes)
  buf[:base]   = ptr
  buf[:length] = bytes.bytesize
  [buf, ptr]  # return ptr too to prevent GC
end

def read_owned(owned_buf)
  data = owned_buf[:base].read_bytes(owned_buf[:length])
  Sig.signal_free_buffer(owned_buf[:base], owned_buf[:length])
  data
end

def addr_key(addr_ptr)
  name_pp = FFI::MemoryPointer.new(:pointer)
  dev_p   = FFI::MemoryPointer.new(:uint32)
  # SignalConstPointerSignalProtocolAddress = {raw: *const addr} — 1 ptr, ABI=ptr
  must Sig.signal_address_get_name(name_pp, addr_ptr),      "addr_get_name"
  must Sig.signal_address_get_device_id(dev_p, addr_ptr),   "addr_get_dev"
  "#{name_pp.read_pointer.read_string}:#{dev_p.read(:uint32)}"
end

# ── In-memory stores ─────────────────────────────────────────────────────────
# Each store class builds the FFI struct that signal_ffi.h expects.
# Callbacks can call back into Sig.* because ruby-ffi callbacks run on the
# calling thread (C calls into Ruby, Ruby calls back into C — all synchronous).

class SessionStore
  # SignalSessionStore = {user_data, load, store, reserved}
  attr_reader :ptr   # pointer to the struct (passed to signal_* functions)

  def initialize
    @db = {}   # addr_key -> serialized bytes

    @load_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer]) do |out, addr, _ud|
      k = addr_key(addr)
      data = @db[k]
      unless data
        out.put_pointer(0, FFI::Pointer::NULL)
        next FFI::Pointer::NULL
      end
      buf, _pin = borrow(data)
      rec_out = FFI::MemoryPointer.new(:pointer)
      # out points to SignalMutPointerSignalSessionRecord {raw: *opaque}
      e = Sig.signal_session_record_deserialize(out, buf)
      e
    end

    @store_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer]) do |addr, rec, _ud|
      # rec is SignalConstPointerSignalSessionRecord (treated as pointer)
      owned = Sig::OwnedBuffer.new
      e = Sig.signal_session_record_serialize(owned.to_ptr, rec)
      next e unless e.null?
      @db[addr_key(addr)] = owned[:base].read_bytes(owned[:length])
      Sig.signal_free_buffer(owned[:base], owned[:length])
      FFI::Pointer::NULL
    end

    @struct = FFI::MemoryPointer.new(:pointer, 4)
    @struct.put_pointer(0,  FFI::Pointer::NULL)   # ctx
    @struct.put_pointer(8,  @load_cb)             # load_session
    @struct.put_pointer(16, @store_cb)            # store_session
    @struct.put_pointer(24, FFI::Pointer::NULL)   # destroy
    @ptr = @struct
  end
end

class IdentityStore
  attr_reader :ptr

  def initialize(priv_bytes, reg_id)
    @priv  = priv_bytes
    @reg   = reg_id
    @db    = {}

    @get_kp_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer]) do |out_pub, out_priv, _ud|
      buf, _pin = borrow(@priv)
      e = Sig.signal_privatekey_deserialize(out_priv, buf)
      next e unless e.null?
      # SignalConstPointerSignalPrivateKey is 1-ptr ABI ≡ pointer
      priv_raw = out_priv.read_pointer
      Sig.signal_privatekey_get_public_key(out_pub, priv_raw)
    end

    @get_reg_cb = FFI::Function.new(:pointer, [:pointer, :pointer]) do |out, _ud|
      out.put_uint32(0, @reg)
      FFI::Pointer::NULL
    end

    @save_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer]) do |addr, key, _ud|
      owned = Sig::OwnedBuffer.new
      e = Sig.signal_publickey_serialize(owned.to_ptr, key)
      next e unless e.null?
      @db[addr_key(addr)] = owned[:base].read_bytes(owned[:length])
      Sig.signal_free_buffer(owned[:base], owned[:length])
      FFI::Pointer::NULL
    end

    @trusted_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer, :uint32, :pointer]) do |out, _addr, _key, _dir, _ud|
      out.put_uint8(0, 1)
      FFI::Pointer::NULL
    end

    @get_id_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer]) do |out, addr, _ud|
      data = @db[addr_key(addr)]
      unless data
        out.put_pointer(0, FFI::Pointer::NULL)
        next FFI::Pointer::NULL
      end
      buf, _pin = borrow(data)
      Sig.signal_publickey_deserialize(out, buf)
    end

    # SignalIdentityKeyStore = {ctx, get_keypair, get_registration_id, save_identity, is_trusted, get_identity, destroy}
    @struct = FFI::MemoryPointer.new(:pointer, 7)
    @struct.put_pointer(0,  FFI::Pointer::NULL)  # ctx
    @struct.put_pointer(8,  @get_kp_cb)          # get_identity_key_pair
    @struct.put_pointer(16, @get_reg_cb)         # get_local_registration_id
    @struct.put_pointer(24, @save_cb)            # save_identity
    @struct.put_pointer(32, @trusted_cb)         # is_trusted_identity
    @struct.put_pointer(40, @get_id_cb)          # get_identity
    @struct.put_pointer(48, FFI::Pointer::NULL)  # destroy
    @ptr = @struct
  end
end

class PreKeyStore
  attr_reader :ptr

  def initialize
    @db = {}

    @load_cb = FFI::Function.new(:pointer, [:pointer, :uint32, :pointer]) do |out, id, _ud|
      data = @db[id]
      unless data
        out.put_pointer(0, FFI::Pointer::NULL)
        next FFI::Pointer::NULL
      end
      buf, _pin = borrow(data)
      Sig.signal_pre_key_record_deserialize(out, buf)
    end

    @store_cb = FFI::Function.new(:pointer, [:uint32, :pointer, :pointer]) do |id, rec, _ud|
      owned = Sig::OwnedBuffer.new
      # rec is SignalMutPointerSignalPreKeyRecord (1-ptr ABI); serialize takes const ptr
      e = Sig.signal_pre_key_record_serialize(owned.to_ptr, rec)
      next e unless e.null?
      @db[id] = owned[:base].read_bytes(owned[:length])
      Sig.signal_free_buffer(owned[:base], owned[:length])
      FFI::Pointer::NULL
    end

    @remove_cb = FFI::Function.new(:pointer, [:uint32, :pointer]) do |_id, _ud|
      FFI::Pointer::NULL
    end

    # SignalPreKeyStore = {ctx, load, store, remove, destroy}
    @struct = FFI::MemoryPointer.new(:pointer, 5)
    @struct.put_pointer(0,  FFI::Pointer::NULL)  # ctx
    @struct.put_pointer(8,  @load_cb)            # load_pre_key
    @struct.put_pointer(16, @store_cb)           # store_pre_key
    @struct.put_pointer(24, @remove_cb)          # remove_pre_key
    @struct.put_pointer(32, FFI::Pointer::NULL)  # destroy
    @ptr = @struct
  end

  def store_record(id, rec_ptr)
    owned = Sig::OwnedBuffer.new
    must Sig.signal_pre_key_record_serialize(owned.to_ptr, rec_ptr), "pk_serialize"
    @db[id] = owned[:base].read_bytes(owned[:length])
    Sig.signal_free_buffer(owned[:base], owned[:length])
  end
end

class SignedPreKeyStore
  attr_reader :ptr

  def initialize
    @db = {}

    @load_cb = FFI::Function.new(:pointer, [:pointer, :uint32, :pointer]) do |out, id, _ud|
      data = @db[id]
      unless data
        out.put_pointer(0, FFI::Pointer::NULL)
        next FFI::Pointer::NULL
      end
      buf, _pin = borrow(data)
      Sig.signal_signed_pre_key_record_deserialize(out, buf)
    end

    @store_cb = FFI::Function.new(:pointer, [:uint32, :pointer, :pointer]) do |id, rec, _ud|
      owned = Sig::OwnedBuffer.new
      e = Sig.signal_signed_pre_key_record_serialize(owned.to_ptr, rec)
      next e unless e.null?
      @db[id] = owned[:base].read_bytes(owned[:length])
      Sig.signal_free_buffer(owned[:base], owned[:length])
      FFI::Pointer::NULL
    end

    # SignalSignedPreKeyStore = {ctx, load, store, destroy}
    @struct = FFI::MemoryPointer.new(:pointer, 4)
    @struct.put_pointer(0,  FFI::Pointer::NULL)  # ctx
    @struct.put_pointer(8,  @load_cb)            # load_signed_pre_key
    @struct.put_pointer(16, @store_cb)           # store_signed_pre_key
    @struct.put_pointer(24, FFI::Pointer::NULL)  # destroy
    @ptr = @struct
  end

  def store_record(id, rec_ptr)
    owned = Sig::OwnedBuffer.new
    must Sig.signal_signed_pre_key_record_serialize(owned.to_ptr, rec_ptr), "spk_serialize"
    @db[id] = owned[:base].read_bytes(owned[:length])
    Sig.signal_free_buffer(owned[:base], owned[:length])
  end
end

class KyberPreKeyStore
  attr_reader :ptr

  def initialize
    @db = {}

    @load_cb = FFI::Function.new(:pointer, [:pointer, :uint32, :pointer]) do |out, id, _ud|
      data = @db[id]
      unless data
        out.put_pointer(0, FFI::Pointer::NULL)
        next FFI::Pointer::NULL
      end
      buf, _pin = borrow(data)
      Sig.signal_kyber_pre_key_record_deserialize(out, buf)
    end

    @store_cb = FFI::Function.new(:pointer, [:uint32, :pointer, :pointer]) do |id, rec, _ud|
      owned = Sig::OwnedBuffer.new
      e = Sig.signal_kyber_pre_key_record_serialize(owned.to_ptr, rec)
      next e unless e.null?
      @db[id] = owned[:base].read_bytes(owned[:length])
      Sig.signal_free_buffer(owned[:base], owned[:length])
      FFI::Pointer::NULL
    end

    @mark_used_cb = FFI::Function.new(:pointer, [:uint32, :pointer]) { |*| FFI::Pointer::NULL }

    # SignalKyberPreKeyStore = {ctx, load, store, mark_used, destroy}
    @struct = FFI::MemoryPointer.new(:pointer, 5)
    @struct.put_pointer(0,  FFI::Pointer::NULL)  # ctx
    @struct.put_pointer(8,  @load_cb)            # load_kyber_pre_key
    @struct.put_pointer(16, @store_cb)           # store_kyber_pre_key
    @struct.put_pointer(24, @mark_used_cb)       # mark_kyber_pre_key_used
    @struct.put_pointer(32, FFI::Pointer::NULL)  # destroy
    @ptr = @struct
  end

  def store_record(id, rec_ptr)
    owned = Sig::OwnedBuffer.new
    must Sig.signal_kyber_pre_key_record_serialize(owned.to_ptr, rec_ptr), "kpk_serialize"
    @db[id] = owned[:base].read_bytes(owned[:length])
    Sig.signal_free_buffer(owned[:base], owned[:length])
  end
end

class SenderKeyStore
  attr_reader :ptr

  def initialize
    @db = {}

    @store_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer, :pointer]) do |addr, dist, rec, _ud|
      k = "#{addr_key(addr)}:#{dist.read_bytes(16).unpack1('H*')}"
      owned = Sig::OwnedBuffer.new
      e = Sig.signal_sender_key_record_serialize(owned.to_ptr, rec)
      next e unless e.null?
      @db[k] = owned[:base].read_bytes(owned[:length])
      Sig.signal_free_buffer(owned[:base], owned[:length])
      FFI::Pointer::NULL
    end

    @load_cb = FFI::Function.new(:pointer, [:pointer, :pointer, :pointer, :pointer]) do |out, addr, dist, _ud|
      k = "#{addr_key(addr)}:#{dist.read_bytes(16).unpack1('H*')}"
      data = @db[k]
      unless data
        out.put_pointer(0, FFI::Pointer::NULL)
        next FFI::Pointer::NULL
      end
      buf, _pin = borrow(data)
      Sig.signal_sender_key_record_deserialize(out, buf)
    end

    # SignalSenderKeyStore = {ctx, store_sender_key, load_sender_key, destroy}
    @struct = FFI::MemoryPointer.new(:pointer, 4)
    @struct.put_pointer(0,  FFI::Pointer::NULL)  # ctx
    @struct.put_pointer(8,  @store_cb)           # store_sender_key
    @struct.put_pointer(16, @load_cb)            # load_sender_key
    @struct.put_pointer(24, FFI::Pointer::NULL)  # destroy
    @ptr = @struct
  end
end

# ── sign_bytes helper ─────────────────────────────────────────────────────────

def sign_bytes(priv32, data)
  buf, _pin = borrow(priv32)
  priv_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_deserialize(priv_out, buf), "sign_bytes_deser"
  priv_raw = priv_out.read_pointer
  owned = Sig::OwnedBuffer.new
  data_buf, _pin2 = borrow(data)
  must Sig.signal_privatekey_sign(owned.to_ptr, priv_raw, data_buf), "sign_bytes_sign"
  Sig.signal_privatekey_destroy(priv_raw)
  read_owned(owned)
end

# ── Bob setup (identity + OPK + SPK + KPK) ───────────────────────────────────

BobKeys = Struct.new(:id_priv, :reg_id, :opk_id, :spk_id, :kpk_id)

def setup_bob(pk_store, spk_store, kpk_store)
  id_priv_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_generate(id_priv_out), "bob_id_gen"
  owned = Sig::OwnedBuffer.new
  must Sig.signal_privatekey_serialize(owned.to_ptr, id_priv_out.read_pointer), "bob_id_ser"
  id_priv_bytes = read_owned(owned)
  Sig.signal_privatekey_destroy(id_priv_out.read_pointer)

  bob = BobKeys.new(id_priv_bytes, 2002, 1, 1, 1)

  # OPK
  opk_priv_out = FFI::MemoryPointer.new(:pointer)
  opk_pub_out  = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_generate(opk_priv_out), "opk_gen"
  must Sig.signal_privatekey_get_public_key(opk_pub_out, opk_priv_out.read_pointer), "opk_pub"
  rec_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_pre_key_record_new(rec_out, bob.opk_id,
         opk_pub_out.read_pointer, opk_priv_out.read_pointer), "opk_rec"
  Sig.signal_privatekey_destroy(opk_priv_out.read_pointer)
  Sig.signal_publickey_destroy(opk_pub_out.read_pointer)
  pk_store.store_record(bob.opk_id, rec_out.read_pointer)
  Sig.signal_pre_key_record_destroy(rec_out.read_pointer)

  # SPK
  spk_priv_out = FFI::MemoryPointer.new(:pointer)
  spk_pub_out  = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_generate(spk_priv_out), "spk_gen"
  must Sig.signal_privatekey_get_public_key(spk_pub_out, spk_priv_out.read_pointer), "spk_pub"
  spk_pub_owned = Sig::OwnedBuffer.new
  must Sig.signal_publickey_serialize(spk_pub_owned.to_ptr, spk_pub_out.read_pointer), "spk_pub_ser"
  spk_pub_bytes = read_owned(spk_pub_owned)
  spk_sig_bytes = sign_bytes(bob.id_priv, spk_pub_bytes)
  spk_sig_buf, _pin = borrow(spk_sig_bytes)
  spk_rec_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_signed_pre_key_record_new(spk_rec_out, bob.spk_id, 1700000000,
         spk_pub_out.read_pointer, spk_priv_out.read_pointer, spk_sig_buf), "spk_rec"
  Sig.signal_privatekey_destroy(spk_priv_out.read_pointer)
  Sig.signal_publickey_destroy(spk_pub_out.read_pointer)
  spk_store.store_record(bob.spk_id, spk_rec_out.read_pointer)
  Sig.signal_signed_pre_key_record_destroy(spk_rec_out.read_pointer)

  # KPK
  kpk_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_kyber_key_pair_generate(kpk_out), "kpk_gen"
  kpk_pub_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_kyber_key_pair_get_public_key(kpk_pub_out, kpk_out.read_pointer), "kpk_pub"
  kpk_pub_owned = Sig::OwnedBuffer.new
  must Sig.signal_kyber_public_key_serialize(kpk_pub_owned.to_ptr, kpk_pub_out.read_pointer), "kpk_pub_ser"
  kpk_pub_bytes = read_owned(kpk_pub_owned)
  kpk_sig_bytes = sign_bytes(bob.id_priv, kpk_pub_bytes)
  kpk_sig_buf, _pin2 = borrow(kpk_sig_bytes)
  kpk_rec_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_kyber_pre_key_record_new(kpk_rec_out, bob.kpk_id, 1700000000,
         kpk_out.read_pointer, kpk_sig_buf), "kpk_rec"
  Sig.signal_kyber_public_key_destroy(kpk_pub_out.read_pointer)
  Sig.signal_kyber_key_pair_destroy(kpk_out.read_pointer)
  kpk_store.store_record(bob.kpk_id, kpk_rec_out.read_pointer)
  Sig.signal_kyber_pre_key_record_destroy(kpk_rec_out.read_pointer)

  bob
end

# ── Tests ─────────────────────────────────────────────────────────────────────

def test_ec_keys
  pa_out = FFI::MemoryPointer.new(:pointer)
  pb_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_generate(pa_out), "gen_a"
  must Sig.signal_privatekey_generate(pb_out), "gen_b"
  pa = pa_out.read_pointer; pb = pb_out.read_pointer

  qa_out = FFI::MemoryPointer.new(:pointer)
  qb_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_get_public_key(qa_out, pa), "pub_a"
  must Sig.signal_privatekey_get_public_key(qb_out, pb), "pub_b"
  qa = qa_out.read_pointer; qb = qb_out.read_pointer

  dh_a = Sig::OwnedBuffer.new; dh_b = Sig::OwnedBuffer.new
  must Sig.signal_privatekey_agree(dh_a.to_ptr, pa, qb), "dh_a"
  must Sig.signal_privatekey_agree(dh_b.to_ptr, pb, qa), "dh_b"
  raise "FAIL DH mismatch" unless dh_a[:base].read_bytes(32) == dh_b[:base].read_bytes(32)
  Sig.signal_free_buffer(dh_a[:base], dh_a[:length])
  Sig.signal_free_buffer(dh_b[:base], dh_b[:length])

  msg = "hello signal"
  msg_buf, _pin = borrow(msg)
  sig_owned = Sig::OwnedBuffer.new
  must Sig.signal_privatekey_sign(sig_owned.to_ptr, pa, msg_buf), "sign"
  sig_buf, _pin2 = borrow(sig_owned[:base].read_bytes(sig_owned[:length]))
  Sig.signal_free_buffer(sig_owned[:base], sig_owned[:length])
  ok_p = FFI::MemoryPointer.new(:bool)
  must Sig.signal_publickey_verify(ok_p, qa, msg_buf, sig_buf), "verify"
  raise "FAIL verify" unless ok_p.read(:bool)

  Sig.signal_privatekey_destroy(pa); Sig.signal_privatekey_destroy(pb)
  Sig.signal_publickey_destroy(qa);  Sig.signal_publickey_destroy(qb)
  puts "EC + XEdDSA                   PASS"
end

def test_kyber_keys
  kp_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_kyber_key_pair_generate(kp_out), "kpk_gen"
  kp = kp_out.read_pointer

  pub_out = FFI::MemoryPointer.new(:pointer)
  sec_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_kyber_key_pair_get_public_key(pub_out, kp), "kpk_pub"
  must Sig.signal_kyber_key_pair_get_secret_key(sec_out, kp), "kpk_sec"

  pub_owned = Sig::OwnedBuffer.new; sec_owned = Sig::OwnedBuffer.new
  must Sig.signal_kyber_public_key_serialize(pub_owned.to_ptr, pub_out.read_pointer), "kpk_pub_ser"
  must Sig.signal_kyber_secret_key_serialize(sec_owned.to_ptr, sec_out.read_pointer), "kpk_sec_ser"
  raise "FAIL Kyber pub size #{pub_owned[:length]}" unless pub_owned[:length] == 1568
  raise "FAIL Kyber sec size #{sec_owned[:length]}" unless sec_owned[:length] == 3168
  Sig.signal_free_buffer(pub_owned[:base], pub_owned[:length])
  Sig.signal_free_buffer(sec_owned[:base], sec_owned[:length])
  Sig.signal_kyber_key_pair_destroy(kp)
  Sig.signal_kyber_public_key_destroy(pub_out.read_pointer)
  Sig.signal_kyber_secret_key_destroy(sec_out.read_pointer)
  puts "ML-KEM-1024 (Kyber)           PASS"
end

def test_session
  # Alice identity
  alice_priv_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_generate(alice_priv_out), "alice_id_gen"
  alice_id_owned = Sig::OwnedBuffer.new
  must Sig.signal_privatekey_serialize(alice_id_owned.to_ptr, alice_priv_out.read_pointer), "alice_id_ser"
  alice_id_priv = read_owned(alice_id_owned)
  Sig.signal_privatekey_destroy(alice_priv_out.read_pointer)

  # Bob key material
  bob_pk_s  = PreKeyStore.new
  bob_spk_s = SignedPreKeyStore.new
  bob_kpk_s = KyberPreKeyStore.new
  bob = setup_bob(bob_pk_s, bob_spk_s, bob_kpk_s)

  # Reload public components from Bob's stores for the bundle
  # (in practice these come over the network)
  bob_priv_out = FFI::MemoryPointer.new(:pointer)
  buf, _pin = borrow(bob.id_priv)
  must Sig.signal_privatekey_deserialize(bob_priv_out, buf), "bob_id_deser"
  bob_id_pub_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_get_public_key(bob_id_pub_out, bob_priv_out.read_pointer), "bob_id_pub"
  Sig.signal_privatekey_destroy(bob_priv_out.read_pointer)

  # Load OPK record from store to get public key
  opk_rec_out = FFI::MemoryPointer.new(:pointer)
  opk_data    = bob_pk_s.instance_variable_get(:@db)[bob.opk_id]
  opk_buf, _  = borrow(opk_data)
  must Sig.signal_pre_key_record_deserialize(opk_rec_out, opk_buf), "opk_load"
  opk_pub_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_pre_key_record_get_public_key(opk_pub_out, opk_rec_out.read_pointer), "opk_pub_get"
  Sig.signal_pre_key_record_destroy(opk_rec_out.read_pointer)

  # Load SPK record from store to get public key + signature
  spk_rec_out = FFI::MemoryPointer.new(:pointer)
  spk_data    = bob_spk_s.instance_variable_get(:@db)[bob.spk_id]
  spk_buf, _  = borrow(spk_data)
  must Sig.signal_signed_pre_key_record_deserialize(spk_rec_out, spk_buf), "spk_load"
  spk_pub_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_signed_pre_key_record_get_public_key(spk_pub_out, spk_rec_out.read_pointer), "spk_pub_get"
  spk_sig_owned = Sig::OwnedBuffer.new
  must Sig.signal_signed_pre_key_record_get_signature(spk_sig_owned.to_ptr, spk_rec_out.read_pointer), "spk_sig_get"
  spk_sig_bytes = read_owned(spk_sig_owned)
  Sig.signal_signed_pre_key_record_destroy(spk_rec_out.read_pointer)

  # Load KPK record from store to get public key + signature
  kpk_rec_out = FFI::MemoryPointer.new(:pointer)
  kpk_data    = bob_kpk_s.instance_variable_get(:@db)[bob.kpk_id]
  kpk_buf, _  = borrow(kpk_data)
  must Sig.signal_kyber_pre_key_record_deserialize(kpk_rec_out, kpk_buf), "kpk_load"
  kpk_pub_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_kyber_pre_key_record_get_public_key(kpk_pub_out, kpk_rec_out.read_pointer), "kpk_pub_get"
  kpk_sig_owned = Sig::OwnedBuffer.new
  must Sig.signal_kyber_pre_key_record_get_signature(kpk_sig_owned.to_ptr, kpk_rec_out.read_pointer), "kpk_sig_get"
  kpk_sig_bytes = read_owned(kpk_sig_owned)
  Sig.signal_kyber_pre_key_record_destroy(kpk_rec_out.read_pointer)

  # Build pre-key bundle
  bundle_out  = FFI::MemoryPointer.new(:pointer)
  spk_sig_buf, _s = borrow(spk_sig_bytes)
  kpk_sig_buf, _k = borrow(kpk_sig_bytes)
  must Sig.signal_pre_key_bundle_new(
    bundle_out,
    bob.reg_id, 1,
    bob.opk_id, true,  opk_pub_out.read_pointer,
    bob.spk_id,        spk_pub_out.read_pointer, spk_sig_buf,
    bob_id_pub_out.read_pointer,
    bob.kpk_id, true,  kpk_pub_out.read_pointer, kpk_sig_buf
  ), "bundle_new"
  Sig.signal_publickey_destroy(opk_pub_out.read_pointer)
  Sig.signal_publickey_destroy(spk_pub_out.read_pointer)
  Sig.signal_kyber_public_key_destroy(kpk_pub_out.read_pointer)
  Sig.signal_publickey_destroy(bob_id_pub_out.read_pointer)

  # Alice's stores
  alice_ss  = SessionStore.new
  alice_is  = IdentityStore.new(alice_id_priv, 1001)
  alice_pks = PreKeyStore.new
  alice_sks = SignedPreKeyStore.new
  alice_kks = KyberPreKeyStore.new

  # Bob's stores
  bob_ss = SessionStore.new
  bob_is = IdentityStore.new(bob.id_priv, bob.reg_id)

  # Addresses
  bob_addr_out   = FFI::MemoryPointer.new(:pointer)
  alice_addr_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_address_new(bob_addr_out,   "bob",   1), "bob_addr"
  must Sig.signal_address_new(alice_addr_out, "alice", 1), "alice_addr"
  bob_addr   = bob_addr_out.read_pointer
  alice_addr = alice_addr_out.read_pointer

  # Alice processes bundle
  must Sig.signal_process_prekey_bundle(
    bundle_out.read_pointer, bob_addr,
    alice_ss.ptr, alice_is.ptr, alice_pks.ptr, alice_sks.ptr, alice_kks.ptr
  ), "process_bundle"
  Sig.signal_pre_key_bundle_destroy(bundle_out.read_pointer)

  # Alice encrypts
  pt1 = "hello bob"
  pt1_buf, _p = borrow(pt1)
  ct1_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_encrypt_message(ct1_out, pt1_buf, bob_addr,
    alice_ss.ptr, alice_is.ptr, alice_pks.ptr, alice_sks.ptr), "encrypt_1"
  ct1_owned = Sig::OwnedBuffer.new
  must Sig.signal_ciphertext_message_serialize(ct1_owned.to_ptr, ct1_out.read_pointer), "ct1_ser"
  Sig.signal_ciphertext_message_destroy(ct1_out.read_pointer)
  ct1_bytes = read_owned(ct1_owned)

  # Bob decrypts the pre-key message
  pksm_out = FFI::MemoryPointer.new(:pointer)
  ct1_buf, _ = borrow(ct1_bytes)
  must Sig.signal_pre_key_signal_message_deserialize(pksm_out, ct1_buf), "pksm_deser"
  dec1_owned = Sig::OwnedBuffer.new
  must Sig.signal_decrypt_pre_key_message(dec1_owned.to_ptr, pksm_out.read_pointer, alice_addr,
    bob_ss.ptr, bob_is.ptr, bob_pk_s.ptr, bob_spk_s.ptr, bob_kpk_s.ptr), "decrypt_prekey"
  Sig.signal_pre_key_signal_message_destroy(pksm_out.read_pointer)
  dec1 = read_owned(dec1_owned)
  raise "FAIL pre-key plaintext: #{dec1.inspect}" unless dec1 == pt1

  # Bob replies (whisper message)
  pt2 = "hey alice"
  pt2_buf, _p2 = borrow(pt2)
  ct2_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_encrypt_message(ct2_out, pt2_buf, alice_addr,
    bob_ss.ptr, bob_is.ptr, bob_pk_s.ptr, bob_spk_s.ptr), "encrypt_2"
  ct2_owned = Sig::OwnedBuffer.new
  must Sig.signal_ciphertext_message_serialize(ct2_owned.to_ptr, ct2_out.read_pointer), "ct2_ser"
  Sig.signal_ciphertext_message_destroy(ct2_out.read_pointer)
  ct2_bytes = read_owned(ct2_owned)

  whisper_out = FFI::MemoryPointer.new(:pointer)
  ct2_buf, _ = borrow(ct2_bytes)
  must Sig.signal_message_deserialize(whisper_out, ct2_buf), "whisper_deser"
  dec2_owned = Sig::OwnedBuffer.new
  must Sig.signal_decrypt_message(dec2_owned.to_ptr, whisper_out.read_pointer, bob_addr,
    alice_ss.ptr, alice_is.ptr), "decrypt_whisper"
  Sig.signal_message_destroy(whisper_out.read_pointer)
  dec2 = read_owned(dec2_owned)
  raise "FAIL whisper plaintext: #{dec2.inspect}" unless dec2 == pt2

  Sig.signal_address_destroy(bob_addr)
  Sig.signal_address_destroy(alice_addr)
  puts "X3DH + PQXDH + Double Ratchet PASS"
end

def test_group
  dist_id = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  dist_buf, _dist_pin = borrow(dist_id)

  alice_sk = SenderKeyStore.new
  bob_sk   = SenderKeyStore.new

  alice_addr_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_address_new(alice_addr_out, "alice", 1), "alice_addr"
  alice_addr = alice_addr_out.read_pointer

  skdm_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_sender_key_distribution_message_create(skdm_out, alice_addr, dist_buf, alice_sk.ptr), "skdm_create"
  must Sig.signal_process_sender_key_distribution_message(alice_addr, skdm_out.read_pointer, bob_sk.ptr), "skdm_process"
  Sig.signal_sender_key_distribution_message_destroy(skdm_out.read_pointer)

  msg = "group hello"; msg_buf, _p = borrow(msg)
  enc_owned = Sig::OwnedBuffer.new
  must Sig.signal_group_encrypt_message(enc_owned.to_ptr, alice_addr, dist_buf, msg_buf, alice_sk.ptr), "group_enc"
  enc_bytes = read_owned(enc_owned)

  dec_owned = Sig::OwnedBuffer.new
  enc_buf, _ = borrow(enc_bytes)
  must Sig.signal_group_decrypt_message(dec_owned.to_ptr, alice_addr, dist_buf, enc_buf, bob_sk.ptr), "group_dec"
  dec = read_owned(dec_owned)
  raise "FAIL group plaintext: #{dec.inspect}" unless dec == msg

  Sig.signal_address_destroy(alice_addr)
  puts "Sender Keys (group)           PASS"
end

def test_fingerprint
  pa_out = FFI::MemoryPointer.new(:pointer); pb_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_generate(pa_out), "fp_gen_a"
  must Sig.signal_privatekey_generate(pb_out), "fp_gen_b"
  qa_out = FFI::MemoryPointer.new(:pointer); qb_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_privatekey_get_public_key(qa_out, pa_out.read_pointer), "fp_puba"
  must Sig.signal_privatekey_get_public_key(qb_out, pb_out.read_pointer), "fp_pubb"
  Sig.signal_privatekey_destroy(pa_out.read_pointer)
  Sig.signal_privatekey_destroy(pb_out.read_pointer)

  aid_buf, _ = borrow("+15551234567"); bid_buf, _ = borrow("+15559876543")
  fp_a_out = FFI::MemoryPointer.new(:pointer); fp_b_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_fingerprint_new(fp_a_out, 5200, 0, aid_buf, qa_out.read_pointer, bid_buf, qb_out.read_pointer), "fp_new_a"
  must Sig.signal_fingerprint_new(fp_b_out, 5200, 0, bid_buf, qb_out.read_pointer, aid_buf, qa_out.read_pointer), "fp_new_b"
  Sig.signal_publickey_destroy(qa_out.read_pointer)
  Sig.signal_publickey_destroy(qb_out.read_pointer)

  scan_b = Sig::OwnedBuffer.new
  must Sig.signal_fingerprint_scannable_encoding(scan_b.to_ptr, fp_b_out.read_pointer), "fp_scan_b"
  scan_b_bytes = read_owned(scan_b)

  ok_p = FFI::MemoryPointer.new(:bool)
  scan_buf, _ = borrow(scan_b_bytes)
  must Sig.signal_fingerprint_compare(ok_p, fp_a_out.read_pointer, scan_buf), "fp_compare"
  raise "FAIL fingerprint mismatch" unless ok_p.read(:bool)

  Sig.signal_fingerprint_destroy(fp_a_out.read_pointer)
  Sig.signal_fingerprint_destroy(fp_b_out.read_pointer)
  puts "Fingerprints                  PASS"
end

def test_username
  hash_ptr = FFI::MemoryPointer.new(:uint8, 32)
  must Sig.signal_username_hash(hash_ptr, "alice.42"), "username_hash"

  proof_owned = Sig::OwnedBuffer.new
  must Sig.signal_username_proof(proof_owned.to_ptr, "alice.42"), "username_proof"
  proof_bytes = read_owned(proof_owned)

  ok_p = FFI::MemoryPointer.new(:bool)
  proof_buf, _ = borrow(proof_bytes)
  must Sig.signal_username_verify(ok_p, hash_ptr, proof_buf), "username_verify"
  raise "FAIL username invalid" unless ok_p.read(:bool)
  puts "Username ZK proof             PASS"
end

def test_account_keys
  pool_out = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_account_entropy_pool_generate(pool_out), "pool_gen"
  pool = pool_out.read_pointer

  str_pp = FFI::MemoryPointer.new(:pointer)
  must Sig.signal_account_entropy_pool_as_string(str_pp, pool), "pool_str"
  puts "  Entropy pool: #{str_pp.read_pointer.read_string[0,16]}…"
  Sig.signal_free_string(str_pp.read_pointer)

  svr = FFI::MemoryPointer.new(:uint8, 32)
  bk  = FFI::MemoryPointer.new(:uint8, 32)
  must Sig.signal_account_entropy_pool_derive_svr_key(svr, pool),    "svr_key"
  must Sig.signal_account_entropy_pool_derive_backup_key(bk, pool),  "backup_key"
  Sig.signal_account_entropy_pool_destroy(pool)
  raise "FAIL svr==backup" if svr.read_bytes(32) == bk.read_bytes(32)

  bk_obj_out = FFI::MemoryPointer.new(:pointer)
  bk_buf, _  = borrow(bk.read_bytes(32))
  must Sig.signal_backup_key_from_bytes(bk_obj_out, bk_buf), "bk_from_bytes"
  media = FFI::MemoryPointer.new(:uint8, 32)
  must Sig.signal_backup_key_derive_media_encryption_key(media, bk_obj_out.read_pointer), "media_key"
  Sig.signal_backup_key_destroy(bk_obj_out.read_pointer)
  raise "FAIL backup==media" if bk.read_bytes(32) == media.read_bytes(32)
  puts "Account entropy pool          PASS"
end

# ── Main ──────────────────────────────────────────────────────────────────────

test_ec_keys
test_kyber_keys
test_session
test_group
test_fingerprint
test_username
test_account_keys
puts "\nAll signal_ffi tests PASSED."
