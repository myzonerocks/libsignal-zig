//! Stub implementations.
//! These return not_yet_implemented until the underlying crypto/network layers are built.

const std = @import("std");
const err_mod = @import("error.zig");
const keys = @import("keys.zig");
const gpa = std.heap.c_allocator;

const SignalFfiError = err_mod.SignalFfiError;
const SignalOwnedBuffer = keys.SignalOwnedBuffer;
const SignalBorrowedBuffer = keys.SignalBorrowedBuffer;

fn stub(name: []const u8) *SignalFfiError {
    _ = name;
    return err_mod.alloc(.internal_error, "not yet implemented");
}

// ── Phase 13: PIN Hash ────────────────────────────────────────────────────────

pub const SignalPinHash = extern struct { bytes: [32]u8 };
pub const SignalMutPointerPinHash = extern struct { raw: ?*SignalPinHash };
pub const SignalConstPointerPinHash = extern struct { raw: ?*const SignalPinHash };

pub export fn signal_pin_hash_from_salt(out: *SignalMutPointerPinHash, pin: SignalBorrowedBuffer, salt: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = out;
    _ = pin;
    _ = salt;
    return stub("signal_pin_hash_from_salt");
}

pub export fn signal_pin_hash_clone(new_obj: *SignalMutPointerPinHash, obj: SignalConstPointerPinHash) ?*SignalFfiError {
    _ = new_obj;
    _ = obj;
    return stub("signal_pin_hash_clone");
}

pub export fn signal_pin_hash_destroy(p: SignalMutPointerPinHash) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_pin_hash_access_key(out: *SignalOwnedBuffer, obj: SignalConstPointerPinHash) ?*SignalFfiError {
    _ = out;
    _ = obj;
    return stub("signal_pin_hash_access_key");
}

pub export fn signal_pin_hash_encryption_key(out: *SignalOwnedBuffer, obj: SignalConstPointerPinHash) ?*SignalFfiError {
    _ = out;
    _ = obj;
    return stub("signal_pin_hash_encryption_key");
}

pub export fn signal_pin_local_hash(out: *[*:0]u8, pin: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = out;
    _ = pin;
    return stub("signal_pin_local_hash");
}

pub export fn signal_pin_verify_local_hash(out: *bool, encoded_hash: [*:0]const u8, pin: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = out;
    _ = encoded_hash;
    _ = pin;
    return stub("signal_pin_verify_local_hash");
}

// ── Phase 13: Device Transfer ─────────────────────────────────────────────────

pub export fn signal_device_transfer_generate_private_key(out: *SignalOwnedBuffer) ?*SignalFfiError {
    _ = out;
    return stub("signal_device_transfer_generate_private_key");
}

pub export fn signal_device_transfer_generate_certificate(out: *SignalOwnedBuffer, private_key: SignalBorrowedBuffer, name: [*:0]const u8, days_to_expire: u32) ?*SignalFfiError {
    _ = out;
    _ = private_key;
    _ = name;
    _ = days_to_expire;
    return stub("signal_device_transfer_generate_certificate");
}

// ── Phase 14: ZK Credentials (all stubs) ─────────────────────────────────────

pub const SignalServerSecretParams = extern struct { reserved: u8 };
pub const SignalMutPointerServerSecretParams = extern struct { raw: ?*SignalServerSecretParams };
pub const SignalConstPointerServerSecretParams = extern struct { raw: ?*const SignalServerSecretParams };

pub export fn signal_server_secret_params_generate_deterministic(out: *SignalMutPointerServerSecretParams, randomness: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = out;
    _ = randomness;
    return stub("signal_server_secret_params_generate_deterministic");
}

pub export fn signal_server_secret_params_destroy(p: SignalMutPointerServerSecretParams) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub const SignalServerPublicParams = extern struct { reserved: u8 };
pub const SignalMutPointerServerPublicParams = extern struct { raw: ?*SignalServerPublicParams };
pub const SignalConstPointerServerPublicParams = extern struct { raw: ?*const SignalServerPublicParams };

pub export fn signal_server_public_params_destroy(p: SignalMutPointerServerPublicParams) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_server_secret_params_get_public_params(out: *SignalMutPointerServerPublicParams, obj: SignalConstPointerServerSecretParams) ?*SignalFfiError {
    _ = out;
    _ = obj;
    return stub("signal_server_secret_params_get_public_params");
}

// ── Phase 15: Message Backup (stubs) ─────────────────────────────────────────

pub const SignalMessageBackupValidationOutcome = extern struct { reserved: u8 };
pub const SignalMutPointerMessageBackupValidationOutcome = extern struct { raw: ?*SignalMessageBackupValidationOutcome };

pub export fn signal_message_backup_validation_outcome_destroy(p: SignalMutPointerMessageBackupValidationOutcome) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_message_backup_validation_outcome_get_error_message(out: *?[*:0]const u8, obj: *const SignalMessageBackupValidationOutcome) ?*SignalFfiError {
    _ = out;
    _ = obj;
    return stub("signal_message_backup_validation_outcome_get_error_message");
}

pub export fn signal_message_backup_validation_outcome_get_unknown_fields(out: *SignalOwnedBuffer, obj: *const SignalMessageBackupValidationOutcome) ?*SignalFfiError {
    _ = out;
    _ = obj;
    return stub("signal_message_backup_validation_outcome_get_unknown_fields");
}

pub const SignalOnlineBackupValidator = extern struct { reserved: u8 };
pub const SignalMutPointerOnlineBackupValidator = extern struct { raw: ?*SignalOnlineBackupValidator };

pub export fn signal_online_backup_validator_new(out: *SignalMutPointerOnlineBackupValidator, backup_info_frame: SignalBorrowedBuffer, purpose: u8) ?*SignalFfiError {
    _ = out;
    _ = backup_info_frame;
    _ = purpose;
    return stub("signal_online_backup_validator_new");
}

pub export fn signal_online_backup_validator_add_frame(out: *SignalMutPointerMessageBackupValidationOutcome, validator: *SignalOnlineBackupValidator, frame: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = out;
    _ = validator;
    _ = frame;
    return stub("signal_online_backup_validator_add_frame");
}

pub export fn signal_online_backup_validator_finalize(out: *SignalMutPointerMessageBackupValidationOutcome, validator: *SignalOnlineBackupValidator) ?*SignalFfiError {
    _ = out;
    _ = validator;
    return stub("signal_online_backup_validator_finalize");
}

pub export fn signal_online_backup_validator_destroy(p: SignalMutPointerOnlineBackupValidator) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

// ── Phase 16: Media Sanitization (stubs) ─────────────────────────────────────

pub export fn signal_mp4_sanitizer_sanitize(out: *SignalOwnedBuffer, input: SignalBorrowedBuffer, len: u64) ?*SignalFfiError {
    _ = out;
    _ = input;
    _ = len;
    return stub("signal_mp4_sanitizer_sanitize");
}

pub export fn signal_webp_sanitizer_sanitize(out: *SignalOwnedBuffer, input: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = out;
    _ = input;
    return stub("signal_webp_sanitizer_sanitize");
}

pub export fn signal_signal_media_check_available() ?*SignalFfiError {
    return null;
}

// ── Phase 17: Async Infrastructure (stubs) ───────────────────────────────────

pub const SignalTokioAsyncContext = extern struct { reserved: u8 };
pub const SignalMutPointerTokioAsyncContext = extern struct { raw: ?*SignalTokioAsyncContext };

pub export fn signal_tokio_async_context_new(out: *SignalMutPointerTokioAsyncContext) ?*SignalFfiError {
    _ = out;
    return stub("signal_tokio_async_context_new");
}

pub export fn signal_tokio_async_context_destroy(p: SignalMutPointerTokioAsyncContext) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

pub export fn signal_tokio_async_context_cancel(ctx: *SignalTokioAsyncContext) ?*SignalFfiError {
    _ = ctx;
    return stub("signal_tokio_async_context_cancel");
}

// ── Phase 18: Network / Chat (stubs) ─────────────────────────────────────────

pub const SignalConnectionManager = extern struct { reserved: u8 };
pub const SignalMutPointerConnectionManager = extern struct { raw: ?*SignalConnectionManager };

pub export fn signal_connection_manager_new(out: *SignalMutPointerConnectionManager, environment: u8, user_agent: [*:0]const u8) ?*SignalFfiError {
    _ = out;
    _ = environment;
    _ = user_agent;
    return stub("signal_connection_manager_new");
}

pub export fn signal_connection_manager_destroy(p: SignalMutPointerConnectionManager) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

// ── Phase 19: SVR / CDSI (stubs) ─────────────────────────────────────────────

pub const SignalSgxClientState = extern struct { reserved: u8 };
pub const SignalMutPointerSgxClientState = extern struct { raw: ?*SignalSgxClientState };

pub export fn signal_sgx_client_state_destroy(p: SignalMutPointerSgxClientState) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

// ── Phase 20: Registration (stubs) ───────────────────────────────────────────

pub const SignalRegistrationService = extern struct { reserved: u8 };
pub const SignalMutPointerRegistrationService = extern struct { raw: ?*SignalRegistrationService };

pub export fn signal_registration_service_destroy(p: SignalMutPointerRegistrationService) ?*SignalFfiError {
    if (p.raw) |obj| gpa.destroy(obj);
    return null;
}

// ── Phase 21: Key Transparency (stubs) ───────────────────────────────────────

pub export fn signal_key_transparency_check(out: *SignalOwnedBuffer, key: SignalBorrowedBuffer) ?*SignalFfiError {
    _ = out;
    _ = key;
    return stub("signal_key_transparency_check");
}
