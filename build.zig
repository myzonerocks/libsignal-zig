const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Native Zig module — import as "libsignal_zig" from other Zig projects.
    _ = b.addModule("libsignal_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library (Zig API).
    const static_lib = b.addLibrary(.{
        .name = "signal_zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });
    b.installArtifact(static_lib);

    // Signal FFI shared library — signal_ffi.h-compatible C API.
    // All C/C++/Go/Ruby/Java/Rust examples link against this.
    const ffi_lib = b.addLibrary(.{
        .name = "signal_ffi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi_entry.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .dynamic,
    });
    ffi_lib.root_module.link_libc = true;
    b.installArtifact(ffi_lib);

    // Integration tests.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run integration tests");
    test_step.dependOn(&run_tests.step);
}
