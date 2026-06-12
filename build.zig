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

    // Shared library with C-compatible exports (include/libsignal.h).
    // Outputs are malloc'd; callers free with the standard free().
    const shared_lib = b.addLibrary(.{
        .name = "signal",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/c_api.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .dynamic,
    });
    shared_lib.root_module.link_libc = true;
    b.installArtifact(shared_lib);
    b.installFile("include/libsignal.h", "include/libsignal.h");

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
