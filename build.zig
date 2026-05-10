const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sqlite_dep = b.dependency("sqlite_amalgamation", .{});
    const cli_dep = b.dependency("cli", .{ .target = target, .optimize = optimize });

    const sqlite_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
    });
    sqlite_mod.addCSourceFile(.{
        .file = sqlite_dep.path("sqlite3.c"),
        .flags = &.{
            "-DSQLITE_THREADSAFE=0",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
        },
    });
    sqlite_mod.addIncludePath(sqlite_dep.path(""));
    sqlite_mod.link_libc = true;

    const sqlite_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "sqlite3",
        .root_module = sqlite_mod,
    });

    const lib_mod = b.addModule("sweetcookie", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkPlatformLibraries(lib_mod, target);

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "sweetcookie",
        .root_module = lib_mod,
    });
    lib.linkLibrary(sqlite_lib);
    b.installArtifact(lib);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("sweetcookie", lib_mod);
    exe_mod.addImport("cli", cli_dep.module("cli"));
    linkPlatformLibraries(exe_mod, target);

    const exe = b.addExecutable(.{
        .name = "sweetcookie",
        .root_module = exe_mod,
    });
    exe.linkLibrary(sqlite_lib);
    b.installArtifact(exe);

    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    lib_tests.linkLibrary(sqlite_lib);

    const exe_tests = b.addTest(.{ .root_module = exe_mod });
    exe_tests.linkLibrary(sqlite_lib);

    const run_lib_tests = b.addRunArtifact(lib_tests);
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const integration_tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration/cli_plumbing_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const integration_tests = b.addTest(.{ .root_module = integration_tests_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    run_integration_tests.step.dependOn(b.getInstallStep());

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    const api_smoke_mod = b.createModule(.{
        .root_source_file = b.path("tests/api_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    api_smoke_mod.addImport("sweetcookie", lib_mod);
    linkPlatformLibraries(api_smoke_mod, target);

    const api_smoke = b.addExecutable(.{
        .name = "api-smoke",
        .root_module = api_smoke_mod,
    });
    api_smoke.linkLibrary(sqlite_lib);

    const api_smoke_step = b.step("api-smoke", "Compile a public API smoke test");
    api_smoke_step.dependOn(&api_smoke.step);

    const lint = b.addSystemCommand(&.{ "zig", "fmt", "--check", "src", "tests", "build.zig" });
    const lint_step = b.step("lint", "Check Zig formatting");
    lint_step.dependOn(&lint.step);
}

fn linkPlatformLibraries(module: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    switch (target.result.os.tag) {
        .macos => {
            module.linkFramework("Security", .{});
            module.linkFramework("CoreFoundation", .{});
        },
        .linux => {
            if (builtin.os.tag == .linux) {
                module.linkSystemLibrary("secret-1", .{
                    .needed = false,
                    .use_pkg_config = .no,
                });
            }
        },
        .windows => {
            module.linkSystemLibrary("crypt32", .{ .needed = false });
            module.linkSystemLibrary("bcrypt", .{ .needed = false });
        },
        else => {},
    }
}
