const std = @import("std");
const builtin = @import("builtin");

const OSStatus = i32;

extern fn SecKeychainFindGenericPassword(
    keychainOrArray: ?*anyopaque,
    serviceNameLength: u32,
    serviceName: [*]const u8,
    accountNameLength: u32,
    accountName: [*]const u8,
    passwordLength: *u32,
    passwordData: *?*anyopaque,
    itemRef: ?*?*anyopaque,
) callconv(.c) OSStatus;

extern fn SecKeychainItemFreeContent(attrList: ?*anyopaque, data: ?*anyopaque) callconv(.c) OSStatus;

pub const SecretError = error{
    UnsupportedPlatform,
    InvalidHexKey,
    NativeSecretFailed,
    FallbackSecretFailed,
};

pub fn getStorageKey(allocator: std.mem.Allocator, browser_name: []const u8) ![]u8 {
    if (try keyFromTestEnv(allocator)) |key| return key;
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    if (try forceNativeFail()) {
        return fallbackStorageKey(allocator, browser_name);
    }

    return nativeStorageKey(allocator, browser_name) catch fallbackStorageKey(allocator, browser_name);
}

fn keyFromTestEnv(allocator: std.mem.Allocator) !?[]u8 {
    const hex = std.process.getEnvVarOwned(allocator, "SWEETCOOKIE_TEST_CHROMIUM_KEY") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    defer allocator.free(hex);
    if (hex.len % 2 != 0) return error.InvalidHexKey;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, hex) catch return error.InvalidHexKey;
    return out;
}

fn forceNativeFail() !bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, "SWEETCOOKIE_FORCE_NATIVE_SECRET_FAIL") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer std.heap.page_allocator.free(value);
    return std.mem.eql(u8, value, "1");
}

fn nativeStorageKey(allocator: std.mem.Allocator, browser_name: []const u8) ![]u8 {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    const account = canonicalBrowserName(browser_name);
    const service = try serviceName(allocator, account);
    defer allocator.free(service);

    var password_len: u32 = 0;
    var password_data: ?*anyopaque = null;
    const status = SecKeychainFindGenericPassword(
        null,
        @intCast(service.len),
        service.ptr,
        @intCast(account.len),
        account.ptr,
        &password_len,
        &password_data,
        null,
    );
    if (status != 0) return error.NativeSecretFailed;
    defer _ = SecKeychainItemFreeContent(null, password_data);

    const bytes: [*]const u8 = @ptrCast(password_data orelse return error.NativeSecretFailed);
    return allocator.dupe(u8, bytes[0..password_len]);
}

fn fallbackStorageKey(allocator: std.mem.Allocator, browser_name: []const u8) ![]u8 {
    const account = canonicalBrowserName(browser_name);
    const service = try serviceName(allocator, account);
    defer allocator.free(service);

    emitFallbackWarning(account) catch {};
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "security", "find-generic-password", "-gw", "-a", account, "-s", service },
        .max_output_bytes = 16 * 1024,
        .expand_arg0 = .expand,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .Exited or result.term.Exited != 0) return error.FallbackSecretFailed;
    return allocator.dupe(u8, std.mem.trimRight(u8, result.stdout, "\r\n"));
}

fn emitFallbackWarning(browser_name: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var writer = std.fs.File.stderr().writer(&buffer);
    const stderr = &writer.interface;
    try stderr.print("warning: kind=os-secret-fallback message=<len={d}>\n", .{browser_name.len});
    try stderr.flush();
}

fn serviceName(allocator: std.mem.Allocator, account: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s} Safe Storage", .{account});
}

fn canonicalBrowserName(browser_name: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(browser_name, "chrome")) return "Chrome";
    if (std.ascii.eqlIgnoreCase(browser_name, "chromium")) return "Chromium";
    if (std.ascii.eqlIgnoreCase(browser_name, "brave")) return "Brave";
    if (std.ascii.eqlIgnoreCase(browser_name, "edge")) return "Edge";
    if (std.ascii.eqlIgnoreCase(browser_name, "vivaldi")) return "Vivaldi";
    if (std.ascii.eqlIgnoreCase(browser_name, "opera")) return "Opera";
    if (std.ascii.eqlIgnoreCase(browser_name, "arc")) return "Arc";
    return browser_name;
}

extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern fn unsetenv(name: [*:0]const u8) c_int;

fn setTestEnv(comptime name: [:0]const u8, comptime value: [:0]const u8) void {
    if (setenv(name, value, 1) != 0) unreachable;
}

fn unsetTestEnv(comptime name: [:0]const u8) void {
    _ = unsetenv(name);
}

test "env var bypass returns supplied Chromium key" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    setTestEnv("SWEETCOOKIE_TEST_CHROMIUM_KEY", "001122aaff");
    defer unsetTestEnv("SWEETCOOKIE_TEST_CHROMIUM_KEY");
    unsetTestEnv("SWEETCOOKIE_FORCE_NATIVE_SECRET_FAIL");

    const key = try getStorageKey(std.testing.allocator, "chrome");
    defer std.testing.allocator.free(key);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x11, 0x22, 0xaa, 0xff }, key);
}

test "force native fail falls back to security shim" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    unsetTestEnv("SWEETCOOKIE_TEST_CHROMIUM_KEY");
    setTestEnv("SWEETCOOKIE_FORCE_NATIVE_SECRET_FAIL", "1");
    defer unsetTestEnv("SWEETCOOKIE_FORCE_NATIVE_SECRET_FAIL");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{
        .sub_path = "security",
        .data =
        \\#!/bin/sh
        \\printf 'shim-key\n'
        \\
        ,
    });
    const shim = try tmp.dir.openFile("security", .{});
    defer shim.close();
    try shim.chmod(0o755);
    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const old_path_owned = std.process.getEnvVarOwned(std.testing.allocator, "PATH") catch null;
    defer if (old_path_owned) |p| std.testing.allocator.free(p);
    const old_path = old_path_owned orelse "";
    const old_path_z = if (old_path_owned) |_| try std.testing.allocator.dupeZ(u8, old_path) else null;
    defer if (old_path_z) |p| std.testing.allocator.free(p);
    defer {
        if (old_path_z) |p| {
            if (setenv("PATH", p, 1) != 0) unreachable;
        } else {
            _ = unsetenv("PATH");
        }
    }
    const formatted_path = try std.fmt.allocPrint(std.testing.allocator, "{s}:{s}", .{ tmp_path, old_path });
    defer std.testing.allocator.free(formatted_path);
    const new_path = try std.testing.allocator.dupeZ(u8, formatted_path);
    defer std.testing.allocator.free(new_path);
    if (setenv("PATH", new_path, 1) != 0) unreachable;

    const key = try getStorageKey(std.testing.allocator, "chrome");
    defer std.testing.allocator.free(key);

    try std.testing.expectEqualStrings("shim-key", key);
}

test "env var bypass does not spawn security from PATH" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    setTestEnv("SWEETCOOKIE_TEST_CHROMIUM_KEY", "abcd");
    defer unsetTestEnv("SWEETCOOKIE_TEST_CHROMIUM_KEY");
    setTestEnv("SWEETCOOKIE_FORCE_NATIVE_SECRET_FAIL", "1");
    defer unsetTestEnv("SWEETCOOKIE_FORCE_NATIVE_SECRET_FAIL");

    const key = try getStorageKey(std.testing.allocator, "chrome");
    defer std.testing.allocator.free(key);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0xcd }, key);
}
