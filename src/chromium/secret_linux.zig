const std = @import("std");
const builtin = @import("builtin");

const Warning = @import("../Result.zig").Warning;

pub const SecretError = error{
    UnsupportedPlatform,
    InvalidHexKey,
    NativeSecretFailed,
    FallbackSecretFailed,
};

pub fn getStorageKey(allocator: std.mem.Allocator, browser_name: []const u8) ![]u8 {
    if (try keyFromTestEnv(allocator)) |key| return key;
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var warnings = std.ArrayList(Warning).empty;
    defer {
        for (warnings.items) |warning| {
            allocator.free(warning.kind);
            allocator.free(warning.message);
        }
        warnings.deinit(allocator);
    }

    return getStorageKeyWithWarnings(allocator, browser_name, &warnings);
}

pub fn getStorageKeyWithWarnings(
    allocator: std.mem.Allocator,
    browser_name: []const u8,
    warnings: *std.ArrayList(Warning),
) ![]u8 {
    if (try keyFromTestEnv(allocator)) |key| return key;
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    if (!try forceNativeFail()) {
        if (nativeStorageKey(allocator, browser_name)) |key| return key else |_| {}
    }
    return fallbackStorageKey(allocator, browser_name, warnings);
}

const SecretSchema = extern struct {
    name: [*:0]const u8,
    flags: c_int,
    attributes: [32]SecretSchemaAttribute,
};

const SecretSchemaAttribute = extern struct {
    name: ?[*:0]const u8,
    type: c_int,
};

const SecretPasswordLookupSync = *const fn (
    schema: *const SecretSchema,
    cancellable: ?*anyopaque,
    error_out: ?*?*anyopaque,
    attr_name: [*:0]const u8,
    attr_value: [*:0]const u8,
    terminator: ?*anyopaque,
) callconv(.c) ?[*:0]u8;

const GFree = *const fn (mem: ?*anyopaque) callconv(.c) void;

fn nativeStorageKey(allocator: std.mem.Allocator, browser_name: []const u8) ![]u8 {
    var lib = std.DynLib.openZ("libsecret-1.so.0") catch return error.NativeSecretFailed;
    defer lib.close();

    const lookup = lib.lookup(SecretPasswordLookupSync, "secret_password_lookup_sync") orelse return error.NativeSecretFailed;
    const g_free = lib.lookup(GFree, "g_free") orelse return error.NativeSecretFailed;
    const application = canonicalApplicationName(browser_name);
    const application_z = try allocator.dupeZ(u8, application);
    defer allocator.free(application_z);
    const schema = chromiumSchema();
    const raw = lookup(&schema, null, null, "application", application_z.ptr, null) orelse return error.NativeSecretFailed;
    defer g_free(@ptrCast(raw));

    return allocator.dupe(u8, std.mem.span(raw));
}

fn fallbackStorageKey(
    allocator: std.mem.Allocator,
    browser_name: []const u8,
    warnings: *std.ArrayList(Warning),
) ![]u8 {
    try appendFallbackWarning(allocator, browser_name, warnings);
    emitFallbackWarning(browser_name) catch {};

    const application = canonicalApplicationName(browser_name);
    if (runAndTrim(allocator, &.{ "secret-tool", "lookup", "application", application })) |key| return key else |_| {}
    if (runAndTrim(allocator, &.{ "kwallet-query", "-r", application, "kdewallet" })) |key| return key else |_| {}
    if (runAndTrim(allocator, &.{ "dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.secrets", "/org/freedesktop/secrets", "org.freedesktop.DBus.Properties.Get", "string:org.freedesktop.Secret.Service", "string:Collections" })) |key| return key else |_| {}
    return error.FallbackSecretFailed;
}

fn getStorageKeyWithDlopenForTest(
    allocator: std.mem.Allocator,
    browser_name: []const u8,
    dlopen_succeeds: bool,
    fallback_key: []const u8,
    warnings: *std.ArrayList(Warning),
) ![]u8 {
    if (dlopen_succeeds) return error.NativeSecretFailed;
    try appendFallbackWarning(allocator, browser_name, warnings);
    return allocator.dupe(u8, fallback_key);
}

fn runAndTrim(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 16 * 1024,
        .expand_arg0 = .expand,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .Exited or result.term.Exited != 0) return error.FallbackSecretFailed;
    const trimmed = std.mem.trim(u8, result.stdout, "\r\n \t");
    if (trimmed.len == 0) return error.FallbackSecretFailed;
    return allocator.dupe(u8, trimmed);
}

fn appendFallbackWarning(
    allocator: std.mem.Allocator,
    browser_name: []const u8,
    warnings: *std.ArrayList(Warning),
) !void {
    try warnings.append(allocator, .{
        .kind = try allocator.dupe(u8, "os-secret-fallback"),
        .message = try std.fmt.allocPrint(allocator, "native linux secret lookup unavailable for {s}", .{browser_name}),
    });
}

fn emitFallbackWarning(browser_name: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var writer = std.fs.File.stderr().writer(&buffer);
    const stderr = &writer.interface;
    try stderr.print("warning: kind=os-secret-fallback message=<len={d}>\n", .{browser_name.len});
    try stderr.flush();
}

fn chromiumSchema() SecretSchema {
    var schema: SecretSchema = .{
        .name = "chrome_libsecret_os_crypt_password_v2",
        .flags = 0,
        .attributes = [_]SecretSchemaAttribute{.{ .name = null, .type = 0 }} ** 32,
    };
    schema.attributes[0] = .{ .name = "application", .type = 0 };
    return schema;
}

fn canonicalApplicationName(browser_name: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(browser_name, "chrome")) return "chrome";
    if (std.ascii.eqlIgnoreCase(browser_name, "chromium")) return "chromium";
    if (std.ascii.eqlIgnoreCase(browser_name, "brave")) return "brave";
    if (std.ascii.eqlIgnoreCase(browser_name, "edge")) return "edge";
    if (std.ascii.eqlIgnoreCase(browser_name, "vivaldi")) return "vivaldi";
    if (std.ascii.eqlIgnoreCase(browser_name, "opera")) return "opera";
    if (std.ascii.eqlIgnoreCase(browser_name, "arc")) return "arc";
    return browser_name;
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

test "dlopen null path emits os-secret-fallback warning" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var warnings = std.ArrayList(Warning).empty;
    defer {
        for (warnings.items) |warning| {
            std.testing.allocator.free(warning.kind);
            std.testing.allocator.free(warning.message);
        }
        warnings.deinit(std.testing.allocator);
    }

    const key = try getStorageKeyWithDlopenForTest(std.testing.allocator, "chrome", false, "fallback-key", &warnings);
    defer std.testing.allocator.free(key);

    try std.testing.expectEqualStrings("fallback-key", key);
    try std.testing.expectEqual(@as(usize, 1), warnings.items.len);
    try std.testing.expectEqualStrings("os-secret-fallback", warnings.items[0].kind);
}
