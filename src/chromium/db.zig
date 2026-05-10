const std = @import("std");
const builtin = @import("builtin");
const sqlite = @import("../util/sqlite.zig");
const time = @import("../util/time.zig");
const CookieMod = @import("../Cookie.zig");
const Cookie = CookieMod.Cookie;
const Browser = CookieMod.Browser;
const SameSite = CookieMod.SameSite;
const Warning = @import("../Result.zig").Warning;
const crypto = @import("crypto.zig");
const secret_macos = @import("secret_macos.zig");
const secret_linux = @import("secret_linux.zig");
const secret_windows = @import("secret_windows.zig");

const select_cookies =
    \\SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, samesite
    \\FROM cookies
    \\ORDER BY rowid
;

pub fn readCookies(
    allocator: std.mem.Allocator,
    db_path: []const u8,
    browser: Browser,
    profile: ?[]const u8,
    warnings: *std.ArrayList(Warning),
) ![]Cookie {
    var db = try sqlite.Db.openReadOnly(db_path);
    defer db.close();
    const meta_version = readMetaVersion(&db) catch 0;
    var stmt = try db.prepare(select_cookies);
    defer stmt.finalize();

    var cookies = std.ArrayList(Cookie).empty;
    errdefer {
        for (cookies.items) |cookie| cookie.deinit(allocator);
        cookies.deinit(allocator);
    }

    var storage_key: ?[]u8 = null;
    defer if (storage_key) |key| allocator.free(key);

    while (try stmt.step()) {
        const host = stmt.columnText(0) orelse "";
        const name = stmt.columnText(1) orelse "";
        const plain_value = stmt.columnText(2) orelse "";
        const encrypted = stmt.columnBlob(3);
        const path = stmt.columnText(4) orelse "/";
        const expires_utc = stmt.columnInt64(5);
        const secure = stmt.columnInt64(6) != 0;
        const http_only = stmt.columnInt64(7) != 0;
        const has_expires = stmt.columnInt64(8) != 0;
        const same_site = chromiumSameSite(stmt.columnInt64(9));
        const value = try valueForRow(allocator, encrypted, plain_value, host, meta_version, browser, &storage_key, warnings) orelse continue;
        defer allocator.free(value);
        try cookies.append(allocator, try Cookie.fromRawDomain(
            allocator,
            host,
            name,
            value,
            path,
            if (has_expires) time.chromiumMicrosToUnix(expires_utc) else null,
            secure,
            http_only,
            same_site,
            .{ .browser = browser, .profile = profile },
        ));
    }

    return cookies.toOwnedSlice(allocator);
}

pub fn chromiumSameSite(value: i64) ?SameSite {
    return switch (value) {
        0 => .None,
        1 => .Lax,
        2 => .Strict,
        else => null,
    };
}

fn readMetaVersion(db: *sqlite.Db) !i64 {
    var stmt = try db.prepare("SELECT value FROM meta WHERE key = 'version' LIMIT 1");
    defer stmt.finalize();
    if (!try stmt.step()) return 0;
    if (stmt.columnText(0)) |text| return std.fmt.parseInt(i64, text, 10) catch 0;
    return stmt.columnInt64(0);
}

fn valueForRow(
    allocator: std.mem.Allocator,
    encrypted: ?[]const u8,
    plain_value: []const u8,
    host: []const u8,
    meta_version: i64,
    browser: Browser,
    storage_key: *?[]u8,
    warnings: *std.ArrayList(Warning),
) !?[]u8 {
    const encrypted_value = encrypted orelse return try allocator.dupe(u8, plain_value);
    if (encrypted_value.len == 0) return try allocator.dupe(u8, plain_value);
    if (storage_key.* == null) storage_key.* = try getStorageKey(allocator, browser);
    const decrypted = decryptChromiumValue(allocator, encrypted_value, storage_key.*.?, host, meta_version) catch |err| {
        try appendDecryptWarning(allocator, warnings, err);
        return null;
    };
    return decrypted;
}

pub fn decryptChromiumValue(
    allocator: std.mem.Allocator,
    encrypted: []const u8,
    key: []const u8,
    host: []const u8,
    meta_version: i64,
) ![]u8 {
    _ = host;
    if (encrypted.len < 3) return error.InvalidCiphertextLength;
    const prefix = encrypted[0..3];
    if (!std.mem.eql(u8, prefix, "v10") and !std.mem.eql(u8, prefix, "v11")) return error.InvalidCiphertextLength;
    const payload = encrypted[3..];
    const plaintext = decryptPayload(allocator, key, payload) catch |err| return err;
    errdefer allocator.free(plaintext);
    const stripped = crypto.strip_hash_prefix(plaintext, meta_version);
    if (stripped.ptr == plaintext.ptr and stripped.len == plaintext.len) return plaintext;
    const out = try allocator.dupe(u8, stripped);
    allocator.free(plaintext);
    return out;
}

fn decryptPayload(allocator: std.mem.Allocator, key: []const u8, payload: []const u8) ![]u8 {
    if (key.len >= 32 and payload.len >= 28) {
        return decryptGcm(allocator, key, payload) catch |gcm_err| {
            if (payload.len % 16 == 0) {
                return decryptCbc(allocator, key, payload) catch return gcm_err;
            }
            return gcm_err;
        };
    }
    return decryptCbc(allocator, key, payload);
}

fn decryptCbc(allocator: std.mem.Allocator, key: []const u8, payload: []const u8) ![]u8 {
    if (key.len < 16) return error.InvalidKeyLength;
    return crypto.aes128_cbc_decrypt(allocator, key[0..16], &([_]u8{' '} ** 16), payload);
}

fn decryptGcm(allocator: std.mem.Allocator, key: []const u8, payload: []const u8) ![]u8 {
    if (payload.len < 28) return error.InvalidCiphertextLength;
    const nonce = payload[0..12];
    const ciphertext = payload[12 .. payload.len - 16];
    const tag = payload[payload.len - 16 ..];
    return crypto.aes256_gcm_decrypt(allocator, key[0..32], nonce, ciphertext, tag);
}

fn getStorageKey(allocator: std.mem.Allocator, browser: Browser) ![]u8 {
    return switch (builtin.os.tag) {
        .macos => secret_macos.getStorageKey(allocator, @tagName(browser)),
        .linux => secret_linux.getStorageKey(allocator, @tagName(browser)),
        .windows => secret_windows.getStorageKey(allocator, @tagName(browser)),
        else => error.UnsupportedPlatform,
    };
}

fn appendDecryptWarning(allocator: std.mem.Allocator, warnings: *std.ArrayList(Warning), err: anyerror) !void {
    try warnings.append(allocator, .{
        .kind = try allocator.dupe(u8, "chromium-decrypt"),
        .message = try std.fmt.allocPrint(allocator, "decrypt failed: {s}", .{@errorName(err)}),
    });
}

test "chromium sameSite values map to canonical enum" {
    try std.testing.expect(chromiumSameSite(-1) == null);
    try std.testing.expectEqual(SameSite.None, chromiumSameSite(0).?);
    try std.testing.expectEqual(SameSite.Lax, chromiumSameSite(1).?);
    try std.testing.expectEqual(SameSite.Strict, chromiumSameSite(2).?);
}
