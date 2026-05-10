const std = @import("std");

const chromium = @import("sqlite_chromium.zig");
const firefox = @import("sqlite_firefox.zig");
const chromium_meta = @import("sqlite_chromium_meta.zig");

fn runSqlite(allocator: std.mem.Allocator, db_path: []const u8, sql: []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "sqlite3", "-batch", "-noheader", db_path, sql },
        .max_output_bytes = 1024 * 1024,
    });
}

test "firefox fixture builder creates selectable moz_cookies rows" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "cookies.sqlite" });
    defer std.testing.allocator.free(db_path);

    try firefox.build(std.testing.allocator, db_path, &.{
        .{ .name = "sid", .value = "one", .host = ".example.com", .path = "/", .expiry = 2_000_000_000, .secure = true, .httponly = true, .samesite = 1 },
        .{ .name = "pref", .value = "two", .host = "example.com", .path = "/app", .expiry = 2_100_000_000, .secure = false, .httponly = false, .samesite = 2 },
    });

    const res = try runSqlite(std.testing.allocator, db_path, "SELECT name || '|' || value || '|' || host || '|' || path || '|' || expiry || '|' || isSecure || '|' || isHttpOnly || '|' || sameSite FROM moz_cookies ORDER BY id;");
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, res.term);
    try std.testing.expectEqualStrings("sid|one|.example.com|/|2000000000|1|1|1\npref|two|example.com|/app|2100000000|0|0|2\n", res.stdout);
}

test "chromium fixture builder creates selectable cookies rows and meta version" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "Cookies" });
    defer std.testing.allocator.free(db_path);

    try chromium.build(std.testing.allocator, db_path, &.{
        .{ .name = "sid", .value = "plain", .host = ".example.com", .path = "/", .expiry = 13_350_000_000_000_000, .secure = true, .httponly = true, .samesite = 1, .has_expires = true, .meta_version = 24 },
        .{ .name = "enc", .value = "", .host = "example.com", .path = "/app", .expiry = 0, .secure = false, .httponly = false, .samesite = -1, .encrypted_value = "v10ciphertext", .has_expires = false },
    });

    const rows = try runSqlite(std.testing.allocator, db_path, "SELECT name || '|' || value || '|' || host_key || '|' || path || '|' || expires_utc || '|' || is_secure || '|' || is_httponly || '|' || samesite || '|' || has_expires || '|' || hex(encrypted_value) FROM cookies ORDER BY rowid;");
    defer std.testing.allocator.free(rows.stdout);
    defer std.testing.allocator.free(rows.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, rows.term);
    try std.testing.expectEqualStrings("sid|plain|.example.com|/|13350000000000000|1|1|1|1|\nenc||example.com|/app|0|0|0|-1|0|76313063697068657274657874\n", rows.stdout);

    const meta = try runSqlite(std.testing.allocator, db_path, "SELECT key || '=' || value FROM meta ORDER BY key;");
    defer std.testing.allocator.free(meta.stdout);
    defer std.testing.allocator.free(meta.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, meta.term);
    try std.testing.expectEqualStrings("version=24\n", meta.stdout);
}

test "chromium meta helper writes configurable version" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "Cookies" });
    defer std.testing.allocator.free(db_path);

    try chromium_meta.writeVersion(std.testing.allocator, db_path, 23);
    try chromium_meta.writeVersion(std.testing.allocator, db_path, 24);

    const res = try runSqlite(std.testing.allocator, db_path, "SELECT key || '=' || value FROM meta ORDER BY key;");
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, res.term);
    try std.testing.expectEqualStrings("version=24\n", res.stdout);
}

test "fixture builders are deterministic for identical inputs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const firefox_a = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "a.sqlite" });
    defer std.testing.allocator.free(firefox_a);
    const firefox_b = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "b.sqlite" });
    defer std.testing.allocator.free(firefox_b);

    const entries = &.{firefox.Cookie{ .name = "sid", .value = "one", .host = ".example.com", .path = "/", .expiry = 2_000_000_000, .secure = true, .httponly = true, .samesite = 1 }};
    try firefox.build(std.testing.allocator, firefox_a, entries);
    try firefox.build(std.testing.allocator, firefox_b, entries);

    const a = try std.fs.cwd().readFileAlloc(std.testing.allocator, firefox_a, 1024 * 1024);
    defer std.testing.allocator.free(a);
    const b = try std.fs.cwd().readFileAlloc(std.testing.allocator, firefox_b, 1024 * 1024);
    defer std.testing.allocator.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
}
