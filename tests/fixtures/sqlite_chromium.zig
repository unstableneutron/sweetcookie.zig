const std = @import("std");
const meta = @import("sqlite_chromium_meta.zig");
const firefox = @import("sqlite_firefox.zig");

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    host: []const u8,
    path: []const u8,
    expiry: i64,
    secure: bool = false,
    httponly: bool = false,
    samesite: i64 = -1,
    encrypted_value: ?[]const u8 = null,
    has_expires: bool = true,
    meta_version: ?i64 = null,
};

pub fn build(allocator: std.mem.Allocator, db_path: []const u8, entries: []const Cookie) !void {
    deleteIfExists(db_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    var sql = std.ArrayList(u8).empty;
    defer sql.deinit(allocator);
    const writer = sql.writer(allocator);
    try writer.writeAll(
        \\PRAGMA journal_mode=DELETE;
        \\CREATE TABLE cookies(
        \\  creation_utc INTEGER NOT NULL DEFAULT 0,
        \\  host_key TEXT NOT NULL,
        \\  top_frame_site_key TEXT NOT NULL DEFAULT '',
        \\  name TEXT NOT NULL,
        \\  value TEXT NOT NULL,
        \\  encrypted_value BLOB NOT NULL,
        \\  path TEXT NOT NULL,
        \\  expires_utc INTEGER NOT NULL,
        \\  is_secure INTEGER NOT NULL,
        \\  is_httponly INTEGER NOT NULL,
        \\  last_access_utc INTEGER NOT NULL DEFAULT 0,
        \\  has_expires INTEGER NOT NULL DEFAULT 1,
        \\  is_persistent INTEGER NOT NULL DEFAULT 1,
        \\  priority INTEGER NOT NULL DEFAULT 1,
        \\  samesite INTEGER NOT NULL DEFAULT -1,
        \\  source_scheme INTEGER NOT NULL DEFAULT 0,
        \\  source_port INTEGER NOT NULL DEFAULT -1,
        \\  is_same_party INTEGER NOT NULL DEFAULT 0,
        \\  last_update_utc INTEGER NOT NULL DEFAULT 0
        \\);
        \\CREATE TABLE meta(
        \\  key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY,
        \\  value LONGVARCHAR
        \\);
        \\BEGIN;
        \\
    );

    var meta_version: ?i64 = null;
    for (entries, 0..) |entry, i| {
        if (entry.meta_version) |version| meta_version = version;
        try writer.print("INSERT INTO cookies(rowid, creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, is_same_party, last_update_utc) VALUES({d}, 0, ", .{i + 1});
        try firefox.writeSqlString(writer, entry.host);
        try writer.writeAll(", '', ");
        try firefox.writeSqlString(writer, entry.name);
        try writer.writeAll(", ");
        try firefox.writeSqlString(writer, entry.value);
        try writer.writeAll(", ");
        try writeSqlBlob(writer, entry.encrypted_value);
        try writer.writeAll(", ");
        try firefox.writeSqlString(writer, entry.path);
        try writer.print(", {d}, {d}, {d}, 0, {d}, {d}, 1, {d}, 0, -1, 0, 0);\n", .{
            entry.expiry,
            @intFromBool(entry.secure),
            @intFromBool(entry.httponly),
            @intFromBool(entry.has_expires),
            @intFromBool(entry.has_expires),
            entry.samesite,
        });
    }
    try writer.writeAll("COMMIT;\n");
    if (meta_version) |version| {
        try writer.print("INSERT OR REPLACE INTO meta(key, value) VALUES('version', '{d}');\n", .{version});
    }
    try writer.writeAll("VACUUM;\n");
    try meta.runSqlite(allocator, db_path, sql.items);
}

fn deleteIfExists(path: []const u8) !void {
    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
}

fn writeSqlBlob(writer: anytype, value: ?[]const u8) !void {
    const bytes = value orelse "";
    try writer.writeAll("X'");
    const alphabet = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 0x0f]);
    }
    try writer.writeByte('\'');
}
