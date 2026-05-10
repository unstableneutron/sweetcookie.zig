const std = @import("std");
const meta = @import("sqlite_chromium_meta.zig");

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    host: []const u8,
    path: []const u8,
    expiry: i64,
    secure: bool = false,
    httponly: bool = false,
    samesite: i64 = 0,
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
        \\CREATE TABLE moz_cookies(
        \\  id INTEGER PRIMARY KEY,
        \\  originAttributes TEXT NOT NULL DEFAULT '',
        \\  name TEXT,
        \\  value TEXT,
        \\  host TEXT,
        \\  path TEXT,
        \\  expiry INTEGER,
        \\  lastAccessed INTEGER,
        \\  creationTime INTEGER,
        \\  isSecure INTEGER,
        \\  isHttpOnly INTEGER,
        \\  inBrowserElement INTEGER DEFAULT 0,
        \\  sameSite INTEGER DEFAULT 0,
        \\  rawSameSite INTEGER DEFAULT 0,
        \\  schemeMap INTEGER DEFAULT 0
        \\);
        \\BEGIN;
        \\
    );

    for (entries, 0..) |entry, i| {
        try writer.print("INSERT INTO moz_cookies(id, originAttributes, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, inBrowserElement, sameSite, rawSameSite, schemeMap) VALUES({d}, '', ", .{i + 1});
        try writeSqlString(writer, entry.name);
        try writer.writeAll(", ");
        try writeSqlString(writer, entry.value);
        try writer.writeAll(", ");
        try writeSqlString(writer, entry.host);
        try writer.writeAll(", ");
        try writeSqlString(writer, entry.path);
        try writer.print(", {d}, 0, 0, {d}, {d}, 0, {d}, {d}, 0);\n", .{
            entry.expiry,
            @intFromBool(entry.secure),
            @intFromBool(entry.httponly),
            entry.samesite,
            entry.samesite,
        });
    }

    try writer.writeAll("COMMIT;\nVACUUM;\n");
    try meta.runSqlite(allocator, db_path, sql.items);
}

fn deleteIfExists(path: []const u8) !void {
    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
}

pub fn writeSqlString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('\'');
    for (value) |ch| {
        if (ch == '\'') try writer.writeByte('\'');
        try writer.writeByte(ch);
    }
    try writer.writeByte('\'');
}
