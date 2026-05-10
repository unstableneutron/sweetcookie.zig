const std = @import("std");

pub const Error = error{
    SqliteCliFailed,
} || std.mem.Allocator.Error || std.process.Child.RunError || std.fs.Dir.DeleteFileError || std.fs.File.OpenError || std.fs.File.WriteError;

pub fn writeVersion(allocator: std.mem.Allocator, db_path: []const u8, version: i64) Error!void {
    var sql = std.ArrayList(u8).empty;
    defer sql.deinit(allocator);
    try sql.writer(allocator).print(
        \\CREATE TABLE IF NOT EXISTS meta(
        \\  key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY,
        \\  value LONGVARCHAR
        \\);
        \\INSERT OR REPLACE INTO meta(key, value) VALUES('version', '{d}');
        \\
    , .{version});
    try runSqlite(allocator, db_path, sql.items);
}

pub fn runSqlite(allocator: std.mem.Allocator, db_path: []const u8, sql: []const u8) Error!void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "sqlite3", "-batch", db_path, sql },
        .max_output_bytes = 1024 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .Exited or result.term.Exited != 0) return error.SqliteCliFailed;
}
