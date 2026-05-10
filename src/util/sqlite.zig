const std = @import("std");

const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const Error = error{
    Busy,
    CannotOpen,
    Constraint,
    Corrupt,
    Internal,
    InvalidColumn,
    InvalidPath,
    Io,
    Misuse,
    NoMemory,
    NotADatabase,
    PermissionDenied,
    Range,
    RowExpected,
    Schema,
    SqlError,
    TooBig,
    Unknown,
};

pub const Db = struct {
    handle: ?*c.sqlite3,

    pub fn openReadOnly(path: []const u8) Error!Db {
        var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        if (path.len >= std.fs.max_path_bytes) return error.InvalidPath;
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;

        var handle: ?*c.sqlite3 = null;
        const flags = c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX;
        const rc = c.sqlite3_open_v2(&path_buf, &handle, flags, null);
        if (rc != c.SQLITE_OK) {
            if (handle) |db| _ = c.sqlite3_close_v2(db);
            return mapResult(rc);
        }

        var db = Db{ .handle = handle };
        errdefer db.close();
        try db.verifyDatabase();
        return db;
    }

    pub fn close(self: *Db) void {
        const db = self.handle orelse return;
        while (c.sqlite3_next_stmt(db, null)) |stmt| {
            _ = c.sqlite3_finalize(stmt);
        }
        _ = c.sqlite3_close_v2(db);
        self.handle = null;
    }

    pub fn prepare(self: *Db, sql: []const u8) Error!Stmt {
        const db = self.handle orelse return error.Misuse;
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(db, sql.ptr, @intCast(sql.len), &stmt, null);
        if (rc != c.SQLITE_OK) return mapResult(rc);
        return .{ .handle = stmt };
    }

    fn verifyDatabase(self: *Db) Error!void {
        var stmt = try self.prepare("PRAGMA schema_version");
        defer stmt.finalize();
        _ = try stmt.step();
    }
};

pub const Stmt = struct {
    handle: ?*c.sqlite3_stmt,

    pub fn step(self: *Stmt) Error!bool {
        const stmt = self.handle orelse return error.Misuse;
        const rc = c.sqlite3_step(stmt);
        return switch (rc) {
            c.SQLITE_ROW => true,
            c.SQLITE_DONE => false,
            else => mapResult(rc),
        };
    }

    pub fn columnText(self: *Stmt, i: i32) ?[]const u8 {
        const stmt = self.handle orelse return null;
        if (!validColumn(stmt, i)) return null;
        const ptr = c.sqlite3_column_text(stmt, i) orelse return null;
        const len: usize = @intCast(c.sqlite3_column_bytes(stmt, i));
        return @as([*]const u8, @ptrCast(ptr))[0..len];
    }

    pub fn columnInt64(self: *Stmt, i: i32) i64 {
        const stmt = self.handle orelse return 0;
        if (!validColumn(stmt, i)) return 0;
        return @intCast(c.sqlite3_column_int64(stmt, i));
    }

    pub fn columnBlob(self: *Stmt, i: i32) ?[]const u8 {
        const stmt = self.handle orelse return null;
        if (!validColumn(stmt, i)) return null;
        if (c.sqlite3_column_type(stmt, i) == c.SQLITE_NULL) return null;
        const len: usize = @intCast(c.sqlite3_column_bytes(stmt, i));
        if (len == 0) return &.{};
        const ptr = c.sqlite3_column_blob(stmt, i) orelse return null;
        return @as([*]const u8, @ptrCast(ptr))[0..len];
    }

    pub fn finalize(self: *Stmt) void {
        const stmt = self.handle orelse return;
        _ = c.sqlite3_finalize(stmt);
        self.handle = null;
    }
};

fn validColumn(stmt: *c.sqlite3_stmt, i: i32) bool {
    return i >= 0 and i < c.sqlite3_column_count(stmt);
}

fn mapResult(rc: c_int) Error {
    return switch (rc & 0xff) {
        c.SQLITE_PERM, c.SQLITE_AUTH, c.SQLITE_READONLY => error.PermissionDenied,
        c.SQLITE_BUSY, c.SQLITE_LOCKED => error.Busy,
        c.SQLITE_NOMEM => error.NoMemory,
        c.SQLITE_IOERR => error.Io,
        c.SQLITE_CORRUPT => error.Corrupt,
        c.SQLITE_NOTFOUND => error.InvalidPath,
        c.SQLITE_CANTOPEN => error.CannotOpen,
        c.SQLITE_PROTOCOL, c.SQLITE_INTERNAL => error.Internal,
        c.SQLITE_SCHEMA => error.Schema,
        c.SQLITE_TOOBIG => error.TooBig,
        c.SQLITE_CONSTRAINT => error.Constraint,
        c.SQLITE_MISMATCH, c.SQLITE_MISUSE => error.Misuse,
        c.SQLITE_RANGE => error.Range,
        c.SQLITE_NOTADB => error.NotADatabase,
        c.SQLITE_ERROR => error.SqlError,
        else => error.Unknown,
    };
}

fn createSqliteDb(path: []const u8, sql: []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "sqlite3", path, sql },
        .max_output_bytes = 1024 * 1024,
    });
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, result.term);
}

test "openReadOnly prepares and steps typed SELECT columns" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "cookies.sqlite" });
    defer std.testing.allocator.free(db_path);
    try createSqliteDb(db_path, "CREATE TABLE t(name TEXT, count INTEGER, payload BLOB); INSERT INTO t VALUES('sid', 42, X'0102ff');");

    var db = try Db.openReadOnly(db_path);
    defer db.close();
    var stmt = try db.prepare("SELECT name, count, payload FROM t");
    defer stmt.finalize();

    try std.testing.expect(try stmt.step());
    try std.testing.expectEqualStrings("sid", stmt.columnText(0).?);
    try std.testing.expectEqual(@as(i64, 42), stmt.columnInt64(1));
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0xff }, stmt.columnBlob(2).?);
    try std.testing.expect(!try stmt.step());
}

test "columnBlob distinguishes SQL NULL from zero-length BLOB" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "nullable-blob.sqlite" });
    defer std.testing.allocator.free(db_path);
    try createSqliteDb(db_path, "CREATE TABLE t(id INTEGER, payload BLOB); INSERT INTO t VALUES(1, NULL), (2, X'');");

    var db = try Db.openReadOnly(db_path);
    defer db.close();
    var stmt = try db.prepare("SELECT payload FROM t ORDER BY id");
    defer stmt.finalize();

    try std.testing.expect(try stmt.step());
    try std.testing.expect(stmt.columnBlob(0) == null);
    try std.testing.expect(try stmt.step());
    const empty_blob = stmt.columnBlob(0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), empty_blob.len);
    try std.testing.expect(!try stmt.step());
}

test "openReadOnly rejects a non database file with a structured error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "not.sqlite", .data = "not a sqlite database" });
    const db_path = try tmp.dir.realpathAlloc(std.testing.allocator, "not.sqlite");
    defer std.testing.allocator.free(db_path);

    try std.testing.expectError(error.NotADatabase, Db.openReadOnly(db_path));
}

test "close succeeds when prepared statements are not explicitly finalized" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_root, "close.sqlite" });
    defer std.testing.allocator.free(db_path);
    try createSqliteDb(db_path, "CREATE TABLE t(value INTEGER); INSERT INTO t VALUES(7);");

    var db = try Db.openReadOnly(db_path);
    _ = try db.prepare("SELECT value FROM t");
    db.close();

    var reopened = try Db.openReadOnly(db_path);
    defer reopened.close();
    var stmt = try reopened.prepare("SELECT value FROM t");
    defer stmt.finalize();
    try std.testing.expect(try stmt.step());
    try std.testing.expectEqual(@as(i64, 7), stmt.columnInt64(0));
}
