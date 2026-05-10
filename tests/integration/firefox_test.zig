const std = @import("std");

const exe = "zig-out/bin/sweetcookie";

const FirefoxCookie = struct {
    name: []const u8,
    value: []const u8,
    host: []const u8,
    path: []const u8,
    expiry: i64,
    secure: bool = false,
    httponly: bool = false,
    samesite: i64 = 0,
};

const FileState = struct {
    size: u64,
    mtime: i128,
    hash: [32]u8,
};

fn run(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    });
}

fn runWithTmp(allocator: std.mem.Allocator, argv: []const []const u8, tmpdir: []const u8) !std.process.Child.RunResult {
    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    try env.put("TMPDIR", tmpdir);
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .env_map = &env,
        .max_output_bytes = 1024 * 1024,
    });
}

fn expectExit0(res: std.process.Child.RunResult) !void {
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), res.term.Exited);
}

fn tmpPath(tmp: *std.testing.TmpDir, parts: []const []const u8) ![]u8 {
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    var list = std.ArrayList([]const u8).empty;
    defer list.deinit(std.testing.allocator);
    try list.append(std.testing.allocator, root);
    for (parts) |part| try list.append(std.testing.allocator, part);
    return std.fs.path.join(std.testing.allocator, list.items);
}

fn buildDb(tmp: *std.testing.TmpDir, entries: []const FirefoxCookie) ![]u8 {
    const db_path = try tmpPath(tmp, &.{"cookies.sqlite"});
    try buildFirefoxDb(db_path, entries);
    return db_path;
}

fn buildProfileRoot(tmp: *std.testing.TmpDir, entries: []const FirefoxCookie) !struct { root: []u8, db: []u8 } {
    try tmp.dir.makePath("Profiles/default");
    try tmp.dir.writeFile(.{
        .sub_path = "profiles.ini",
        .data =
        \\[Profile0]
        \\Name=default
        \\IsRelative=1
        \\Path=Profiles/default
        \\Default=1
        \\
        ,
    });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ root, "Profiles", "default", "cookies.sqlite" });
    try buildFirefoxDb(db_path, entries);
    return .{ .root = root, .db = db_path };
}

fn buildFirefoxDb(db_path: []const u8, entries: []const FirefoxCookie) !void {
    var sql = std.ArrayList(u8).empty;
    defer sql.deinit(std.testing.allocator);
    const writer = sql.writer(std.testing.allocator);
    try writer.writeAll(
        \\PRAGMA journal_mode=DELETE;
        \\CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0);
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
        try writer.print(", {d}, 0, 0, {d}, {d}, 0, {d}, {d}, 0);\n", .{ entry.expiry, @intFromBool(entry.secure), @intFromBool(entry.httponly), entry.samesite, entry.samesite });
    }
    try writer.writeAll("COMMIT;\nVACUUM;\n");
    const res = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "sqlite3", "-batch", db_path, sql.items },
        .max_output_bytes = 1024 * 1024,
    });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, res.term);
}

fn writeSqlString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('\'');
    for (value) |ch| {
        if (ch == '\'') try writer.writeByte('\'');
        try writer.writeByte(ch);
    }
    try writer.writeByte('\'');
}

fn parseJson(stdout: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, std.testing.allocator, stdout, .{});
}

fn cookieAt(value: std.json.Value, idx: usize) std.json.Value {
    return value.array.items[idx];
}

fn fileState(path: []const u8) !FileState {
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    const stat = try file.stat();
    const bytes = try file.readToEndAlloc(std.testing.allocator, 16 * 1024 * 1024);
    defer std.testing.allocator.free(bytes);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return .{ .size = stat.size, .mtime = stat.mtime, .hash = hash };
}

fn expectUnchanged(path: []const u8, before: FileState) !void {
    const after = try fileState(path);
    try std.testing.expectEqual(before.size, after.size);
    try std.testing.expectEqual(before.mtime, after.mtime);
    try std.testing.expectEqualSlices(u8, &before.hash, &after.hash);
}

fn expectNoSnapshots(tmpdir: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(tmpdir, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        try std.testing.expect(!std.mem.startsWith(u8, entry.name, "sweetcookie-snapshot-"));
    }
}

test "firefox explicit cookies file maps rows, sameSite values, and domain semantics" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try buildDb(&tmp, &.{
        .{ .name = "none", .value = "0", .host = ".example.com", .path = "/", .expiry = 2_000_000_000, .secure = true, .httponly = true, .samesite = 0 },
        .{ .name = "lax", .value = "1", .host = "example.com", .path = "/a", .expiry = 2_000_000_001, .samesite = 1 },
        .{ .name = "strict", .value = "2", .host = ".example.org", .path = "/", .expiry = 2_000_000_002, .samesite = 2 },
        .{ .name = "unset", .value = "3", .host = "example.net", .path = "/", .expiry = 2_000_000_003, .samesite = 3 },
    });
    defer std.testing.allocator.free(db_path);

    const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-cookies-file", db_path, "--format", "sweet-cookie-json" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);

    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    const cookies = parsed.value.object.get("cookies").?.array.items;
    try std.testing.expectEqual(@as(usize, 4), cookies.len);
    try std.testing.expectEqualStrings("lax", cookies[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("example.com", cookies[0].object.get("raw_domain").?.string);
    try std.testing.expect(cookies[0].object.get("host_only").?.bool);
    try std.testing.expectEqualStrings("Lax", cookies[0].object.get("sameSite").?.string);
    try std.testing.expectEqualStrings("none", cookies[1].object.get("name").?.string);
    try std.testing.expectEqualStrings(".example.com", cookies[1].object.get("raw_domain").?.string);
    try std.testing.expect(!cookies[1].object.get("host_only").?.bool);
    try std.testing.expectEqualStrings("example.com", cookies[1].object.get("domain").?.string);
    try std.testing.expectEqualStrings("None", cookies[1].object.get("sameSite").?.string);
    try std.testing.expectEqualStrings("Strict", cookies[2].object.get("sameSite").?.string);
    try std.testing.expect(cookies[3].object.get("sameSite").? == .null);
    try std.testing.expect(cookies[1].object.get("secure").?.bool);
    try std.testing.expect(cookies[1].object.get("httpOnly").?.bool);
}

test "firefox empty database produces empty array" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try buildDb(&tmp, &.{});
    defer std.testing.allocator.free(db_path);

    const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-cookies-file", db_path });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 0), parsed.value.array.items.len);
}

test "firefox corrupt database errors clearly and leaves source unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "cookies.sqlite", .data = "not a database" });
    const db_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cookies.sqlite");
    defer std.testing.allocator.free(db_path);
    const before = try fileState(db_path);
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);

    const res = try runWithTmp(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-cookies-file", db_path }, tmp_root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 1), res.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "not a database") != null);
    try expectUnchanged(db_path, before);
    try expectNoSnapshots(tmp_root);
}

test "firefox profile root discovery plus url and name filters" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const profile = try buildProfileRoot(&tmp, &.{
        .{ .name = "sid", .value = "keep", .host = ".example.com", .path = "/app", .expiry = 2_000_000_000 },
        .{ .name = "sid", .value = "wrong-path", .host = ".example.com", .path = "/other", .expiry = 2_000_000_000 },
        .{ .name = "other", .value = "wrong-name", .host = ".example.com", .path = "/app", .expiry = 2_000_000_000 },
    });
    defer std.testing.allocator.free(profile.root);
    defer std.testing.allocator.free(profile.db);

    const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-profile-root", profile.root, "--url", "https://www.example.com/app/page", "--name", "sid" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try std.testing.expectEqualStrings("keep", cookieAt(parsed.value, 0).object.get("value").?.string);
}

test "firefox source database and sidecars unchanged and snapshot cleaned on success" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try buildDb(&tmp, &.{.{ .name = "sid", .value = "one", .host = ".example.com", .path = "/", .expiry = 2_000_000_000 }});
    defer std.testing.allocator.free(db_path);
    const wal = try std.fmt.allocPrint(std.testing.allocator, "{s}-wal", .{db_path});
    defer std.testing.allocator.free(wal);
    const shm = try std.fmt.allocPrint(std.testing.allocator, "{s}-shm", .{db_path});
    defer std.testing.allocator.free(shm);
    try std.fs.cwd().writeFile(.{ .sub_path = wal, .data = "wal sidecar" });
    try std.fs.cwd().writeFile(.{ .sub_path = shm, .data = "shm sidecar" });
    const before_db = try fileState(db_path);
    const before_wal = try fileState(wal);
    const before_shm = try fileState(shm);
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);

    const res = try runWithTmp(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-cookies-file", db_path }, tmp_root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try expectUnchanged(db_path, before_db);
    try expectUnchanged(wal, before_wal);
    try expectUnchanged(shm, before_shm);
    try expectNoSnapshots(tmp_root);
}

test "firefox wal-only committed data is visible through snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmpPath(&tmp, &.{"cookies.sqlite"});
    defer std.testing.allocator.free(db_path);
    var child = std.process.Child.init(&.{ "sqlite3", db_path }, std.testing.allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    try child.stdin.?.writeAll(
        \\PRAGMA journal_mode=WAL;
        \\PRAGMA wal_autocheckpoint=0;
        \\CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0);
        \\INSERT INTO moz_cookies(name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly,sameSite) VALUES('wal','visible','.example.com','/',2000000000,0,0,0,0,1);
        \\
    );

    const wal = try std.fmt.allocPrint(std.testing.allocator, "{s}-wal", .{db_path});
    defer std.testing.allocator.free(wal);
    const shm = try std.fmt.allocPrint(std.testing.allocator, "{s}-shm", .{db_path});
    defer std.testing.allocator.free(shm);
    var attempts: usize = 0;
    while (attempts < 20 and !exists(wal)) : (attempts += 1) std.Thread.sleep(10 * std.time.ns_per_ms);
    try std.testing.expect(exists(wal));
    try std.testing.expect(exists(shm));

    const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-cookies-file", db_path });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try std.testing.expectEqualStrings("wal", cookieAt(parsed.value, 0).object.get("name").?.string);

    try child.stdin.?.writeAll(".quit\n");
    child.stdin.?.close();
    child.stdin = null;
    const stderr = try child.stderr.?.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(stderr);
    const term = try child.wait();
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, term);
}

test "firefox two parallel cli runs both succeed without source corruption" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try buildDb(&tmp, &.{.{ .name = "sid", .value = "one", .host = ".example.com", .path = "/", .expiry = 2_000_000_000 }});
    defer std.testing.allocator.free(db_path);
    const before = try fileState(db_path);

    var one = std.process.Child.init(&.{ exe, "export", "--browser", "firefox", "--firefox-cookies-file", db_path }, std.testing.allocator);
    var two = std.process.Child.init(&.{ exe, "export", "--browser", "firefox", "--firefox-cookies-file", db_path }, std.testing.allocator);
    one.stdout_behavior = .Pipe;
    one.stderr_behavior = .Pipe;
    two.stdout_behavior = .Pipe;
    two.stderr_behavior = .Pipe;
    try one.spawn();
    try two.spawn();
    const one_out = try one.stdout.?.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(one_out);
    const one_err = try one.stderr.?.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(one_err);
    const two_out = try two.stdout.?.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(two_out);
    const two_err = try two.stderr.?.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(two_err);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, try one.wait());
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, try two.wait());
    try expectUnchanged(db_path, before);
    try std.testing.expect(std.mem.indexOf(u8, one_out, "sid") != null);
    try std.testing.expect(std.mem.indexOf(u8, two_out, "sid") != null);
}

fn exists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}
