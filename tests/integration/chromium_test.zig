const std = @import("std");

const exe = "zig-out/bin/sweetcookie";

const FileState = struct {
    size: u64,
    mtime: i128,
    hash: [32]u8,
};

fn run(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.RunResult {
    return runEnv(allocator, argv, null, null);
}

fn runEnv(allocator: std.mem.Allocator, argv: []const []const u8, tmpdir: ?[]const u8, key_hex: ?[]const u8) !std.process.Child.RunResult {
    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    if (tmpdir) |dir| try env.put("TMPDIR", dir);
    if (key_hex) |key| try env.put("SWEETCOOKIE_TEST_CHROMIUM_KEY", key);
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

fn parseJson(stdout: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, std.testing.allocator, stdout, .{});
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

fn buildDb(db_path: []const u8, meta_version: i64, entries: []const ChromiumCookie) !void {
    var sql = std.ArrayList(u8).empty;
    defer sql.deinit(std.testing.allocator);
    const writer = sql.writer(std.testing.allocator);
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
        \\CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
    );
    try writer.print("INSERT INTO meta(key, value) VALUES('version', '{d}');\nBEGIN;\n", .{meta_version});
    for (entries, 0..) |entry, i| {
        try writer.print("INSERT INTO cookies(rowid, host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, is_persistent, samesite) VALUES({d}, ", .{i + 1});
        try sqlString(writer, entry.host);
        try writer.writeAll(", ");
        try sqlString(writer, entry.name);
        try writer.writeAll(", ");
        try sqlString(writer, entry.value);
        try writer.writeAll(", ");
        try sqlBlob(writer, entry.encrypted_value);
        try writer.writeAll(", ");
        try sqlString(writer, entry.path);
        try writer.print(", {d}, {d}, {d}, {d}, {d}, {d});\n", .{
            entry.expires_utc,
            @intFromBool(entry.secure),
            @intFromBool(entry.httponly),
            @intFromBool(entry.has_expires),
            @intFromBool(entry.has_expires),
            entry.samesite,
        });
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

const ChromiumCookie = struct {
    name: []const u8,
    value: []const u8 = "",
    encrypted_value: []const u8 = "",
    host: []const u8,
    path: []const u8,
    expires_utc: i64,
    secure: bool = false,
    httponly: bool = false,
    has_expires: bool = true,
    samesite: i64 = -1,
};

fn sqlString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('\'');
    for (value) |ch| {
        if (ch == '\'') try writer.writeByte('\'');
        try writer.writeByte(ch);
    }
    try writer.writeByte('\'');
}

fn sqlBlob(writer: anytype, bytes: []const u8) !void {
    try writer.writeAll("X'");
    const alphabet = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 0x0f]);
    }
    try writer.writeByte('\'');
}

fn cbcBlob(allocator: std.mem.Allocator, prefix: []const u8, key: []const u8, plaintext: []const u8) ![]u8 {
    const padded_len = ((plaintext.len / 16) + 1) * 16;
    var padded = try allocator.alloc(u8, padded_len);
    defer allocator.free(padded);
    @memcpy(padded[0..plaintext.len], plaintext);
    @memset(padded[plaintext.len..], @intCast(padded_len - plaintext.len));
    const out = try allocator.alloc(u8, prefix.len + padded_len);
    errdefer allocator.free(out);
    @memcpy(out[0..prefix.len], prefix);
    var previous = [_]u8{' '} ** 16;
    const aes = std.crypto.core.aes.Aes128.initEnc(key[0..16].*);
    var offset: usize = 0;
    while (offset < padded.len) : (offset += 16) {
        var block: [16]u8 = undefined;
        @memcpy(&block, padded[offset..][0..16]);
        for (&block, previous) |*byte, prev| byte.* ^= prev;
        aes.encrypt(out[prefix.len + offset ..][0..16], &block);
        @memcpy(&previous, out[prefix.len + offset ..][0..16]);
    }
    return out;
}

fn gcmBlob(allocator: std.mem.Allocator, key: []const u8, plaintext: []const u8) ![]u8 {
    const Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    const nonce = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const out = try allocator.alloc(u8, 3 + nonce.len + plaintext.len + Gcm.tag_length);
    errdefer allocator.free(out);
    @memcpy(out[0..3], "v10");
    @memcpy(out[3..15], &nonce);
    var key_block: [Gcm.key_length]u8 = undefined;
    @memcpy(&key_block, key[0..Gcm.key_length]);
    var tag: [Gcm.tag_length]u8 = undefined;
    Gcm.encrypt(out[15 .. 15 + plaintext.len], &tag, plaintext, "", nonce, key_block);
    @memcpy(out[15 + plaintext.len ..], &tag);
    return out;
}

test "chromium explicit db maps plaintext rows and fields" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmpPath(&tmp, &.{"Cookies"});
    defer std.testing.allocator.free(db_path);
    try buildDb(db_path, 23, &.{
        .{ .name = "plain", .value = "plaintext", .host = ".example.com", .path = "/", .expires_utc = 13_350_000_000_000_000, .secure = true, .httponly = true, .samesite = 2 },
        .{ .name = "session", .value = "value", .host = "example.com", .path = "/app", .expires_utc = 0, .has_expires = false, .samesite = 0 },
    });

    const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", db_path, "--all-domains", "--include-expired", "--format", "sweet-cookie-json" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    const cookies = parsed.value.object.get("cookies").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), cookies.len);
    try std.testing.expectEqualStrings("plain", cookies[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("plaintext", cookies[0].object.get("value").?.string);
    try std.testing.expectEqual(@as(i64, 1_705_526_400), cookies[0].object.get("expires").?.integer);
    try std.testing.expect(cookies[0].object.get("secure").?.bool);
    try std.testing.expect(cookies[0].object.get("httpOnly").?.bool);
    try std.testing.expectEqualStrings("Strict", cookies[0].object.get("sameSite").?.string);
    try std.testing.expect(!cookies[0].object.get("host_only").?.bool);
    try std.testing.expectEqualStrings(".example.com", cookies[0].object.get("raw_domain").?.string);
    try std.testing.expectEqualStrings("session", cookies[1].object.get("name").?.string);
    try std.testing.expect(cookies[1].object.get("expires").? == .null);
    try std.testing.expect(cookies[1].object.get("host_only").?.bool);
    try std.testing.expectEqualStrings("None", cookies[1].object.get("sameSite").?.string);
}

test "chromium decrypts v10 cbc v11 cbc and v10 gcm with hash-prefix stripping" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmpPath(&tmp, &.{"Cookies"});
    defer std.testing.allocator.free(db_path);
    const key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var prefixed = [_]u8{'h'} ** 42;
    @memcpy(prefixed[32..], "real-value");
    const v10 = try cbcBlob(std.testing.allocator, "v10", &key, "decrypted-secret");
    defer std.testing.allocator.free(v10);
    const v11 = try cbcBlob(std.testing.allocator, "v11", &key, "v11-secret");
    defer std.testing.allocator.free(v11);
    const gcm = try gcmBlob(std.testing.allocator, &key, &prefixed);
    defer std.testing.allocator.free(gcm);
    try buildDb(db_path, 24, &.{
        .{ .name = "a", .encrypted_value = v10, .host = "example.com", .path = "/", .expires_utc = 13_350_000_000_000_000 },
        .{ .name = "b", .encrypted_value = v11, .host = "example.com", .path = "/", .expires_utc = 13_350_000_000_000_000 },
        .{ .name = "c", .encrypted_value = gcm, .host = "example.com", .path = "/", .expires_utc = 13_350_000_000_000_000 },
    });

    const res = try runEnv(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", db_path, "--all-domains", "--include-expired" }, null, key_hex);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("decrypted-secret", parsed.value.array.items[0].object.get("value").?.string);
    try std.testing.expectEqualStrings("v11-secret", parsed.value.array.items[1].object.get("value").?.string);
    try std.testing.expectEqualStrings("real-value", parsed.value.array.items[2].object.get("value").?.string);
}

test "chromium source db and sidecars unchanged and snapshots cleaned on success and failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmpPath(&tmp, &.{"Cookies"});
    defer std.testing.allocator.free(db_path);
    try buildDb(db_path, 23, &.{.{ .name = "plain", .value = "plaintext", .host = "example.com", .path = "/", .expires_utc = 13_350_000_000_000_000 }});
    const wal = try std.fmt.allocPrint(std.testing.allocator, "{s}-wal", .{db_path});
    defer std.testing.allocator.free(wal);
    const shm = try std.fmt.allocPrint(std.testing.allocator, "{s}-shm", .{db_path});
    defer std.testing.allocator.free(shm);
    const journal = try std.fmt.allocPrint(std.testing.allocator, "{s}-journal", .{db_path});
    defer std.testing.allocator.free(journal);
    try std.fs.cwd().writeFile(.{ .sub_path = wal, .data = "" });
    try std.fs.cwd().writeFile(.{ .sub_path = shm, .data = "" });
    try std.fs.cwd().writeFile(.{ .sub_path = journal, .data = "" });
    const before_db = try fileState(db_path);
    const before_wal = try fileState(wal);
    const before_shm = try fileState(shm);
    const before_journal = try fileState(journal);
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);

    const ok = try runEnv(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", db_path, "--all-domains", "--include-expired" }, tmp_root, null);
    defer std.testing.allocator.free(ok.stdout);
    defer std.testing.allocator.free(ok.stderr);
    try expectExit0(ok);
    try expectUnchanged(db_path, before_db);
    try expectUnchanged(wal, before_wal);
    try expectUnchanged(shm, before_shm);
    try expectUnchanged(journal, before_journal);
    try expectNoSnapshots(tmp_root);

    try tmp.dir.writeFile(.{ .sub_path = "bad", .data = "not a database" });
    const bad_path = try tmp.dir.realpathAlloc(std.testing.allocator, "bad");
    defer std.testing.allocator.free(bad_path);
    const before_bad = try fileState(bad_path);
    const bad = try runEnv(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", bad_path, "--all-domains" }, tmp_root, null);
    defer std.testing.allocator.free(bad.stdout);
    defer std.testing.allocator.free(bad.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 1 }, bad.term);
    try expectUnchanged(bad_path, before_bad);
    try expectNoSnapshots(tmp_root);
}

test "chromium empty database and wal-only data are read through snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const empty_path = try tmpPath(&tmp, &.{ "empty", "Cookies" });
    defer std.testing.allocator.free(empty_path);
    try tmp.dir.makePath("empty");
    try buildDb(empty_path, 23, &.{});
    const empty = try run(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", empty_path, "--all-domains" });
    defer std.testing.allocator.free(empty.stdout);
    defer std.testing.allocator.free(empty.stderr);
    try expectExit0(empty);
    var empty_json = try parseJson(empty.stdout);
    defer empty_json.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_json.value.array.items.len);

    const db_path = try tmpPath(&tmp, &.{ "wal", "Cookies" });
    defer std.testing.allocator.free(db_path);
    try tmp.dir.makePath("wal");
    var child = std.process.Child.init(&.{ "sqlite3", db_path }, std.testing.allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    try child.stdin.?.writeAll(
        \\PRAGMA journal_mode=WAL;
        \\PRAGMA wal_autocheckpoint=0;
        \\CREATE TABLE cookies(creation_utc INTEGER NOT NULL DEFAULT 0, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL DEFAULT 0, has_expires INTEGER NOT NULL DEFAULT 1, is_persistent INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1, samesite INTEGER NOT NULL DEFAULT -1, source_scheme INTEGER NOT NULL DEFAULT 0, source_port INTEGER NOT NULL DEFAULT -1, is_same_party INTEGER NOT NULL DEFAULT 0, last_update_utc INTEGER NOT NULL DEFAULT 0);
        \\CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        \\INSERT INTO meta(key,value) VALUES('version','23');
        \\INSERT INTO cookies(host_key,name,value,encrypted_value,path,expires_utc,is_secure,is_httponly,has_expires,is_persistent,samesite) VALUES('example.com','wal','visible',X'','/',13350000000000000,0,0,1,1,1);
        \\
    );
    const wal = try std.fmt.allocPrint(std.testing.allocator, "{s}-wal", .{db_path});
    defer std.testing.allocator.free(wal);
    var attempts: usize = 0;
    while (attempts < 20 and !exists(wal)) : (attempts += 1) std.Thread.sleep(10 * std.time.ns_per_ms);
    try std.testing.expect(exists(wal));

    const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", db_path, "--all-domains", "--include-expired" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try std.testing.expectEqualStrings("wal", parsed.value.array.items[0].object.get("name").?.string);

    try child.stdin.?.writeAll(".quit\n");
    child.stdin.?.close();
    child.stdin = null;
    const stderr = try child.stderr.?.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, try child.wait());
}

test "chromium profile roots support all browser values and default discovery is gated" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const browsers = [_][]const u8{ "chrome", "chromium", "edge", "brave", "vivaldi", "opera", "arc" };
    for (browsers) |browser| {
        const profile_dir = try std.fmt.allocPrint(std.testing.allocator, "{s}/Default", .{browser});
        defer std.testing.allocator.free(profile_dir);
        try tmp.dir.makePath(profile_dir);
        const root = try tmp.dir.realpathAlloc(std.testing.allocator, browser);
        defer std.testing.allocator.free(root);
        const db_path = try std.fs.path.join(std.testing.allocator, &.{ root, "Default", "Cookies" });
        defer std.testing.allocator.free(db_path);
        try buildDb(db_path, 23, &.{.{ .name = browser, .value = "ok", .host = "example.com", .path = "/", .expires_utc = 13_350_000_000_000_000 }});
        const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", browser, "--chrome-profile-root", root, "--all-domains", "--include-expired" });
        defer std.testing.allocator.free(res.stdout);
        defer std.testing.allocator.free(res.stderr);
        try expectExit0(res);
        try std.testing.expect(std.mem.indexOf(u8, res.stdout, browser) != null);
    }
    const gated = try run(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--all-domains" });
    defer std.testing.allocator.free(gated.stdout);
    defer std.testing.allocator.free(gated.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 1 }, gated.term);
    try std.testing.expect(std.mem.indexOf(u8, gated.stderr, "SWEETCOOKIE_ALLOW_REAL_BROWSER=1") != null);
}

test "chromium broad export requires all domains and wrong key warns while continuing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmpPath(&tmp, &.{"Cookies"});
    defer std.testing.allocator.free(db_path);
    const key = [_]u8{0} ** 32;
    const encrypted = try gcmBlob(std.testing.allocator, &key, "secret");
    defer std.testing.allocator.free(encrypted);
    try buildDb(db_path, 23, &.{
        .{ .name = "plain", .value = "plaintext", .host = "example.com", .path = "/", .expires_utc = 13_350_000_000_000_000 },
        .{ .name = "encrypted", .encrypted_value = encrypted, .host = "example.com", .path = "/", .expires_utc = 13_350_000_000_000_000 },
    });

    const refused = try run(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", db_path });
    defer std.testing.allocator.free(refused.stdout);
    defer std.testing.allocator.free(refused.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 2 }, refused.term);
    try std.testing.expect(std.mem.indexOf(u8, refused.stderr, "--all-domains") != null);

    const wrong = try runEnv(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", db_path, "--all-domains", "--include-expired" }, null, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    defer std.testing.allocator.free(wrong.stdout);
    defer std.testing.allocator.free(wrong.stderr);
    try expectExit0(wrong);
    try std.testing.expect(std.mem.indexOf(u8, wrong.stderr, "warning:") != null);
    var parsed = try parseJson(wrong.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try std.testing.expectEqualStrings("plain", parsed.value.array.items[0].object.get("name").?.string);
}

fn exists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}
