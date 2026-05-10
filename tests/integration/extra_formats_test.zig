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

fn parseJson(bytes: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
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

fn fixtureJson() []const u8 {
    return 
    \\[
    \\  {"name":"sid","value":"SECRET_VALUE_XYZ","domain":".example.com","path":"/","expires":4102444800,"secure":true,"httpOnly":true},
    \\  {"name":"sid","value":"expired","domain":".example.com","path":"/old","expires":1},
    \\  {"name":"csrf","value":"token","domain":"example.com","path":"/app","expires":4102444800},
    \\  {"name":"other","value":"nope","domain":"other.com","path":"/","expires":4102444800}
    \\]
    ;
}

fn assertMode0600(path: []const u8) !void {
    if (@import("builtin").os.tag == .windows) return;
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    const stat = try file.stat();
    try std.testing.expectEqual(@as(u32, 0o600), stat.mode & 0o777);
    try std.testing.expect(stat.size > 0);
}

fn readFile(path: []const u8) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    return file.readToEndAlloc(std.testing.allocator, 1024 * 1024);
}

fn sha256(bytes: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return hash;
}

fn fileState(path: []const u8) !FileState {
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    const stat = try file.stat();
    const bytes = try file.readToEndAlloc(std.testing.allocator, 16 * 1024 * 1024);
    defer std.testing.allocator.free(bytes);
    return .{ .size = stat.size, .mtime = stat.mtime, .hash = sha256(bytes) };
}

fn expectUnchanged(path: []const u8, before: FileState) !void {
    const after = try fileState(path);
    try std.testing.expectEqual(before.size, after.size);
    try std.testing.expectEqual(before.mtime, after.mtime);
    try std.testing.expectEqualSlices(u8, &before.hash, &after.hash);
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
        try writer.print(", {d}, 0, 0, {d}, {d}, 0, 0, 0, 0);\n", .{ entry.expiry, @intFromBool(entry.secure), @intFromBool(entry.httponly) });
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

fn buildChromiumDb(db_path: []const u8) !void {
    var sql = std.ArrayList(u8).empty;
    defer sql.deinit(std.testing.allocator);
    const writer = sql.writer(std.testing.allocator);
    try writer.writeAll(
        \\PRAGMA journal_mode=DELETE;
        \\CREATE TABLE cookies(creation_utc INTEGER NOT NULL DEFAULT 0, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL DEFAULT 0, has_expires INTEGER NOT NULL DEFAULT 1, is_persistent INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1, samesite INTEGER NOT NULL DEFAULT -1, source_scheme INTEGER NOT NULL DEFAULT 0, source_port INTEGER NOT NULL DEFAULT -1, is_same_party INTEGER NOT NULL DEFAULT 0, last_update_utc INTEGER NOT NULL DEFAULT 0);
        \\CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        \\INSERT INTO meta(key, value) VALUES('version', '23');
        \\BEGIN;
        \\INSERT INTO cookies(host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, is_persistent, samesite) VALUES('.example.com', 'sid', 'keep', X'', '/', 13350000000000000, 1, 1, 1, 1, 1);
        \\INSERT INTO cookies(host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, is_persistent, samesite) VALUES('other.com', 'other', 'drop', X'', '/', 13350000000000000, 0, 0, 1, 1, -1);
        \\COMMIT;
        \\VACUUM;
        \\
    );
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

test "VAL-NETSCAPE-015 and VAL-NETSCAPE-016 file mode and bytes stable across two runs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "in.json", .data = fixtureJson() });
    const in_path = try tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
    defer std.testing.allocator.free(in_path);
    const out_path = try tmpPath(&tmp, &.{"cookies.txt"});
    defer std.testing.allocator.free(out_path);

    const first = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--format", "netscape", "--output", out_path });
    defer std.testing.allocator.free(first.stdout);
    defer std.testing.allocator.free(first.stderr);
    try expectExit0(first);
    try assertMode0600(out_path);
    const first_bytes = try readFile(out_path);
    defer std.testing.allocator.free(first_bytes);
    const first_hash = sha256(first_bytes);

    const second = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--format", "netscape", "--output", out_path });
    defer std.testing.allocator.free(second.stdout);
    defer std.testing.allocator.free(second.stderr);
    try expectExit0(second);
    try assertMode0600(out_path);
    const second_bytes = try readFile(out_path);
    defer std.testing.allocator.free(second_bytes);
    const second_hash = sha256(second_bytes);
    try std.testing.expectEqualSlices(u8, &first_hash, &second_hash);
}

test "VAL-NETSCAPE-012 through VAL-NETSCAPE-014 CLI reports offending cookie and writes no output" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const out_path = try tmpPath(&tmp, &.{"bad.txt"});
    defer std.testing.allocator.free(out_path);
    const res = try run(std.testing.allocator, &.{ exe, "export", "--inline-json", "[{\"name\":\"bad\",\"value\":\"a\\tb\",\"domain\":\"example.com\",\"path\":\"/\"}]", "--format", "netscape", "--output", out_path });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expect(res.term.Exited != 0);
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stderr, 1, "NetscapeUnencodableValue"));
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stderr, 1, "bad"));
    try std.testing.expectError(error.FileNotFound, std.fs.openFileAbsolute(out_path, .{ .mode = .read_only }));
}

test "VAL-NETSCAPE-019 and VAL-NETSCAPE-022 stdout and shared filters work with debug redaction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "in.json", .data = fixtureJson() });
    const in_path = try tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
    defer std.testing.allocator.free(in_path);
    const res = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--format", "netscape", "--url", "https://example.com/app/page", "--name", "csrf", "--include-expired", "--debug" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try std.testing.expect(std.mem.startsWith(u8, res.stdout, "# Netscape HTTP Cookie File\n"));
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "example.com\tFALSE"));
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "\tcsrf\ttoken\n"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, res.stdout, 1, "sid"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, res.stderr, 1, "SECRET_VALUE_XYZ"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, res.stderr, 1, "token"));

    const expired_excluded = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--format", "netscape", "--url", "https://example.com/old/page", "--name", "sid" });
    defer std.testing.allocator.free(expired_excluded.stdout);
    defer std.testing.allocator.free(expired_excluded.stderr);
    try expectExit0(expired_excluded);
    try std.testing.expect(!std.mem.containsAtLeast(u8, expired_excluded.stdout, 1, "expired"));

    const expired_included = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--format", "netscape", "--url", "https://example.com/old/page", "--name", "sid", "--include-expired" });
    defer std.testing.allocator.free(expired_included.stdout);
    defer std.testing.allocator.free(expired_included.stderr);
    try expectExit0(expired_included);
    try std.testing.expect(std.mem.containsAtLeast(u8, expired_included.stdout, 1, "\tsid\texpired\n"));
}

test "VAL-NETSCAPE-018 empty input after filtering is header only" {
    const res = try run(std.testing.allocator, &.{ exe, "export", "--inline-json", "[]", "--format", "netscape" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try std.testing.expectEqualStrings("# Netscape HTTP Cookie File\n\n", res.stdout);
}

test "export help lists netscape format" {
    const res = try run(std.testing.allocator, &.{ exe, "export", "--help" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "netscape"));
}

test "VAL-NETSCAPE-021 firefox source bytes unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{
        .sub_path = "profiles.ini",
        .data =
        \\[Profile0]
        \\Name=default
        \\IsRelative=1
        \\Path=default
        \\Default=1
        \\
        ,
    });
    try tmp.dir.makePath("default");
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ root, "default", "cookies.sqlite" });
    defer std.testing.allocator.free(db_path);
    try buildFirefoxDb(db_path, &.{.{ .name = "sid", .value = "safe", .host = ".example.com", .path = "/", .expiry = 4102444800 }});
    const before = try fileState(db_path);
    const out_path = try tmpPath(&tmp, &.{"firefox.txt"});
    defer std.testing.allocator.free(out_path);

    const res = try runWithTmp(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-profile-root", root, "--format", "netscape", "--output", out_path }, root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try expectUnchanged(db_path, before);
    try assertMode0600(out_path);
}

test "VAL-PLAYWRIGHT-001 through VAL-PLAYWRIGHT-013 storage state file shape mode and determinism" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{
        .sub_path = "in.json",
        .data =
        \\[
        \\  {"name":"b","value":"bee","domain":"z.example","path":"/","secure":true,"httpOnly":false,"sameSite":"None"},
        \\  {"name":"a","value":"strict","domain":".Example.com","path":"/b","expires":1750000000,"secure":false,"httpOnly":true,"sameSite":"Strict"},
        \\  {"name":"a","value":"lax","domain":".example.com","path":"/a","secure":true,"httpOnly":true,"sameSite":"Lax"},
        \\  {"name":"no-site","value":"none","domain":"example.com","path":"/"}
        \\]
        ,
    });
    const in_path = try tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
    defer std.testing.allocator.free(in_path);
    const out1_path = try tmpPath(&tmp, &.{"state1.json"});
    defer std.testing.allocator.free(out1_path);
    const out2_path = try tmpPath(&tmp, &.{"state2.json"});
    defer std.testing.allocator.free(out2_path);

    const first = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--include-expired", "--format", "playwright", "--output", out1_path });
    defer std.testing.allocator.free(first.stdout);
    defer std.testing.allocator.free(first.stderr);
    try expectExit0(first);
    try assertMode0600(out1_path);

    const second = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--include-expired", "--format", "playwright", "--output", out2_path });
    defer std.testing.allocator.free(second.stdout);
    defer std.testing.allocator.free(second.stderr);
    try expectExit0(second);
    try assertMode0600(out2_path);

    const bytes1 = try readFile(out1_path);
    defer std.testing.allocator.free(bytes1);
    const bytes2 = try readFile(out2_path);
    defer std.testing.allocator.free(bytes2);
    try std.testing.expectEqualSlices(u8, bytes1, bytes2);
    try std.testing.expect(bytes1.len > 0 and bytes1[bytes1.len - 1] != '\n');

    const jq = try run(std.testing.allocator, &.{ "jq", ".", out1_path });
    defer std.testing.allocator.free(jq.stdout);
    defer std.testing.allocator.free(jq.stderr);
    try expectExit0(jq);
    const node_script = try std.fmt.allocPrint(std.testing.allocator, "JSON.parse(require('fs').readFileSync('{s}', 'utf8'))", .{out1_path});
    defer std.testing.allocator.free(node_script);
    const node = try run(std.testing.allocator, &.{ "node", "-e", node_script });
    defer std.testing.allocator.free(node.stdout);
    defer std.testing.allocator.free(node.stderr);
    try expectExit0(node);

    var parsed = try parseJson(bytes1);
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.object.count());
    const cookies = parsed.value.object.get("cookies").?.array.items;
    try std.testing.expectEqual(@as(usize, 4), cookies.len);
    try std.testing.expectEqual(@as(usize, 0), parsed.value.object.get("origins").?.array.items.len);
    try std.testing.expectEqualStrings("a", cookies[0].object.get("name").?.string);
    try std.testing.expectEqualStrings(".example.com", cookies[0].object.get("domain").?.string);
    try std.testing.expectEqualStrings("/a", cookies[0].object.get("path").?.string);
    try std.testing.expectEqual(@as(i64, -1), cookies[0].object.get("expires").?.integer);
    try std.testing.expect(cookies[0].object.get("secure").?.bool);
    try std.testing.expect(cookies[0].object.get("httpOnly").?.bool);
    try std.testing.expectEqualStrings("Lax", cookies[0].object.get("sameSite").?.string);
    try std.testing.expectEqual(@as(i64, 1750000000), cookies[1].object.get("expires").?.integer);
    try std.testing.expectEqualStrings("Strict", cookies[1].object.get("sameSite").?.string);
    try std.testing.expectEqualStrings("None", cookies[2].object.get("sameSite").?.string);
    try std.testing.expect(!cookies[3].object.contains("sameSite"));
}

test "VAL-PLAYWRIGHT-013 empty input yields exact storage state object" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const out_path = try tmpPath(&tmp, &.{"empty-state.json"});
    defer std.testing.allocator.free(out_path);

    const res = try run(std.testing.allocator, &.{ exe, "export", "--inline-json", "[]", "--format", "playwright", "--output", out_path });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    const bytes = try readFile(out_path);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("{\"cookies\":[],\"origins\":[]}", bytes);
}

test "VAL-PLAYWRIGHT-015 and VAL-PLAYWRIGHT-016 source unchanged and filters flow through" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmpPath(&tmp, &.{"Cookies"});
    defer std.testing.allocator.free(db_path);
    try buildChromiumDb(db_path);
    const before = try fileState(db_path);
    const out_path = try tmpPath(&tmp, &.{"chrome-state.json"});
    defer std.testing.allocator.free(out_path);
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);

    const res = try runWithTmp(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--chrome-cookies-db", db_path, "--all-domains", "--include-expired", "--url", "https://example.com/", "--name", "sid", "--format", "playwright", "--output", out_path }, tmp_root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try expectUnchanged(db_path, before);
    try assertMode0600(out_path);
    const bytes = try readFile(out_path);
    defer std.testing.allocator.free(bytes);
    var parsed = try parseJson(bytes);
    defer parsed.deinit();
    const cookies = parsed.value.object.get("cookies").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
    try std.testing.expectEqualStrings("sid", cookies[0].object.get("name").?.string);
    try std.testing.expectEqualStrings(".example.com", cookies[0].object.get("domain").?.string);
}

test "VAL-PUPPETEER-001 through VAL-PUPPETEER-011 and VAL-PUPPETEER-015 array shape mode and determinism" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{
        .sub_path = "in.json",
        .data =
        \\[
        \\  {"name":"b","value":"bee","domain":"z.example","path":"/","secure":true,"httpOnly":false,"sameSite":"None"},
        \\  {"name":"a","value":"strict","domain":".Example.com","path":"/b","expires":1750000000,"secure":false,"httpOnly":true,"sameSite":"Strict"},
        \\  {"name":"a","value":"lax","domain":".example.com","path":"/a","secure":true,"httpOnly":true,"sameSite":"Lax"},
        \\  {"name":"c","value":"session","domain":"example.com","path":"/","secure":false,"httpOnly":false,"sameSite":"Lax"}
        \\]
        ,
    });
    const in_path = try tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
    defer std.testing.allocator.free(in_path);
    const out1_path = try tmpPath(&tmp, &.{"cookies1.json"});
    defer std.testing.allocator.free(out1_path);
    const out2_path = try tmpPath(&tmp, &.{"cookies2.json"});
    defer std.testing.allocator.free(out2_path);

    const first = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--include-expired", "--format", "puppeteer", "--output", out1_path });
    defer std.testing.allocator.free(first.stdout);
    defer std.testing.allocator.free(first.stderr);
    try expectExit0(first);
    try assertMode0600(out1_path);

    const second = try run(std.testing.allocator, &.{ exe, "export", "--inline-file", in_path, "--include-expired", "--format", "puppeteer", "--output", out2_path });
    defer std.testing.allocator.free(second.stdout);
    defer std.testing.allocator.free(second.stderr);
    try expectExit0(second);
    try assertMode0600(out2_path);

    const bytes1 = try readFile(out1_path);
    defer std.testing.allocator.free(bytes1);
    const bytes2 = try readFile(out2_path);
    defer std.testing.allocator.free(bytes2);
    try std.testing.expectEqualSlices(u8, bytes1, bytes2);
    try std.testing.expect(bytes1.len > 0 and bytes1[bytes1.len - 1] != '\n');

    const jq = try run(std.testing.allocator, &.{ "jq", "type == \"array\"", out1_path });
    defer std.testing.allocator.free(jq.stdout);
    defer std.testing.allocator.free(jq.stderr);
    try expectExit0(jq);
    try std.testing.expect(std.mem.containsAtLeast(u8, jq.stdout, 1, "true"));

    var parsed = try parseJson(bytes1);
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .array);
    const cookies = parsed.value.array.items;
    try std.testing.expectEqual(@as(usize, 4), cookies.len);
    try std.testing.expectEqualStrings("a", cookies[0].object.get("name").?.string);
    try std.testing.expectEqualStrings(".example.com", cookies[0].object.get("domain").?.string);
    try std.testing.expectEqualStrings("/a", cookies[0].object.get("path").?.string);
    try std.testing.expect(!cookies[0].object.contains("expires"));
    try std.testing.expect(cookies[0].object.get("secure").?.bool);
    try std.testing.expect(cookies[0].object.get("httpOnly").?.bool);
    try std.testing.expectEqualStrings("Lax", cookies[0].object.get("sameSite").?.string);
    try std.testing.expectEqual(@as(i64, 1750000000), cookies[1].object.get("expires").?.integer);
    try std.testing.expectEqualStrings("Strict", cookies[1].object.get("sameSite").?.string);
    try std.testing.expectEqualStrings("None", cookies[2].object.get("sameSite").?.string);
    try std.testing.expect(!cookies[2].object.contains("expires"));
    try std.testing.expect(!cookies[3].object.contains("expires"));
}

test "VAL-PUPPETEER-011 empty input yields exact array" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const out_path = try tmpPath(&tmp, &.{"empty-cookies.json"});
    defer std.testing.allocator.free(out_path);

    const res = try run(std.testing.allocator, &.{ exe, "export", "--inline-json", "[]", "--format", "puppeteer", "--output", out_path });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    const bytes = try readFile(out_path);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("[]", bytes);
}

test "VAL-PUPPETEER-013 and VAL-PUPPETEER-014 source unchanged and filters flow through" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{
        .sub_path = "profiles.ini",
        .data =
        \\[Profile0]
        \\Name=default
        \\IsRelative=1
        \\Path=default
        \\Default=1
        \\
        ,
    });
    try tmp.dir.makePath("default");
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const db_path = try std.fs.path.join(std.testing.allocator, &.{ root, "default", "cookies.sqlite" });
    defer std.testing.allocator.free(db_path);
    try buildFirefoxDb(db_path, &.{
        .{ .name = "sid", .value = "keep", .host = ".example.com", .path = "/", .expiry = 4102444800, .secure = true, .httponly = true },
        .{ .name = "other", .value = "drop", .host = "other.com", .path = "/", .expiry = 4102444800 },
    });
    const before = try fileState(db_path);
    const out_path = try tmpPath(&tmp, &.{"firefox-puppeteer.json"});
    defer std.testing.allocator.free(out_path);

    const res = try runWithTmp(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--firefox-profile-root", root, "--url", "https://example.com/", "--name", "sid", "--format", "puppeteer", "--output", out_path }, root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try expectUnchanged(db_path, before);
    try assertMode0600(out_path);
    const bytes = try readFile(out_path);
    defer std.testing.allocator.free(bytes);
    var parsed = try parseJson(bytes);
    defer parsed.deinit();
    const cookies = parsed.value.array.items;
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
    try std.testing.expectEqualStrings("sid", cookies[0].object.get("name").?.string);
    try std.testing.expectEqualStrings(".example.com", cookies[0].object.get("domain").?.string);
}

test "export help lists puppeteer format" {
    const res = try run(std.testing.allocator, &.{ exe, "export", "--help" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "puppeteer"));
}
