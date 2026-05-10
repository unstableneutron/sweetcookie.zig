const std = @import("std");

fn run(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.RunResult {
    return runEnv(allocator, argv, null);
}

fn runEnv(allocator: std.mem.Allocator, argv: []const []const u8, tmpdir: ?[]const u8) !std.process.Child.RunResult {
    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    if (tmpdir) |dir| try env.put("TMPDIR", dir);
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

fn fixtureJson() []const u8 {
    return 
    \\[
    \\  {"name":"zeta","value":"last","domain":"example.com","path":"/z","expires":4102444800,"secure":false,"httpOnly":false,"sameSite":"Lax"},
    \\  {"name":"alpha","value":"first","domain":".example.com","path":"/","expires":4102444800,"secure":true,"httpOnly":true,"sameSite":"Strict"},
    \\  {"name":"beta","value":"second","domain":"example.com","path":"/","expires":null,"secure":false,"httpOnly":false,"sameSite":null}
    \\]
    ;
}

fn writeFixture(tmp: *std.testing.TmpDir) ![]u8 {
    try tmp.dir.writeFile(.{ .sub_path = "in.json", .data = fixtureJson() });
    return tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
}

fn tmpPath(tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    return std.fs.path.join(std.testing.allocator, &.{ root, name });
}

fn readOutput(path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(std.testing.allocator, path, 1024 * 1024);
}

const FileState = struct {
    size: u64,
    mtime: i128,
    hash: [32]u8,
};

const FirefoxCookie = struct {
    name: []const u8,
    value: []const u8,
    host: []const u8,
    path: []const u8,
    expiry: i64 = 2_000_000_000,
};

const ChromiumCookie = struct {
    name: []const u8,
    value: []const u8,
    host: []const u8,
    path: []const u8,
    expires_utc: i64 = 13_350_000_000_000_000,
};

const SafariCookie = struct {
    domain: []const u8,
    name: []const u8,
    path: []const u8,
    value: []const u8,
    expiry: f64 = 1_021_692_800.0,
};

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

fn writeSidecars(db_path: []const u8) ![3][]u8 {
    const suffixes = [_][]const u8{ "-wal", "-shm", "-journal" };
    var paths: [3][]u8 = undefined;
    var written: usize = 0;
    errdefer for (paths[0..written]) |path| std.testing.allocator.free(path);
    for (suffixes, 0..) |suffix, i| {
        paths[i] = try std.mem.concat(std.testing.allocator, u8, &.{ db_path, suffix });
        written += 1;
        try std.fs.cwd().writeFile(.{ .sub_path = paths[i], .data = "" });
    }
    return paths;
}

fn freeSidecarPaths(paths: [3][]u8) void {
    for (paths) |path| std.testing.allocator.free(path);
}

fn sidecarStates(paths: [3][]u8) ![3]FileState {
    var states: [3]FileState = undefined;
    for (paths, 0..) |path, i| states[i] = try fileState(path);
    return states;
}

fn expectSidecarsUnchanged(paths: [3][]u8, before: [3]FileState) !void {
    for (paths, before) |path, state| try expectUnchanged(path, state);
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
        try sqlString(writer, entry.name);
        try writer.writeAll(", ");
        try sqlString(writer, entry.value);
        try writer.writeAll(", ");
        try sqlString(writer, entry.host);
        try writer.writeAll(", ");
        try sqlString(writer, entry.path);
        try writer.print(", {d}, 0, 0, 0, 0, 0, 1, 1, 0);\n", .{entry.expiry});
    }
    try writer.writeAll("COMMIT;\nVACUUM;\n");
    const res = try std.process.Child.run(.{ .allocator = std.testing.allocator, .argv = &.{ "sqlite3", "-batch", db_path, sql.items }, .max_output_bytes = 1024 * 1024 });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, res.term);
}

fn buildFirefoxProfile(tmp: *std.testing.TmpDir, entries: []const FirefoxCookie) !struct { root: []u8, db: []u8 } {
    try tmp.dir.makePath("firefox/Profiles/default");
    try tmp.dir.writeFile(.{
        .sub_path = "firefox/profiles.ini",
        .data =
        \\[Profile0]
        \\Name=default
        \\IsRelative=1
        \\Path=Profiles/default
        \\Default=1
        \\
        ,
    });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "firefox");
    const db = try std.fs.path.join(std.testing.allocator, &.{ root, "Profiles", "default", "cookies.sqlite" });
    try buildFirefoxDb(db, entries);
    return .{ .root = root, .db = db };
}

fn buildChromiumDb(db_path: []const u8, entries: []const ChromiumCookie) !void {
    var sql = std.ArrayList(u8).empty;
    defer sql.deinit(std.testing.allocator);
    const writer = sql.writer(std.testing.allocator);
    try writer.writeAll(
        \\PRAGMA journal_mode=DELETE;
        \\CREATE TABLE cookies(creation_utc INTEGER NOT NULL DEFAULT 0, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL DEFAULT 0, has_expires INTEGER NOT NULL DEFAULT 1, is_persistent INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1, samesite INTEGER NOT NULL DEFAULT -1, source_scheme INTEGER NOT NULL DEFAULT 0, source_port INTEGER NOT NULL DEFAULT -1, is_same_party INTEGER NOT NULL DEFAULT 0, last_update_utc INTEGER NOT NULL DEFAULT 0);
        \\CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        \\INSERT INTO meta(key, value) VALUES('version', '23');
        \\BEGIN;
        \\
    );
    for (entries, 0..) |entry, i| {
        try writer.print("INSERT INTO cookies(rowid, host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, has_expires, is_persistent, samesite) VALUES({d}, ", .{i + 1});
        try sqlString(writer, entry.host);
        try writer.writeAll(", ");
        try sqlString(writer, entry.name);
        try writer.writeAll(", ");
        try sqlString(writer, entry.value);
        try writer.writeAll(", X'', ");
        try sqlString(writer, entry.path);
        try writer.print(", {d}, 0, 0, 1, 1, 1);\n", .{entry.expires_utc});
    }
    try writer.writeAll("COMMIT;\nVACUUM;\n");
    const res = try std.process.Child.run(.{ .allocator = std.testing.allocator, .argv = &.{ "sqlite3", "-batch", db_path, sql.items }, .max_output_bytes = 1024 * 1024 });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, res.term);
}

fn sqlString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('\'');
    for (value) |ch| {
        if (ch == '\'') try writer.writeByte('\'');
        try writer.writeByte(ch);
    }
    try writer.writeByte('\'');
}

fn buildSafariBlobFile(tmp: *std.testing.TmpDir, entries: []const SafariCookie) ![]u8 {
    var blob = std.ArrayList(u8).empty;
    defer blob.deinit(std.testing.allocator);
    try appendSafariBlob(std.testing.allocator, &blob, entries);
    const path = try tmpPath(tmp, "Cookies.binarycookies");
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = blob.items });
    return path;
}

fn appendSafariBlob(allocator: std.mem.Allocator, out: *std.ArrayList(u8), cookies: []const SafariCookie) !void {
    try out.appendSlice(allocator, "cook");
    try appendU32(out, allocator, 1, .big);
    const page = try buildSafariPage(allocator, cookies);
    defer allocator.free(page);
    try appendU32(out, allocator, @intCast(page.len), .big);
    try out.appendSlice(allocator, page);
}

fn buildSafariPage(allocator: std.mem.Allocator, cookies: []const SafariCookie) ![]u8 {
    var page = std.ArrayList(u8).empty;
    errdefer page.deinit(allocator);
    try appendU32(&page, allocator, 0x0000_0100, .little);
    try appendU32(&page, allocator, @intCast(cookies.len), .little);
    const offsets_start = page.items.len;
    try page.appendNTimes(allocator, 0, cookies.len * 4);
    for (cookies, 0..) |cookie, index| {
        const offset = page.items.len;
        writeU32At(page.items, offsets_start + index * 4, @intCast(offset), .little);
        try appendSafariCookie(&page, allocator, cookie);
    }
    return page.toOwnedSlice(allocator);
}

fn appendSafariCookie(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cookie: SafariCookie) !void {
    const start = out.items.len;
    try out.appendNTimes(allocator, 0, 44);
    const domain_offset = out.items.len - start;
    try out.appendSlice(allocator, cookie.domain);
    try out.append(allocator, 0);
    const name_offset = out.items.len - start;
    try out.appendSlice(allocator, cookie.name);
    try out.append(allocator, 0);
    const path_offset = out.items.len - start;
    try out.appendSlice(allocator, cookie.path);
    try out.append(allocator, 0);
    const value_offset = out.items.len - start;
    try out.appendSlice(allocator, cookie.value);
    try out.append(allocator, 0);
    const record = out.items[start..][0 .. out.items.len - start];
    writeU32At(record, 0, @intCast(record.len), .little);
    writeU32At(record, 4, 0, .little);
    writeU32At(record, 8, 0, .little);
    writeU32At(record, 12, @intCast(domain_offset), .little);
    writeU32At(record, 16, @intCast(name_offset), .little);
    writeU32At(record, 20, @intCast(path_offset), .little);
    writeU32At(record, 24, @intCast(value_offset), .little);
    writeF64At(record, 28, cookie.expiry);
    writeF64At(record, 36, 0.0);
}

fn appendU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32, endian: std.builtin.Endian) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, endian);
    try out.appendSlice(allocator, &buf);
}

fn writeU32At(bytes: []u8, offset: usize, value: u32, endian: std.builtin.Endian) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, endian);
}

fn writeF64At(bytes: []u8, offset: usize, value: f64) void {
    std.mem.writeInt(u64, bytes[offset..][0..8], @bitCast(value), .little);
}

fn expectSweetCookieEquivalent(a: std.json.Value, b: std.json.Value) !void {
    try std.testing.expectEqual(@as(i64, 1), a.object.get("version").?.integer);
    try std.testing.expectEqual(@as(i64, 1), b.object.get("version").?.integer);
    try std.testing.expectEqualStrings(a.object.get("source").?.string, b.object.get("source").?.string);
    const a_cookies = a.object.get("cookies").?.array.items;
    const b_cookies = b.object.get("cookies").?.array.items;
    try std.testing.expectEqual(a_cookies.len, b_cookies.len);
    for (a_cookies, b_cookies) |a_cookie, b_cookie| {
        try expectCookieEquivalent(a_cookie, b_cookie);
    }
}

fn expectCookieEquivalent(a: std.json.Value, b: std.json.Value) !void {
    try std.testing.expectEqualStrings(a.object.get("name").?.string, b.object.get("name").?.string);
    try std.testing.expectEqualStrings(a.object.get("value").?.string, b.object.get("value").?.string);
    try std.testing.expectEqualStrings(a.object.get("domain").?.string, b.object.get("domain").?.string);
    try std.testing.expectEqualStrings(a.object.get("raw_domain").?.string, b.object.get("raw_domain").?.string);
    try std.testing.expectEqual(a.object.get("host_only").?.bool, b.object.get("host_only").?.bool);
    try std.testing.expectEqualStrings(a.object.get("path").?.string, b.object.get("path").?.string);
    try std.testing.expectEqual(a.object.get("secure").?.bool, b.object.get("secure").?.bool);
    try std.testing.expectEqual(a.object.get("httpOnly").?.bool, b.object.get("httpOnly").?.bool);
    try expectJsonScalarEqual(a.object.get("expires").?, b.object.get("expires").?);
    try expectJsonScalarEqual(a.object.get("sameSite").?, b.object.get("sameSite").?);
}

fn expectJsonScalarEqual(a: std.json.Value, b: std.json.Value) !void {
    try std.testing.expectEqual(std.meta.activeTag(a), std.meta.activeTag(b));
    switch (a) {
        .null => {},
        .integer => |i| try std.testing.expectEqual(i, b.integer),
        .bool => |v| try std.testing.expectEqual(v, b.bool),
        .string => |s| try std.testing.expectEqualStrings(s, b.string),
        else => return error.UnsupportedScalar,
    }
}

test "VAL-CROSS-008 lossless round-trip via sweet-cookie-json" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const in_path = try writeFixture(&tmp);
    defer std.testing.allocator.free(in_path);
    const out_path = try tmpPath(&tmp, "roundtrip.json");
    defer std.testing.allocator.free(out_path);

    const export_res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "sweet-cookie-json", "--output", out_path });
    defer std.testing.allocator.free(export_res.stdout);
    defer std.testing.allocator.free(export_res.stderr);
    try expectExit0(export_res);

    const reimport_res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", out_path, "--format", "sweet-cookie-json" });
    defer std.testing.allocator.free(reimport_res.stdout);
    defer std.testing.allocator.free(reimport_res.stderr);
    try expectExit0(reimport_res);

    const first_bytes = try readOutput(out_path);
    defer std.testing.allocator.free(first_bytes);
    var first = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, first_bytes, .{});
    defer first.deinit();
    var second = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, reimport_res.stdout, .{});
    defer second.deinit();

    try expectSweetCookieEquivalent(first.value, second.value);
}

test "VAL-CROSS-012 lightpanda-json and cookie-header are deterministic" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const in_path = try writeFixture(&tmp);
    defer std.testing.allocator.free(in_path);

    const light_1 = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "lightpanda-json" });
    defer std.testing.allocator.free(light_1.stdout);
    defer std.testing.allocator.free(light_1.stderr);
    try expectExit0(light_1);
    const light_2 = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "lightpanda-json" });
    defer std.testing.allocator.free(light_2.stdout);
    defer std.testing.allocator.free(light_2.stderr);
    try expectExit0(light_2);
    try std.testing.expectEqualStrings(light_1.stdout, light_2.stdout);

    const header_1 = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "cookie-header", "--url", "https://example.com/" });
    defer std.testing.allocator.free(header_1.stdout);
    defer std.testing.allocator.free(header_1.stderr);
    try expectExit0(header_1);
    const header_2 = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "cookie-header", "--url", "https://example.com/" });
    defer std.testing.allocator.free(header_2.stdout);
    defer std.testing.allocator.free(header_2.stderr);
    try expectExit0(header_2);
    try std.testing.expectEqualStrings(header_1.stdout, header_2.stdout);
}

test "VAL-CROSS-001 VAL-CROSS-002 inline wins across merge and replace modes with firefox" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const profile = try buildFirefoxProfile(&tmp, &.{
        .{ .name = "sid", .value = "firefox-value", .host = "example.com", .path = "/" },
        .{ .name = "firefox-only", .value = "browser", .host = "example.com", .path = "/" },
    });
    defer std.testing.allocator.free(profile.root);
    defer std.testing.allocator.free(profile.db);
    try tmp.dir.writeFile(.{
        .sub_path = "inline.json",
        .data =
        \\[
        \\{"name":"sid","value":"inline-value","domain":"example.com","path":"/","expires":4102444800},
        \\{"name":"inline-only","value":"inline","domain":"example.com","path":"/","expires":4102444800}
        \\]
        ,
    });
    const inline_path = try tmp.dir.realpathAlloc(std.testing.allocator, "inline.json");
    defer std.testing.allocator.free(inline_path);

    const modes = [_][]const u8{ "merge", "replace" };
    for (modes) |mode| {
        const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--browser", "firefox", "--firefox-profile-root", profile.root, "--inline-file", inline_path, "--mode", mode, "--include-expired" });
        defer std.testing.allocator.free(res.stdout);
        defer std.testing.allocator.free(res.stderr);
        try expectExit0(res);
        var parsed = try parseJson(res.stdout);
        defer parsed.deinit();
        const cookies = parsed.value.array.items;
        try std.testing.expectEqual(@as(usize, 3), cookies.len);
        var found_sid = false;
        var found_firefox = false;
        var found_inline = false;
        for (cookies) |cookie| {
            const name = cookie.object.get("name").?.string;
            const value = cookie.object.get("value").?.string;
            if (std.mem.eql(u8, name, "sid")) {
                found_sid = true;
                try std.testing.expectEqualStrings("inline-value", value);
            } else if (std.mem.eql(u8, name, "firefox-only")) {
                found_firefox = true;
                try std.testing.expectEqualStrings("browser", value);
            } else if (std.mem.eql(u8, name, "inline-only")) {
                found_inline = true;
                try std.testing.expectEqualStrings("inline", value);
            }
        }
        try std.testing.expect(found_sid and found_firefox and found_inline);
    }
}

test "VAL-CROSS-003 all backends in one invocation leave source files unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const firefox = try buildFirefoxProfile(&tmp, &.{.{ .name = "ff", .value = "firefox", .host = "example.com", .path = "/" }});
    defer std.testing.allocator.free(firefox.root);
    defer std.testing.allocator.free(firefox.db);
    const safari_file = try buildSafariBlobFile(&tmp, &.{.{ .domain = "example.com", .name = "sf", .path = "/", .value = "safari" }});
    defer std.testing.allocator.free(safari_file);
    try tmp.dir.makePath("chrome/Default");
    const chrome_root = try tmp.dir.realpathAlloc(std.testing.allocator, "chrome");
    defer std.testing.allocator.free(chrome_root);
    const chrome_db = try std.fs.path.join(std.testing.allocator, &.{ chrome_root, "Default", "Cookies" });
    defer std.testing.allocator.free(chrome_db);
    try buildChromiumDb(chrome_db, &.{.{ .name = "ch", .value = "chromium", .host = "example.com", .path = "/" }});
    const firefox_sidecars = try writeSidecars(firefox.db);
    defer freeSidecarPaths(firefox_sidecars);
    const chromium_sidecars = try writeSidecars(chrome_db);
    defer freeSidecarPaths(chromium_sidecars);
    const before_ff = try fileState(firefox.db);
    const before_ff_sidecars = try sidecarStates(firefox_sidecars);
    const before_sf = try fileState(safari_file);
    const before_ch = try fileState(chrome_db);
    const before_ch_sidecars = try sidecarStates(chromium_sidecars);
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);

    const res = try runEnv(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--browser", "firefox", "--firefox-profile-root", firefox.root, "--browser", "safari", "--safari-cookies-file", safari_file, "--browser", "chrome", "--chrome-cookies-db", chrome_db, "--all-domains", "--include-expired" }, tmp_root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 3), parsed.value.array.items.len);
    try expectUnchanged(firefox.db, before_ff);
    try expectSidecarsUnchanged(firefox_sidecars, before_ff_sidecars);
    try expectUnchanged(safari_file, before_sf);
    try expectUnchanged(chrome_db, before_ch);
    try expectSidecarsUnchanged(chromium_sidecars, before_ch_sidecars);
}

test "VAL-CROSS-006 raw values do not leak in debug for each backend" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const firefox = try buildFirefoxProfile(&tmp, &.{.{ .name = "ff", .value = "FF_SECRET_VALUE", .host = "example.com", .path = "/" }});
    defer std.testing.allocator.free(firefox.root);
    defer std.testing.allocator.free(firefox.db);
    const safari_file = try buildSafariBlobFile(&tmp, &.{.{ .domain = "example.com", .name = "sf", .path = "/", .value = "SF_SECRET_VALUE" }});
    defer std.testing.allocator.free(safari_file);
    const chrome_db = try tmpPath(&tmp, "Cookies");
    defer std.testing.allocator.free(chrome_db);
    try buildChromiumDb(chrome_db, &.{.{ .name = "ch", .value = "CH_SECRET_VALUE", .host = "example.com", .path = "/" }});

    const cases = [_]struct { secret: []const u8, argv: []const []const u8 }{
        .{ .secret = "FF_SECRET_VALUE", .argv = &.{ "zig-out/bin/sweetcookie", "export", "--browser", "firefox", "--firefox-profile-root", firefox.root, "--debug" } },
        .{ .secret = "SF_SECRET_VALUE", .argv = &.{ "zig-out/bin/sweetcookie", "export", "--browser", "safari", "--safari-cookies-file", safari_file, "--debug", "--include-expired" } },
        .{ .secret = "CH_SECRET_VALUE", .argv = &.{ "zig-out/bin/sweetcookie", "export", "--browser", "chrome", "--chrome-cookies-db", chrome_db, "--all-domains", "--debug", "--include-expired" } },
    };
    for (cases) |case| {
        const res = try run(std.testing.allocator, case.argv);
        defer std.testing.allocator.free(res.stdout);
        defer std.testing.allocator.free(res.stderr);
        try expectExit0(res);
        try std.testing.expect(std.mem.indexOf(u8, res.stderr, case.secret) == null);
    }
}

test "VAL-CROSS-010 concurrent multi-backend runs do not corrupt source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const firefox = try buildFirefoxProfile(&tmp, &.{.{ .name = "ff", .value = "firefox", .host = "example.com", .path = "/" }});
    defer std.testing.allocator.free(firefox.root);
    defer std.testing.allocator.free(firefox.db);
    const safari_file = try buildSafariBlobFile(&tmp, &.{.{ .domain = "example.com", .name = "sf", .path = "/", .value = "safari" }});
    defer std.testing.allocator.free(safari_file);
    const chrome_db = try tmpPath(&tmp, "Cookies");
    defer std.testing.allocator.free(chrome_db);
    try buildChromiumDb(chrome_db, &.{.{ .name = "ch", .value = "chromium", .host = "example.com", .path = "/" }});
    const firefox_sidecars = try writeSidecars(firefox.db);
    defer freeSidecarPaths(firefox_sidecars);
    const chromium_sidecars = try writeSidecars(chrome_db);
    defer freeSidecarPaths(chromium_sidecars);
    const before_ff = try fileState(firefox.db);
    const before_ff_sidecars = try sidecarStates(firefox_sidecars);
    const before_sf = try fileState(safari_file);
    const before_ch = try fileState(chrome_db);
    const before_ch_sidecars = try sidecarStates(chromium_sidecars);
    const argv = &.{ "zig-out/bin/sweetcookie", "export", "--browser", "firefox", "--firefox-profile-root", firefox.root, "--browser", "safari", "--safari-cookies-file", safari_file, "--browser", "chrome", "--chrome-cookies-db", chrome_db, "--all-domains", "--include-expired" };
    var one = std.process.Child.init(argv, std.testing.allocator);
    var two = std.process.Child.init(argv, std.testing.allocator);
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
    try std.testing.expect(std.mem.indexOf(u8, one_out, "ff") != null);
    try std.testing.expect(std.mem.indexOf(u8, two_out, "ff") != null);
    try expectUnchanged(firefox.db, before_ff);
    try expectSidecarsUnchanged(firefox_sidecars, before_ff_sidecars);
    try expectUnchanged(safari_file, before_sf);
    try expectUnchanged(chrome_db, before_ch);
    try expectSidecarsUnchanged(chromium_sidecars, before_ch_sidecars);
}
