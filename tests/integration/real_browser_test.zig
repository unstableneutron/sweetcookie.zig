const std = @import("std");
const builtin = @import("builtin");

const exe = "zig-out/bin/sweetcookie";

fn runWithHome(allocator: std.mem.Allocator, argv: []const []const u8, home: []const u8, tmpdir: []const u8) !std.process.Child.RunResult {
    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    try env.put("HOME", home);
    try env.put("TMPDIR", tmpdir);
    try env.put("SWEETCOOKIE_ALLOW_REAL_BROWSER", "1");
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

fn runSql(sql: []const u8, db_path: []const u8) !void {
    var child = std.process.Child.init(&.{ "sqlite3", db_path }, std.testing.allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    try child.stdin.?.writeAll(sql);
    child.stdin.?.close();
    child.stdin = null;
    const stderr = try child.stderr.?.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(stderr);
    const term = try child.wait();
    if (term != .Exited or term.Exited != 0) {
        std.debug.print("sqlite3 stderr: {s}\n", .{stderr});
        return error.SqliteFailed;
    }
}

fn buildChromiumDb(db_path: []const u8) !void {
    try runSql(
        \\CREATE TABLE cookies(creation_utc INTEGER NOT NULL DEFAULT 0, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL DEFAULT 0, has_expires INTEGER NOT NULL DEFAULT 1, is_persistent INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1, samesite INTEGER NOT NULL DEFAULT -1, source_scheme INTEGER NOT NULL DEFAULT 0, source_port INTEGER NOT NULL DEFAULT -1, is_same_party INTEGER NOT NULL DEFAULT 0, last_update_utc INTEGER NOT NULL DEFAULT 0);
        \\CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        \\INSERT INTO meta(key,value) VALUES('version','23');
        \\INSERT INTO cookies(host_key,name,value,encrypted_value,path,expires_utc,is_secure,is_httponly,has_expires,is_persistent,samesite) VALUES('example.com','chrome','ok',X'','/',13350000000000000,0,0,1,1,1);
        \\
    , db_path);
}

fn buildFirefoxDb(db_path: []const u8) !void {
    try runSql(
        \\CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0);
        \\INSERT INTO moz_cookies(id, originAttributes, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, inBrowserElement, sameSite, rawSameSite, schemeMap) VALUES(1, '', 'firefox', 'ok', 'example.com', '/', 2000000000, 0, 0, 0, 0, 0, 1, 1, 0);
        \\
    , db_path);
}

fn backupCount(tmpdir: []const u8, browser: []const u8) !usize {
    var count: usize = 0;
    var dir = try std.fs.openDirAbsolute(tmpdir, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    const suffix = try std.fmt.allocPrint(std.testing.allocator, "-{s}.tar", .{browser});
    defer std.testing.allocator.free(suffix);
    while (try it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.name, "sweetcookie-backup-") and std.mem.endsWith(u8, entry.name, suffix)) count += 1;
    }
    return count;
}

fn expectBackup(tmpdir: []const u8, browser: []const u8, stderr: []const u8) !void {
    try std.testing.expectEqual(@as(usize, 1), try backupCount(tmpdir, browser));
    try std.testing.expect(std.mem.indexOf(u8, stderr, "backup written to") != null);
}

test "real-browser gate creates chromium backup using HOME override" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);
    try tmp.dir.makePath("Library/Application Support/Google/Chrome/Default");
    const db_path = try tmpPath(&tmp, &.{ "Library", "Application Support", "Google", "Chrome", "Default", "Cookies" });
    defer std.testing.allocator.free(db_path);
    try buildChromiumDb(db_path);

    const res = try runWithHome(std.testing.allocator, &.{ exe, "export", "--browser", "chrome", "--all-domains", "--include-expired" }, home, home);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try expectBackup(home, "chrome", res.stderr);
}

test "real-browser gate creates firefox backup using HOME override" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);
    try tmp.dir.makePath("Library/Application Support/Firefox/abcd.default");
    try tmp.dir.writeFile(.{ .sub_path = "Library/Application Support/Firefox/profiles.ini", .data = 
        \\[Profile0]
        \\Name=default
        \\IsRelative=1
        \\Path=abcd.default
        \\Default=1
        \\
    });
    const db_path = try tmpPath(&tmp, &.{ "Library", "Application Support", "Firefox", "abcd.default", "cookies.sqlite" });
    defer std.testing.allocator.free(db_path);
    try buildFirefoxDb(db_path);

    const res = try runWithHome(std.testing.allocator, &.{ exe, "export", "--browser", "firefox", "--include-expired" }, home, home);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try expectBackup(home, "firefox", res.stderr);
}

test "real-browser gate creates safari backup using HOME override" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);
    try tmp.dir.makePath("Library/Containers/com.apple.Safari/Data/Library/Cookies");
    try tmp.dir.writeFile(.{ .sub_path = "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies", .data = "cook\x00\x00\x00\x00" });

    const res = try runWithHome(std.testing.allocator, &.{ exe, "export", "--browser", "safari", "--include-expired" }, home, home);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try expectBackup(home, "safari", res.stderr);
}
