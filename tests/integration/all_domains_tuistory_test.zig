const std = @import("std");

fn tuistoryAvailable() !bool {
    const res = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "tuistory", "--help" },
        .max_output_bytes = 256 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    return res.term == .Exited;
}

fn run(argv: []const []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    });
}

fn expectOk(argv: []const []const u8) !std.process.Child.RunResult {
    const res = try run(argv);
    if (res.term != .Exited or res.term.Exited != 0) {
        std.debug.print("command failed: {any}\nstdout: {s}\nstderr: {s}\n", .{ argv, res.stdout, res.stderr });
        return error.CommandFailed;
    }
    return res;
}

fn closeSession(session: []const u8) void {
    const res = run(&.{ "tuistory", "-s", session, "close" }) catch return;
    std.testing.allocator.free(res.stdout);
    std.testing.allocator.free(res.stderr);
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

fn buildEmptyChromiumDb(db_path: []const u8) !void {
    var child = std.process.Child.init(&.{ "sqlite3", db_path }, std.testing.allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    try child.stdin.?.writeAll(
        \\CREATE TABLE cookies(creation_utc INTEGER NOT NULL DEFAULT 0, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL DEFAULT 0, has_expires INTEGER NOT NULL DEFAULT 1, is_persistent INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1, samesite INTEGER NOT NULL DEFAULT -1, source_scheme INTEGER NOT NULL DEFAULT 0, source_port INTEGER NOT NULL DEFAULT -1, is_same_party INTEGER NOT NULL DEFAULT 0, last_update_utc INTEGER NOT NULL DEFAULT 0);
        \\CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        \\INSERT INTO meta(key,value) VALUES('version','23');
        \\
    );
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

test "tuistory all-domains confirmation declines and accepts" {
    if (!(try tuistoryAvailable())) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmpPath(&tmp, &.{"Cookies"});
    defer std.testing.allocator.free(db_path);
    try buildEmptyChromiumDb(db_path);
    const decline_out = try tmpPath(&tmp, &.{"decline.json"});
    defer std.testing.allocator.free(decline_out);
    const accept_out = try tmpPath(&tmp, &.{"accept.json"});
    defer std.testing.allocator.free(accept_out);

    const decline_session = try std.fmt.allocPrint(std.testing.allocator, "sweetcookie_decline_{d}", .{std.time.nanoTimestamp()});
    defer std.testing.allocator.free(decline_session);
    defer closeSession(decline_session);
    const decline_cmd = try std.fmt.allocPrint(std.testing.allocator, "zig-out/bin/sweetcookie export --browser chrome --chrome-cookies-db {s} --all-domains --output {s}", .{ db_path, decline_out });
    defer std.testing.allocator.free(decline_cmd);
    var launched = try expectOk(&.{ "tuistory", "launch", decline_cmd, "-s", decline_session, "--cwd", "/Users/thinh/Projects/sweetcookie.zig", "--cols", "100", "--rows", "20" });
    std.testing.allocator.free(launched.stdout);
    std.testing.allocator.free(launched.stderr);
    var waited = try expectOk(&.{ "tuistory", "-s", decline_session, "wait", "Broad export of cookies will include credentials", "--timeout", "8000" });
    std.testing.allocator.free(waited.stdout);
    std.testing.allocator.free(waited.stderr);
    const snap = try expectOk(&.{ "tuistory", "-s", decline_session, "snapshot", "--trim" });
    defer std.testing.allocator.free(snap.stdout);
    defer std.testing.allocator.free(snap.stderr);
    try std.testing.expect(std.mem.indexOf(u8, snap.stdout, "Type \"yes\" to continue") != null);
    var typed = try expectOk(&.{ "tuistory", "-s", decline_session, "type", "no" });
    std.testing.allocator.free(typed.stdout);
    std.testing.allocator.free(typed.stderr);
    var pressed = try expectOk(&.{ "tuistory", "-s", decline_session, "press", "enter" });
    std.testing.allocator.free(pressed.stdout);
    std.testing.allocator.free(pressed.stderr);
    std.fs.accessAbsolute(decline_out, .{}) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    const accept_session = try std.fmt.allocPrint(std.testing.allocator, "sweetcookie_accept_{d}", .{std.time.nanoTimestamp()});
    defer std.testing.allocator.free(accept_session);
    defer closeSession(accept_session);
    const accept_cmd = try std.fmt.allocPrint(std.testing.allocator, "zig-out/bin/sweetcookie export --browser chrome --chrome-cookies-db {s} --all-domains --output {s}", .{ db_path, accept_out });
    defer std.testing.allocator.free(accept_cmd);
    launched = try expectOk(&.{ "tuistory", "launch", accept_cmd, "-s", accept_session, "--cwd", "/Users/thinh/Projects/sweetcookie.zig", "--cols", "100", "--rows", "20" });
    std.testing.allocator.free(launched.stdout);
    std.testing.allocator.free(launched.stderr);
    waited = try expectOk(&.{ "tuistory", "-s", accept_session, "wait", "Broad export of cookies will include credentials", "--timeout", "8000" });
    std.testing.allocator.free(waited.stdout);
    std.testing.allocator.free(waited.stderr);
    typed = try expectOk(&.{ "tuistory", "-s", accept_session, "type", "yes" });
    std.testing.allocator.free(typed.stdout);
    std.testing.allocator.free(typed.stderr);
    pressed = try expectOk(&.{ "tuistory", "-s", accept_session, "press", "enter" });
    std.testing.allocator.free(pressed.stdout);
    std.testing.allocator.free(pressed.stderr);
    std.Thread.sleep(250 * std.time.ns_per_ms);
    try std.fs.accessAbsolute(accept_out, .{});
}
