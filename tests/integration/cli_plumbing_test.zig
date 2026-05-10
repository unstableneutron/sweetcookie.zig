const std = @import("std");

fn run(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    });
}

test "--version exits 0" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "--version" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), res.term.Exited);
}

test "--help exits 0" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "--help" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), res.term.Exited);
}

test "no args exits 2" {
    const res = try run(std.testing.allocator, &.{"zig-out/bin/sweetcookie"});
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 2), res.term.Exited);
}

test "unknown subcommand exits non-zero" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "nope" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expect(res.term.Exited != 0);
}

test "unknown flag exits non-zero" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--not-a-real-flag" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expect(res.term.Exited != 0);
}

test "export no input exits 1 and message" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 1), res.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "no input source provided") != null);
}

test "malformed inline json reports parse error with line and column" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-json", "{not json" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 1), res.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "parse error") != null);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "line") != null);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "column") != null);
}

test "malformed inline base64 reports base64 wording" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-base64", "$$$" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 1), res.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "base64") != null);
}

test "missing inline file reports not found and path" {
    const missing = "/tmp/definitely-missing-sweetcookie-cli.json";
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", missing });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 1), res.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "not found") != null);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, missing) != null);
}

test "header without url names url flag" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "header", "--inline-json", "[]" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 1), res.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "--url") != null);
}

test "header browser no source exits cleanly without leak diagnostics" {
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "header", "--browser", "chrome", "--url", "https://example.com/", "--all-domains" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expect(res.term.Exited != 0);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "no input source") != null);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "error(gpa)") == null);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, "leak") == null);
}

test "--debug does not leak cookie values to stderr" {
    const secret = "SECRET_VALUE_XYZ";
    const json = "[{\"name\":\"sid\",\"value\":\"" ++ secret ++ "\",\"domain\":\"example.com\",\"path\":\"/\",\"expires\":4102444800}]";
    const res = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--debug", "--inline-json", json, "--format", "lightpanda-json" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), res.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, secret) == null);
}
