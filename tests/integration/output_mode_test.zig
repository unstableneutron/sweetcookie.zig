const std = @import("std");

fn run(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    });
}

fn expectExit0(res: std.process.Child.RunResult) !void {
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), res.term.Exited);
}

fn fixtureJson() []const u8 {
    return "[{\"name\":\"sid\",\"value\":\"secret\",\"domain\":\"example.com\",\"path\":\"/\",\"expires\":4102444800}]";
}

fn tmpPath(tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    return std.fs.path.join(std.testing.allocator, &.{ root, name });
}

fn assertMode0600(path: []const u8) !void {
    if (@import("builtin").os.tag == .windows) return;
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    const stat = try file.stat();
    try std.testing.expectEqual(@as(u32, 0o600), stat.mode & 0o777);
    try std.testing.expect(stat.size > 0);
}

test "VAL-CROSS-007 output mode 0600 across all export formats" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "in.json", .data = fixtureJson() });
    const in_path = try tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
    defer std.testing.allocator.free(in_path);

    const light_path = try tmpPath(&tmp, "lightpanda.json");
    defer std.testing.allocator.free(light_path);
    const light = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "lightpanda-json", "--output", light_path });
    defer std.testing.allocator.free(light.stdout);
    defer std.testing.allocator.free(light.stderr);
    try expectExit0(light);
    try assertMode0600(light_path);

    const sweet_path = try tmpPath(&tmp, "sweet-cookie.json");
    defer std.testing.allocator.free(sweet_path);
    const sweet = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "sweet-cookie-json", "--output", sweet_path });
    defer std.testing.allocator.free(sweet.stdout);
    defer std.testing.allocator.free(sweet.stderr);
    try expectExit0(sweet);
    try assertMode0600(sweet_path);

    const header_path = try tmpPath(&tmp, "cookie-header.txt");
    defer std.testing.allocator.free(header_path);
    const header = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "cookie-header", "--url", "https://example.com/", "--output", header_path });
    defer std.testing.allocator.free(header.stdout);
    defer std.testing.allocator.free(header.stderr);
    try expectExit0(header);
    try assertMode0600(header_path);

    const httpie_path = try tmpPath(&tmp, "httpie.json");
    defer std.testing.allocator.free(httpie_path);
    const httpie = try run(std.testing.allocator, &.{ "zig-out/bin/sweetcookie", "export", "--inline-file", in_path, "--format", "httpie", "--output", httpie_path });
    defer std.testing.allocator.free(httpie.stdout);
    defer std.testing.allocator.free(httpie.stderr);
    try expectExit0(httpie);
    try assertMode0600(httpie_path);
}
