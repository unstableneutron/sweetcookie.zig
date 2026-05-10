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
