const std = @import("std");
const builtin = @import("builtin");

const exe = "zig-out/bin/sweetcookie";
const page_magic: u32 = 0x0000_0100;
const cookie_header_size: usize = 44;

const SafariCookie = struct {
    domain: []const u8,
    name: []const u8,
    path: []const u8,
    value: []const u8,
    flags: u32 = 0,
    expiry: f64 = 1_021_692_800.0,
    creation: f64 = 0.0,
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

fn buildBlobFile(tmp: *std.testing.TmpDir, entries: []const SafariCookie) ![]u8 {
    var blob = std.ArrayList(u8).empty;
    defer blob.deinit(std.testing.allocator);
    try appendBlob(std.testing.allocator, &blob, &.{entries});
    const path = try tmpPath(tmp, &.{"Cookies.binarycookies"});
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = blob.items });
    return path;
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

test "safari explicit cookies file leaves source unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cookies_file = try buildBlobFile(&tmp, &.{.{ .domain = ".example.com", .name = "sid", .path = "/", .value = "one" }});
    defer std.testing.allocator.free(cookies_file);
    const before = try fileState(cookies_file);
    const tmp_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);

    const res = try runWithTmp(std.testing.allocator, &.{ exe, "export", "--browser", "safari", "--safari-cookies-file", cookies_file }, tmp_root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    var parsed = try parseJson(res.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try expectUnchanged(cookies_file, before);
    try expectNoSnapshots(tmp_root);
}

test "safari url name and expired filters work" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cookies_file = try buildBlobFile(&tmp, &.{
        .{ .domain = ".example.com", .name = "sid", .path = "/app", .value = "keep", .expiry = 1_021_692_800.0 },
        .{ .domain = ".example.com", .name = "sid", .path = "/other", .value = "wrong-path", .expiry = 1_021_692_800.0 },
        .{ .domain = ".example.com", .name = "other", .path = "/app", .value = "wrong-name", .expiry = 1_021_692_800.0 },
        .{ .domain = ".example.com", .name = "old", .path = "/app", .value = "expired", .expiry = 0.0 },
    });
    defer std.testing.allocator.free(cookies_file);

    const filtered = try run(std.testing.allocator, &.{ exe, "export", "--browser", "safari", "--safari-cookies-file", cookies_file, "--url", "https://www.example.com/app/page", "--name", "sid" });
    defer std.testing.allocator.free(filtered.stdout);
    defer std.testing.allocator.free(filtered.stderr);
    try expectExit0(filtered);
    var parsed = try parseJson(filtered.stdout);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try std.testing.expectEqualStrings("keep", parsed.value.array.items[0].object.get("value").?.string);

    const no_expired = try run(std.testing.allocator, &.{ exe, "export", "--browser", "safari", "--safari-cookies-file", cookies_file, "--name", "old" });
    defer std.testing.allocator.free(no_expired.stdout);
    defer std.testing.allocator.free(no_expired.stderr);
    try expectExit0(no_expired);
    var no_expired_json = try parseJson(no_expired.stdout);
    defer no_expired_json.deinit();
    try std.testing.expectEqual(@as(usize, 0), no_expired_json.value.array.items.len);

    const with_expired = try run(std.testing.allocator, &.{ exe, "export", "--browser", "safari", "--safari-cookies-file", cookies_file, "--name", "old", "--include-expired" });
    defer std.testing.allocator.free(with_expired.stdout);
    defer std.testing.allocator.free(with_expired.stderr);
    try expectExit0(with_expired);
    var with_expired_json = try parseJson(with_expired.stdout);
    defer with_expired_json.deinit();
    try std.testing.expectEqual(@as(usize, 1), with_expired_json.value.array.items.len);
    try std.testing.expectEqualStrings("expired", with_expired_json.value.array.items[0].object.get("value").?.string);
}

test "safari without explicit file is gated on darwin and darwin-only elsewhere" {
    const res = try run(std.testing.allocator, &.{ exe, "export", "--browser", "safari" });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 1), res.term.Exited);
    if (builtin.os.tag == .macos) {
        try std.testing.expect(std.mem.indexOf(u8, res.stderr, "SWEETCOOKIE_ALLOW_REAL_BROWSER=1") != null);
    } else {
        try std.testing.expect(std.mem.indexOf(u8, res.stderr, "darwin") != null or std.mem.indexOf(u8, res.stderr, "macOS") != null);
    }
}

fn appendBlob(allocator: std.mem.Allocator, out: *std.ArrayList(u8), pages: []const []const SafariCookie) !void {
    try out.appendSlice(allocator, "cook");
    try appendU32(out, allocator, @intCast(pages.len), .big);

    var encoded_pages = std.ArrayList([]u8).empty;
    defer {
        for (encoded_pages.items) |page| allocator.free(page);
        encoded_pages.deinit(allocator);
    }

    for (pages) |page_cookies| {
        const page = try buildPage(allocator, page_cookies);
        errdefer allocator.free(page);
        try encoded_pages.append(allocator, page);
        try appendU32(out, allocator, @intCast(page.len), .big);
    }

    for (encoded_pages.items) |page| try out.appendSlice(allocator, page);
}

fn buildPage(allocator: std.mem.Allocator, cookies: []const SafariCookie) ![]u8 {
    var page = std.ArrayList(u8).empty;
    errdefer page.deinit(allocator);
    try appendU32(&page, allocator, page_magic, .little);
    try appendU32(&page, allocator, @intCast(cookies.len), .little);
    const offsets_start = page.items.len;
    try page.appendNTimes(allocator, 0, cookies.len * 4);

    for (cookies, 0..) |cookie, index| {
        const offset = page.items.len;
        writeU32At(page.items, offsets_start + index * 4, @intCast(offset), .little);
        try appendCookie(&page, allocator, cookie);
    }

    return page.toOwnedSlice(allocator);
}

fn appendCookie(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cookie: SafariCookie) !void {
    const start = out.items.len;
    try out.appendNTimes(allocator, 0, cookie_header_size);
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

    const size = out.items.len - start;
    const record = out.items[start..][0..size];
    writeU32At(record, 0, @intCast(size), .little);
    writeU32At(record, 4, 0, .little);
    writeU32At(record, 8, cookie.flags, .little);
    writeU32At(record, 12, @intCast(domain_offset), .little);
    writeU32At(record, 16, @intCast(name_offset), .little);
    writeU32At(record, 20, @intCast(path_offset), .little);
    writeU32At(record, 24, @intCast(value_offset), .little);
    writeF64At(record, 28, cookie.expiry);
    writeF64At(record, 36, cookie.creation);
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
