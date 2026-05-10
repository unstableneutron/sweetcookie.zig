const std = @import("std");
const Cookie = @import("../Cookie.zig").Cookie;
const time = @import("../util/time.zig");

const page_magic: u32 = 0x0000_0100;
const cookie_header_size: usize = 44;

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ![]Cookie {
    if (bytes.len < 4) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], "cook")) return error.BadMagic;
    if (bytes.len < 8) return error.Truncated;

    const page_count = readU32BE(bytes, 4);
    const page_table_size = std.math.mul(usize, @as(usize, page_count), 4) catch return error.Truncated;
    const page_table_end = std.math.add(usize, 8, page_table_size) catch return error.Truncated;
    if (bytes.len < page_table_end) return error.Truncated;

    var cookies = std.ArrayList(Cookie).empty;
    errdefer {
        for (cookies.items) |cookie| cookie.deinit(allocator);
        cookies.deinit(allocator);
    }

    var page_start = page_table_end;
    for (0..page_count) |page_index| {
        const page_size = readU32BE(bytes, 8 + page_index * 4);
        const page_end = std.math.add(usize, page_start, @as(usize, page_size)) catch return error.Truncated;
        if (page_end > bytes.len) return error.Truncated;
        try parsePage(allocator, bytes[page_start..page_end], &cookies);
        page_start = page_end;
    }

    return cookies.toOwnedSlice(allocator);
}

fn parsePage(allocator: std.mem.Allocator, page: []const u8, cookies: *std.ArrayList(Cookie)) !void {
    if (page.len < 8) return error.Truncated;
    if (readU32LE(page, 0) != page_magic) return error.BadPageMagic;

    const count = readU32LE(page, 4);
    const offsets_size = std.math.mul(usize, @as(usize, count), 4) catch return error.Truncated;
    const offsets_end = std.math.add(usize, 8, offsets_size) catch return error.Truncated;
    if (offsets_end > page.len) return error.Truncated;

    for (0..count) |i| {
        const offset = readU32LE(page, 8 + i * 4);
        const cookie = try parseCookie(allocator, page, @as(usize, offset));
        var appended = false;
        errdefer if (!appended) cookie.deinit(allocator);
        try cookies.append(allocator, cookie);
        appended = true;
    }
}

fn parseCookie(allocator: std.mem.Allocator, page: []const u8, offset: usize) !Cookie {
    const header_end = std.math.add(usize, offset, cookie_header_size) catch return error.Truncated;
    if (header_end > page.len) return error.Truncated;
    const record = page[offset..];
    const size = readU32LE(record, 0);
    if (size < cookie_header_size) return error.Truncated;
    const end = std.math.add(usize, offset, @as(usize, size)) catch return error.Truncated;
    if (end > page.len) return error.Truncated;
    const cookie_bytes = page[offset..end];

    const flags = readU32LE(cookie_bytes, 8);
    const domain_offset = readU32LE(cookie_bytes, 12);
    const name_offset = readU32LE(cookie_bytes, 16);
    const path_offset = readU32LE(cookie_bytes, 20);
    const value_offset = readU32LE(cookie_bytes, 24);
    const expiry = readF64LE(cookie_bytes, 28);
    const creation = readF64LE(cookie_bytes, 36);
    const expires = try appleSecondsToUnixChecked(expiry);
    _ = try appleSecondsToUnixChecked(creation);

    const domain = try cString(cookie_bytes, domain_offset);
    const name = try cString(cookie_bytes, name_offset);
    const path = try cString(cookie_bytes, path_offset);
    const value = try cString(cookie_bytes, value_offset);

    return Cookie.fromRawDomain(
        allocator,
        domain,
        name,
        value,
        path,
        expires,
        flags & 0x1 != 0,
        flags & 0x4 != 0,
        null,
        .{ .browser = .safari },
    );
}

fn appleSecondsToUnixChecked(apple_seconds: f64) !i64 {
    if (!std.math.isFinite(apple_seconds)) return error.InvalidExpiry;
    const min_i64_float: f64 = @floatFromInt(std.math.minInt(i64));
    const max_i64_float: f64 = @floatFromInt(std.math.maxInt(i64));
    if (apple_seconds < min_i64_float or apple_seconds >= max_i64_float) return error.InvalidExpiry;
    const seconds: i64 = @intFromFloat(apple_seconds);
    return std.math.add(i64, time.apple_unix_offset_seconds, seconds) catch error.InvalidExpiry;
}

fn cString(record: []const u8, raw_offset: u32) ![]const u8 {
    const offset = @as(usize, raw_offset);
    if (offset >= record.len) return error.Truncated;
    const tail = record[offset..];
    const nul = std.mem.indexOfScalar(u8, tail, 0) orelse return error.Truncated;
    return tail[0..nul];
}

fn readU32BE(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .big);
}

fn readU32LE(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn readF64LE(bytes: []const u8, offset: usize) f64 {
    return @bitCast(std.mem.readInt(u64, bytes[offset..][0..8], .little));
}

test "binarycookies empty blob parses to empty cookie list" {
    const blob = "cook" ++ [_]u8{ 0, 0, 0, 0 };
    const cookies = try parse(std.testing.allocator, blob);
    defer std.testing.allocator.free(cookies);
    try std.testing.expectEqual(@as(usize, 0), cookies.len);
}

test "binarycookies rejects bad magic" {
    try std.testing.expectError(error.BadMagic, parse(std.testing.allocator, "cooz"));
}

test "binarycookies rejects truncated page" {
    const blob = "cook" ++ [_]u8{
        0, 0, 0, 1,
        0, 0, 0, 16,
        0, 1, 0, 0,
    };
    try std.testing.expectError(error.Truncated, parse(std.testing.allocator, blob));
}

test "binarycookies rejects invalid Apple date doubles without panicking" {
    const invalids = [_]f64{
        @bitCast(@as(u64, 0x7ff8_0000_0000_0000)),
        @bitCast(@as(u64, 0x7ff0_0000_0000_0000)),
        @bitCast(@as(u64, 0xfff0_0000_0000_0000)),
        @as(f64, @floatFromInt(std.math.maxInt(i64))) * 2.0,
    };
    for (invalids) |expiry| {
        var blob = std.ArrayList(u8).empty;
        defer blob.deinit(std.testing.allocator);
        try appendBlob(std.testing.allocator, &blob, &.{&.{.{ .domain = "example.com", .name = "sid", .path = "/", .value = "abc", .expiry = expiry }}});
        try std.testing.expectError(error.InvalidExpiry, parse(std.testing.allocator, blob.items));
    }
}

test "binarycookies rejects invalid creation double without panicking" {
    var blob = std.ArrayList(u8).empty;
    defer blob.deinit(std.testing.allocator);
    try appendBlob(std.testing.allocator, &blob, &.{&.{.{ .domain = "example.com", .name = "sid", .path = "/", .value = "abc", .creation = @bitCast(@as(u64, 0x7ff8_0000_0000_0000)) }}});
    try std.testing.expectError(error.InvalidExpiry, parse(std.testing.allocator, blob.items));
}

test "binarycookies deinitializes parsed cookie when append fails" {
    var blob = std.ArrayList(u8).empty;
    defer blob.deinit(std.testing.allocator);
    try appendBlob(std.testing.allocator, &blob, &.{&.{.{ .domain = "example.com", .name = "sid", .path = "/", .value = "abc" }}});

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 5 });
    try std.testing.expectError(error.OutOfMemory, parse(failing.allocator(), blob.items));
    try std.testing.expect(failing.has_induced_failure);
}

test "binarycookies parser handles required page, flag, and domain shapes" {
    var blob = std.ArrayList(u8).empty;
    defer blob.deinit(std.testing.allocator);
    try appendBlob(std.testing.allocator, &blob, &.{
        &.{
            .{ .domain = ".example.com", .name = "secure", .path = "/", .value = "1", .flags = 1, .expiry = 0.0 },
            .{ .domain = "example.org", .name = "http", .path = "/a", .value = "2", .flags = 4, .expiry = 694_224_000.0 },
        },
        &.{
            .{ .domain = ".example.net", .name = "both", .path = "/", .value = "3", .flags = 5, .expiry = 0.0 },
            .{ .domain = "host.test", .name = "neither", .path = "/", .value = "4", .flags = 0, .expiry = 0.0 },
        },
    });
    const cookies = try parse(std.testing.allocator, blob.items);
    defer {
        for (cookies) |cookie| cookie.deinit(std.testing.allocator);
        std.testing.allocator.free(cookies);
    }
    try std.testing.expectEqual(@as(usize, 4), cookies.len);
    try std.testing.expectEqualStrings("secure", cookies[0].name);
    try std.testing.expect(cookies[0].secure);
    try std.testing.expect(!cookies[0].http_only);
    try std.testing.expectEqual(@as(i64, 978_307_200), cookies[0].expires.?);
    try std.testing.expect(!cookies[0].host_only);
    try std.testing.expectEqualStrings("example.com", cookies[0].domain);
    try std.testing.expectEqualStrings(".example.com", cookies[0].raw_domain);
    try std.testing.expectEqualStrings("http", cookies[1].name);
    try std.testing.expect(!cookies[1].secure);
    try std.testing.expect(cookies[1].http_only);
    try std.testing.expectEqual(@as(i64, 1_672_531_200), cookies[1].expires.?);
    try std.testing.expectEqualStrings("both", cookies[2].name);
    try std.testing.expect(cookies[2].secure);
    try std.testing.expect(cookies[2].http_only);
    try std.testing.expectEqualStrings("neither", cookies[3].name);
    try std.testing.expect(!cookies[3].secure);
    try std.testing.expect(!cookies[3].http_only);
    try std.testing.expect(cookies[3].host_only);
}

test "binarycookies single page single cookie parses" {
    var blob = std.ArrayList(u8).empty;
    defer blob.deinit(std.testing.allocator);
    try appendBlob(std.testing.allocator, &blob, &.{&.{.{ .domain = "example.com", .name = "sid", .path = "/", .value = "abc" }}});
    const cookies = try parse(std.testing.allocator, blob.items);
    defer {
        for (cookies) |cookie| cookie.deinit(std.testing.allocator);
        std.testing.allocator.free(cookies);
    }
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
    try std.testing.expectEqualStrings("sid", cookies[0].name);
}

test "binarycookies multi-cookie page preserves all cookies in order" {
    var blob = std.ArrayList(u8).empty;
    defer blob.deinit(std.testing.allocator);
    try appendBlob(std.testing.allocator, &blob, &.{&.{
        .{ .domain = "example.com", .name = "a", .path = "/", .value = "1" },
        .{ .domain = "example.com", .name = "b", .path = "/", .value = "2" },
        .{ .domain = "example.com", .name = "c", .path = "/", .value = "3" },
        .{ .domain = "example.com", .name = "d", .path = "/", .value = "4" },
        .{ .domain = "example.com", .name = "e", .path = "/", .value = "5" },
    }});
    const cookies = try parse(std.testing.allocator, blob.items);
    defer {
        for (cookies) |cookie| cookie.deinit(std.testing.allocator);
        std.testing.allocator.free(cookies);
    }
    try std.testing.expectEqual(@as(usize, 5), cookies.len);
    try std.testing.expectEqualStrings("a", cookies[0].name);
    try std.testing.expectEqualStrings("e", cookies[4].name);
}

const FixtureCookie = struct {
    domain: []const u8,
    name: []const u8,
    path: []const u8,
    value: []const u8,
    flags: u32 = 0,
    expiry: f64 = 0.0,
    creation: f64 = 0.0,
};

fn appendBlob(allocator: std.mem.Allocator, out: *std.ArrayList(u8), pages: []const []const FixtureCookie) !void {
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

fn buildPage(allocator: std.mem.Allocator, cookies: []const FixtureCookie) ![]u8 {
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

fn appendCookie(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cookie: FixtureCookie) !void {
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
