const std = @import("std");
const Cookie = @import("Cookie.zig").Cookie;
const SameSite = @import("Cookie.zig").SameSite;

pub fn parseInlineJson(allocator: std.mem.Allocator, input: []const u8) ![]Cookie {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, input, .{});
    defer parsed.deinit();
    return parseValue(allocator, parsed.value);
}

pub fn parseInlineBase64(allocator: std.mem.Allocator, input: []const u8) ![]Cookie {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(input);
    const decoded = try allocator.alloc(u8, size);
    defer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, input);
    return parseInlineJson(allocator, decoded);
}

pub fn parseInlineFile(allocator: std.mem.Allocator, path: []const u8) ![]Cookie {
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 8 * 1024 * 1024);
    defer allocator.free(content);
    return parseInlineJson(allocator, content);
}

pub fn parseSweetCookiePayload(allocator: std.mem.Allocator, value: std.json.Value) ![]Cookie {
    if (value != .object) return error.InvalidPayload;
    const obj = value.object;
    const cookies_v = obj.get("cookies") orelse return error.InvalidPayload;
    if (cookies_v != .array) return error.InvalidPayload;
    return parseCookieArray(allocator, cookies_v.array.items);
}

fn parseValue(allocator: std.mem.Allocator, value: std.json.Value) ![]Cookie {
    return switch (value) {
        .array => |arr| parseCookieArray(allocator, arr.items),
        .object => |obj| blk: {
            if (obj.get("version") != null and obj.get("cookies") != null) {
                break :blk parseSweetCookiePayload(allocator, value);
            }
            var single = try allocator.alloc(Cookie, 1);
            errdefer allocator.free(single);
            single[0] = try parseCookieObject(allocator, value);
            break :blk single;
        },
        else => error.InvalidJsonShape,
    };
}

fn parseCookieArray(allocator: std.mem.Allocator, items: []const std.json.Value) ![]Cookie {
    var out = try allocator.alloc(Cookie, items.len);
    errdefer allocator.free(out);
    for (items, 0..) |item, i| out[i] = try parseCookieObject(allocator, item);
    return out;
}

fn parseCookieObject(allocator: std.mem.Allocator, value: std.json.Value) !Cookie {
    if (value != .object) return error.InvalidCookie;
    const obj = value.object;
    const name = try getString(obj, "name");
    const cookie_value = try getString(obj, "value");
    const path = getStringOr(obj, "path", "/");
    const secure = getBoolOr(obj, "secure", false);
    const http_only = getBoolOr(obj, "httpOnly", getBoolOr(obj, "http_only", false));
    const expires = getI64OrNull(obj, "expires");
    const same_site = parseSameSite(obj.get("sameSite") orelse obj.get("same_site") orelse .null);

    const raw_domain = if (obj.get("raw_domain")) |raw| try valueToString(raw) else if (obj.get("domain")) |d| try valueToString(d) else return error.MissingDomain;
    return Cookie.fromRawDomain(
        allocator,
        raw_domain,
        name,
        cookie_value,
        path,
        expires,
        secure,
        http_only,
        same_site,
        .{},
    );
}

fn getString(obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    return valueToString(obj.get(key) orelse return error.MissingField);
}

fn getStringOr(obj: std.json.ObjectMap, key: []const u8, default: []const u8) []const u8 {
    const v = obj.get(key) orelse return default;
    return if (v == .string) v.string else default;
}

fn valueToString(v: std.json.Value) ![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => error.InvalidFieldType,
    };
}

fn getBoolOr(obj: std.json.ObjectMap, key: []const u8, default: bool) bool {
    const v = obj.get(key) orelse return default;
    return if (v == .bool) v.bool else default;
}

fn getI64OrNull(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| @intCast(i),
        .float => |f| @intFromFloat(f),
        .null => null,
        else => null,
    };
}

fn parseSameSite(v: std.json.Value) ?SameSite {
    if (v != .string) return null;
    if (std.ascii.eqlIgnoreCase(v.string, "strict")) return .Strict;
    if (std.ascii.eqlIgnoreCase(v.string, "lax")) return .Lax;
    if (std.ascii.eqlIgnoreCase(v.string, "none")) return .None;
    return null;
}

test "VAL-INLINE-001 parse inline JSON array" {
    const cookies = try parseInlineJson(std.testing.allocator, "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\".example.com\",\"path\":\"/\"}]");
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
    try std.testing.expectEqualStrings("a", cookies[0].name);
}

test "VAL-INLINE-002 parse single object" {
    const cookies = try parseInlineJson(std.testing.allocator, "{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\"}");
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
}

test "VAL-INLINE-003 parse base64 JSON" {
    const json = "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\"},{\"name\":\"b\",\"value\":\"2\",\"domain\":\"example.com\",\"path\":\"/\"}]";
    const size = std.base64.standard.Encoder.calcSize(json.len);
    const encoded = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, json);
    const cookies = try parseInlineBase64(std.testing.allocator, encoded);
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(@as(usize, 2), cookies.len);
}

test "VAL-INLINE-004 parse from file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "in.json", .data = "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\"}]" });
    const abs = try tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
    defer std.testing.allocator.free(abs);
    const cookies = try parseInlineFile(std.testing.allocator, abs);
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
}

test "VAL-INLINE-005 parse sweet-cookie payload" {
    const cookies = try parseInlineJson(std.testing.allocator, "{\"version\":1,\"cookies\":[{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\"}],\"targetUrl\":\"https://example.com\"}");
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
}

test "VAL-INLINE-006 preserve leading dot semantics" {
    const cookies = try parseInlineJson(std.testing.allocator, "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\".example.com\",\"path\":\"/\"}]");
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(false, cookies[0].host_only);
    try std.testing.expectEqualStrings(".example.com", cookies[0].raw_domain);
    try std.testing.expectEqualStrings("example.com", cookies[0].domain);
}

test "VAL-INLINE-007 host-only inferred without leading dot" {
    const cookies = try parseInlineJson(std.testing.allocator, "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\"}]");
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(true, cookies[0].host_only);
}

test "VAL-INLINE-008 sameSite case-insensitive" {
    const cookies = try parseInlineJson(std.testing.allocator, "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\",\"sameSite\":\"STRICT\"},{\"name\":\"b\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\",\"sameSite\":\"lax\"},{\"name\":\"c\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\",\"sameSite\":\"None\"}]");
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(SameSite.Strict, cookies[0].same_site.?);
    try std.testing.expectEqual(SameSite.Lax, cookies[1].same_site.?);
    try std.testing.expectEqual(SameSite.None, cookies[2].same_site.?);
}

test "VAL-INLINE-009 reject malformed JSON" {
    try std.testing.expectError(error.SyntaxError, parseInlineJson(std.testing.allocator, "{not json"));
}

test "VAL-INLINE-010 reject malformed base64" {
    _ = parseInlineBase64(std.testing.allocator, "$$$") catch |err| {
        try std.testing.expect(err == error.InvalidCharacter or err == error.InvalidPadding);
        return;
    };
    return error.TestExpectedError;
}

test "VAL-INLINE-011 missing inline file path errors" {
    try std.testing.expectError(error.FileNotFound, parseInlineFile(std.testing.allocator, "/tmp/definitely-missing-sweetcookie.json"));
}

test "VAL-INLINE-012 ignore unknown cookie fields" {
    const cookies = try parseInlineJson(std.testing.allocator, "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\",\"foo\":\"bar\"}]");
    defer freeCookies(std.testing.allocator, cookies);
    try std.testing.expectEqual(@as(usize, 1), cookies.len);
}

test "VAL-INLINE-013 inline file remains unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const data = "[{\"name\":\"a\",\"value\":\"1\",\"domain\":\"example.com\",\"path\":\"/\"}]";
    try tmp.dir.writeFile(.{ .sub_path = "in.json", .data = data });
    const abs = try tmp.dir.realpathAlloc(std.testing.allocator, "in.json");
    defer std.testing.allocator.free(abs);

    const before = try tmp.dir.readFileAlloc(std.testing.allocator, "in.json", 1024);
    defer std.testing.allocator.free(before);
    const cookies = try parseInlineFile(std.testing.allocator, abs);
    defer freeCookies(std.testing.allocator, cookies);
    const after = try tmp.dir.readFileAlloc(std.testing.allocator, "in.json", 1024);
    defer std.testing.allocator.free(after);

    try std.testing.expectEqualStrings(before, after);
}

fn freeCookies(allocator: std.mem.Allocator, cookies: []Cookie) void {
    for (cookies) |c| c.deinit(allocator);
    allocator.free(cookies);
}
