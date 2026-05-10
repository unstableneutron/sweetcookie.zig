const std = @import("std");
const Cookie = @import("Cookie.zig").Cookie;
const filter = @import("filter.zig");

pub const ExportMeta = struct {
    generated_at_unix: i64,
    target_url: ?[]const u8 = null,
    origins: []const []const u8 = &.{},
};

pub const NetscapeUnencodable = struct {
    name: []const u8,
    field: []const u8,
    byte: u8,
};

pub fn writeLightpandaJson(writer: anytype, cookies: []const Cookie) !void {
    const sorted = try sortedIndexes(std.heap.page_allocator, cookies);
    defer std.heap.page_allocator.free(sorted);

    try writer.writeByte('[');
    for (sorted, 0..) |idx, i| {
        if (i > 0) try writer.writeByte(',');
        const cookie = cookies[idx];
        try writer.writeByte('{');
        try writeField(writer, "name", cookie.name);
        try writer.writeByte(',');
        try writeField(writer, "value", cookie.value);
        try writer.writeByte(',');
        try writeField(writer, "domain", cookie.raw_domain);
        try writer.writeByte(',');
        try writeField(writer, "path", cookie.path);
        try writer.writeByte(',');
        try writer.writeAll("\"expires\":");
        if (cookie.expires) |expires| {
            try writer.print("{d}", .{expires});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeByte(',');
        try writer.writeAll("\"secure\":");
        try writer.writeAll(if (cookie.secure) "true" else "false");
        try writer.writeByte(',');
        try writer.writeAll("\"httpOnly\":");
        try writer.writeAll(if (cookie.http_only) "true" else "false");
        try writer.writeByte(',');
        try writer.writeAll("\"sameSite\":");
        if (cookie.same_site) |same_site| {
            try writeJsonString(writer, sameSiteText(same_site));
        } else {
            try writer.writeAll("null");
        }
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

pub fn writeNetscapeJar(writer: anytype, cookies: []const Cookie) !void {
    if (firstNetscapeUnencodable(cookies) != null) return error.NetscapeUnencodableValue;

    const sorted = try sortedIndexes(std.heap.page_allocator, cookies);
    defer std.heap.page_allocator.free(sorted);

    try writer.writeAll("# Netscape HTTP Cookie File\n");
    for (sorted) |idx| {
        const cookie = cookies[idx];
        try writer.print("{s}\t{s}\t{s}\t{s}\t", .{
            cookie.raw_domain,
            if (std.mem.startsWith(u8, cookie.raw_domain, ".")) "TRUE" else "FALSE",
            cookie.path,
            if (cookie.secure) "TRUE" else "FALSE",
        });
        if (cookie.expires) |expires| {
            try writer.print("{d}", .{expires});
        } else {
            try writer.writeByte('0');
        }
        try writer.print("\t{s}\t{s}\n", .{ cookie.name, cookie.value });
    }
}

pub fn firstNetscapeUnencodable(cookies: []const Cookie) ?NetscapeUnencodable {
    for (cookies) |cookie| {
        if (firstControlByte(cookie.name)) |byte| return .{ .name = cookie.name, .field = "name", .byte = byte };
        if (firstControlByte(cookie.value)) |byte| return .{ .name = cookie.name, .field = "value", .byte = byte };
    }
    return null;
}

pub fn writeSweetCookieJson(writer: anytype, cookies: []const Cookie, meta: ExportMeta) !void {
    const sorted = try sortedIndexes(std.heap.page_allocator, cookies);
    defer std.heap.page_allocator.free(sorted);

    var generated_at_buf: [32]u8 = undefined;
    const generated_at = try formatIso8601(meta.generated_at_unix, &generated_at_buf);

    try writer.writeByte('{');
    try writer.writeAll("\"version\":1,");
    try writeField(writer, "generatedAt", generated_at);
    try writer.writeByte(',');
    try writeField(writer, "source", "sweetcookie.zig");
    if (meta.target_url) |target_url| {
        try writer.writeByte(',');
        try writeField(writer, "targetUrl", target_url);
    }
    if (meta.origins.len > 0) {
        try writer.writeAll(",\"origins\":");
        try writer.writeByte('[');
        for (meta.origins, 0..) |origin, i| {
            if (i > 0) try writer.writeByte(',');
            try writeJsonString(writer, origin);
        }
        try writer.writeByte(']');
    }
    try writer.writeAll(",\"cookies\":[");
    for (sorted, 0..) |idx, i| {
        if (i > 0) try writer.writeByte(',');
        const cookie = cookies[idx];
        try writer.writeByte('{');
        try writeField(writer, "name", cookie.name);
        try writer.writeByte(',');
        try writeField(writer, "value", cookie.value);
        try writer.writeByte(',');
        try writeField(writer, "domain", cookie.domain);
        try writer.writeByte(',');
        try writeField(writer, "raw_domain", cookie.raw_domain);
        try writer.writeByte(',');
        try writer.writeAll("\"host_only\":");
        try writer.writeAll(if (cookie.host_only) "true" else "false");
        try writer.writeByte(',');
        try writeField(writer, "path", cookie.path);
        try writer.writeByte(',');
        try writer.writeAll("\"expires\":");
        if (cookie.expires) |expires| {
            try writer.print("{d}", .{expires});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeByte(',');
        try writer.writeAll("\"secure\":");
        try writer.writeAll(if (cookie.secure) "true" else "false");
        try writer.writeByte(',');
        try writer.writeAll("\"httpOnly\":");
        try writer.writeAll(if (cookie.http_only) "true" else "false");
        try writer.writeByte(',');
        try writer.writeAll("\"sameSite\":");
        if (cookie.same_site) |same_site| {
            try writeJsonString(writer, sameSiteText(same_site));
        } else {
            try writer.writeAll("null");
        }
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
}

pub fn writeCookieHeader(writer: anytype, cookies: []const Cookie, url: []const u8) !void {
    const filtered = try filter.filterByUrl(std.heap.page_allocator, cookies, url);
    defer freeCookies(std.heap.page_allocator, filtered);
    const sorted = try sortedIndexes(std.heap.page_allocator, filtered);
    defer std.heap.page_allocator.free(sorted);

    for (sorted, 0..) |idx, i| {
        if (i > 0) try writer.writeAll("; ");
        const cookie = filtered[idx];
        try writer.print("{s}={s}", .{ cookie.name, cookie.value });
    }
}

fn writeField(writer: anytype, key: []const u8, value: []const u8) !void {
    try writeJsonString(writer, key);
    try writer.writeByte(':');
    try writeJsonString(writer, value);
}

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        else => try writer.writeByte(c),
    };
    try writer.writeByte('"');
}

fn firstControlByte(value: []const u8) ?u8 {
    for (value) |byte| switch (byte) {
        '\t', '\n', '\r' => return byte,
        else => {},
    };
    return null;
}

fn sameSiteText(same_site: @import("Cookie.zig").SameSite) []const u8 {
    return switch (same_site) {
        .Strict => "Strict",
        .Lax => "Lax",
        .None => "None",
    };
}

fn formatIso8601(ts: i64, buf: []u8) ![]const u8 {
    const seconds: u64 = @intCast(if (ts < 0) 0 else ts);
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        @intFromEnum(month_day.month) + 1,
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

fn sortedIndexes(allocator: std.mem.Allocator, cookies: []const Cookie) ![]usize {
    const indexes = try allocator.alloc(usize, cookies.len);
    for (indexes, 0..) |*idx, i| idx.* = i;
    for (indexes, 0..) |_, i| {
        var j = i;
        while (j > 0 and compare(cookies[indexes[j - 1]], cookies[indexes[j]]) == .gt) : (j -= 1) {
            const tmp = indexes[j - 1];
            indexes[j - 1] = indexes[j];
            indexes[j] = tmp;
        }
    }
    return indexes;
}

fn compare(a: Cookie, b: Cookie) std.math.Order {
    const by_name = std.mem.order(u8, a.name, b.name);
    if (by_name != .eq) return by_name;
    const by_domain = compareCaseInsensitive(a.domain, b.domain);
    if (by_domain != .eq) return by_domain;
    return std.mem.order(u8, a.path, b.path);
}

fn compareCaseInsensitive(a: []const u8, b: []const u8) std.math.Order {
    const len = @min(a.len, b.len);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const ca = std.ascii.toLower(a[i]);
        const cb = std.ascii.toLower(b[i]);
        if (ca < cb) return .lt;
        if (ca > cb) return .gt;
    }
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    return .eq;
}

test "VAL-EXPORT-001 and VAL-EXPORT-002 lightpanda-json bare array preserves dotted domain" {
    const cookies = try testCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, cookies);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try writeLightpandaJson(out.writer(std.testing.allocator), cookies);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out.items, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .array);
    try std.testing.expectEqualStrings(".example.com", parsed.value.array.items[0].object.get("domain").?.string);
}

test "VAL-EXPORT-003 and VAL-EXPORT-004 sweet-cookie-json metadata plus host_only/raw_domain" {
    const cookies = try testCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, cookies);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try writeSweetCookieJson(out.writer(std.testing.allocator), cookies, .{ .generated_at_unix = 0, .target_url = "https://example.com", .origins = &.{ "https://example.com", "https://www.example.com" } });
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out.items, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("version").?.integer);
    try std.testing.expectEqualStrings("sweetcookie.zig", parsed.value.object.get("source").?.string);
    try std.testing.expect(parsed.value.object.get("generatedAt") != null);
    const first_cookie = parsed.value.object.get("cookies").?.array.items[0];
    try std.testing.expect(first_cookie.object.get("host_only") != null);
    try std.testing.expect(first_cookie.object.get("raw_domain") != null);
}

test "VAL-EXPORT-005 and VAL-EXPORT-006 cookie header only includes matching cookies" {
    const cookies = try testCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, cookies);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try writeCookieHeader(out.writer(std.testing.allocator), cookies, "https://example.com/");
    try std.testing.expectEqualStrings("a=1", out.items);
}

test "VAL-EXPORT-012 lightpanda determinism is byte-identical" {
    const cookies = try testCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, cookies);
    var out1 = std.ArrayList(u8).empty;
    var out2 = std.ArrayList(u8).empty;
    defer out1.deinit(std.testing.allocator);
    defer out2.deinit(std.testing.allocator);
    try writeLightpandaJson(out1.writer(std.testing.allocator), cookies);
    try writeLightpandaJson(out2.writer(std.testing.allocator), cookies);
    try std.testing.expectEqualStrings(out1.items, out2.items);
}

test "VAL-EXPORT-013 sweet-cookie determinism differs only in generatedAt" {
    const cookies = try testCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, cookies);
    var out1 = std.ArrayList(u8).empty;
    var out2 = std.ArrayList(u8).empty;
    defer out1.deinit(std.testing.allocator);
    defer out2.deinit(std.testing.allocator);
    try writeSweetCookieJson(out1.writer(std.testing.allocator), cookies, .{ .generated_at_unix = 1 });
    try writeSweetCookieJson(out2.writer(std.testing.allocator), cookies, .{ .generated_at_unix = 2 });
    var p1 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out1.items, .{});
    defer p1.deinit();
    var p2 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out2.items, .{});
    defer p2.deinit();
    const generated_1 = p1.value.object.get("generatedAt").?.string;
    const generated_2 = p2.value.object.get("generatedAt").?.string;
    try std.testing.expect(!std.mem.eql(u8, generated_1, generated_2));
    try std.testing.expectEqual(@as(i64, 1), p1.value.object.get("version").?.integer);
    try std.testing.expectEqual(@as(i64, 1), p2.value.object.get("version").?.integer);
    try std.testing.expectEqualStrings("sweetcookie.zig", p1.value.object.get("source").?.string);
    try std.testing.expectEqualStrings("sweetcookie.zig", p2.value.object.get("source").?.string);
    const c1 = p1.value.object.get("cookies").?.array.items;
    const c2 = p2.value.object.get("cookies").?.array.items;
    try std.testing.expectEqual(c1.len, c2.len);
    try std.testing.expectEqualStrings(c1[0].object.get("name").?.string, c2[0].object.get("name").?.string);
    try std.testing.expectEqualStrings(c1[0].object.get("raw_domain").?.string, c2[0].object.get("raw_domain").?.string);
}

test "VAL-NETSCAPE-001 through VAL-NETSCAPE-011 writes exact rows" {
    var cookies = try std.testing.allocator.alloc(Cookie, 3);
    defer freeCookies(std.testing.allocator, cookies);
    cookies[0] = try Cookie.fromRawDomain(std.testing.allocator, ".example.com", "sid", "abc", "/", 1750000000, true, true, .Lax, .{});
    cookies[1] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", "host", "def", "/app", null, false, false, null, .{});
    cookies[2] = try Cookie.fromRawDomain(std.testing.allocator, "other.com", "zzz", "", "/", null, false, false, null, .{});

    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try writeNetscapeJar(out.writer(std.testing.allocator), cookies);

    try std.testing.expect(!std.mem.containsAtLeast(u8, out.items, 1, "\r"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, out.items, 1, "#HttpOnly_"));
    try std.testing.expectEqualStrings(
        "# Netscape HTTP Cookie File\nexample.com\tFALSE\t/app\tFALSE\t0\thost\tdef\n.example.com\tTRUE\t/\tTRUE\t1750000000\tsid\tabc\nother.com\tFALSE\t/\tFALSE\t0\tzzz\t\n",
        out.items,
    );

    var line_it = std.mem.splitScalar(u8, out.items, '\n');
    _ = line_it.next().?;
    while (line_it.next()) |line| {
        if (line.len == 0) continue;
        try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, line, "\t"));
    }
}

test "VAL-NETSCAPE-012 through VAL-NETSCAPE-014 rejects tab lf cr in name and value" {
    const bad_inputs = [_]struct {
        name: []const u8,
        value: []const u8,
    }{
        .{ .name = "tab", .value = "a\tb" },
        .{ .name = "lf", .value = "a\nb" },
        .{ .name = "cr", .value = "a\rb" },
        .{ .name = "bad\tname", .value = "ok" },
    };
    for (bad_inputs) |bad| {
        var cookies = try std.testing.allocator.alloc(Cookie, 1);
        defer freeCookies(std.testing.allocator, cookies);
        cookies[0] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", bad.name, bad.value, "/", null, false, false, null, .{});
        var out = std.ArrayList(u8).empty;
        defer out.deinit(std.testing.allocator);
        try std.testing.expectError(error.NetscapeUnencodableValue, writeNetscapeJar(out.writer(std.testing.allocator), cookies));
    }
}

test "VAL-NETSCAPE-016 and VAL-NETSCAPE-017 sorts by name lowercased domain path deterministically" {
    var cookies = try std.testing.allocator.alloc(Cookie, 4);
    defer freeCookies(std.testing.allocator, cookies);
    cookies[0] = try Cookie.fromRawDomain(std.testing.allocator, "z.example", "b", "1", "/", null, false, false, null, .{});
    cookies[1] = try Cookie.fromRawDomain(std.testing.allocator, "Example.com", "a", "2", "/b", null, false, false, null, .{});
    cookies[2] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", "a", "3", "/a", null, false, false, null, .{});
    cookies[3] = try Cookie.fromRawDomain(std.testing.allocator, "alpha.example", "a", "4", "/", null, false, false, null, .{});

    var out1 = std.ArrayList(u8).empty;
    var out2 = std.ArrayList(u8).empty;
    defer out1.deinit(std.testing.allocator);
    defer out2.deinit(std.testing.allocator);
    try writeNetscapeJar(out1.writer(std.testing.allocator), cookies);
    try writeNetscapeJar(out2.writer(std.testing.allocator), cookies);
    try std.testing.expectEqualStrings(out1.items, out2.items);
    try std.testing.expectEqualStrings(
        "# Netscape HTTP Cookie File\nalpha.example\tFALSE\t/\tFALSE\t0\ta\t4\nexample.com\tFALSE\t/a\tFALSE\t0\ta\t3\nExample.com\tFALSE\t/b\tFALSE\t0\ta\t2\nz.example\tFALSE\t/\tFALSE\t0\tb\t1\n",
        out1.items,
    );
}

test "VAL-NETSCAPE-018 empty input is header only" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try writeNetscapeJar(out.writer(std.testing.allocator), &.{});
    try std.testing.expectEqualStrings("# Netscape HTTP Cookie File\n", out.items);
}

fn testCookies(allocator: std.mem.Allocator) ![]Cookie {
    var cookies = try allocator.alloc(Cookie, 2);
    cookies[0] = try Cookie.fromRawDomain(allocator, ".example.com", "a", "1", "/", 100, false, false, .Lax, .{});
    cookies[1] = try Cookie.fromRawDomain(allocator, "other.com", "b", "2", "/", 100, false, false, .Lax, .{});
    return cookies;
}

fn freeCookies(allocator: std.mem.Allocator, cookies: []Cookie) void {
    for (cookies) |c| c.deinit(allocator);
    allocator.free(cookies);
}
