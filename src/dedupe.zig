const std = @import("std");
const Cookie = @import("Cookie.zig").Cookie;

pub fn dedupeLastWins(allocator: std.mem.Allocator, cookies: []const Cookie) ![]Cookie {
    var list = std.ArrayList(Cookie).empty;
    defer list.deinit(allocator);

    for (cookies) |cookie| {
        var replaced = false;
        for (list.items) |*existing| {
            if (sameKey(existing.*, cookie)) {
                existing.deinit(allocator);
                existing.* = try dupCookie(allocator, cookie);
                replaced = true;
                break;
            }
        }
        if (!replaced) try list.append(allocator, try dupCookie(allocator, cookie));
    }

    return list.toOwnedSlice(allocator);
}

fn sameKey(a: Cookie, b: Cookie) bool {
    return std.mem.eql(u8, a.name, b.name) and
        std.ascii.eqlIgnoreCase(a.domain, b.domain) and
        std.mem.eql(u8, a.path, b.path);
}

fn dupCookie(allocator: std.mem.Allocator, c: Cookie) !Cookie {
    return Cookie.fromRawDomain(
        allocator,
        c.raw_domain,
        c.name,
        c.value,
        c.path,
        c.expires,
        c.secure,
        c.http_only,
        c.same_site,
        c.source,
    );
}

test "VAL-FILTER-007 dedupe by name domain path last-wins" {
    var in = try std.testing.allocator.alloc(Cookie, 2);
    defer freeCookies(std.testing.allocator, in);
    in[0] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", "a", "first", "/", null, false, false, null, .{});
    in[1] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", "a", "second", "/", null, false, false, null, .{});
    const out = try dedupeLastWins(std.testing.allocator, in);
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expectEqualStrings("second", out[0].value);
}

test "VAL-FILTER-008 dedupe domain comparison case-insensitive" {
    var in = try std.testing.allocator.alloc(Cookie, 2);
    defer freeCookies(std.testing.allocator, in);
    in[0] = try Cookie.fromRawDomain(std.testing.allocator, "Example.com", "a", "first", "/", null, false, false, null, .{});
    in[1] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", "a", "second", "/", null, false, false, null, .{});
    const out = try dedupeLastWins(std.testing.allocator, in);
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 1), out.len);
}

test "VAL-FILTER-009 dedupe path is case-sensitive" {
    var in = try std.testing.allocator.alloc(Cookie, 2);
    defer freeCookies(std.testing.allocator, in);
    in[0] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", "a", "first", "/A", null, false, false, null, .{});
    in[1] = try Cookie.fromRawDomain(std.testing.allocator, "example.com", "a", "second", "/a", null, false, false, null, .{});
    const out = try dedupeLastWins(std.testing.allocator, in);
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 2), out.len);
}

fn freeCookies(allocator: std.mem.Allocator, cookies: []Cookie) void {
    for (cookies) |c| c.deinit(allocator);
    allocator.free(cookies);
}
