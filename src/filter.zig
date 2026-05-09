const std = @import("std");
const Cookie = @import("Cookie.zig").Cookie;

pub fn filterByNames(allocator: std.mem.Allocator, cookies: []const Cookie, names: []const []const u8) ![]Cookie {
    if (names.len == 0) return dupCookies(allocator, cookies);
    var list = std.ArrayList(Cookie).empty;
    defer list.deinit(allocator);
    for (cookies) |cookie| {
        for (names) |name| {
            if (std.mem.eql(u8, cookie.name, name)) {
                try list.append(allocator, try dupCookie(allocator, cookie));
                break;
            }
        }
    }
    return list.toOwnedSlice(allocator);
}

pub fn filterExpired(allocator: std.mem.Allocator, cookies: []const Cookie, include_expired: bool, now: i64) ![]Cookie {
    if (include_expired) return dupCookies(allocator, cookies);
    var list = std.ArrayList(Cookie).empty;
    defer list.deinit(allocator);
    for (cookies) |cookie| {
        if (cookie.expires) |ts| {
            if (ts <= now) continue;
        }
        try list.append(allocator, try dupCookie(allocator, cookie));
    }
    return list.toOwnedSlice(allocator);
}

pub fn filterByUrl(allocator: std.mem.Allocator, cookies: []const Cookie, url: ?[]const u8) ![]Cookie {
    if (url == null) return dupCookies(allocator, cookies);
    const parsed = try std.Uri.parse(url.?);
    const host = parsed.host orelse return error.InvalidUrl;
    var host_buf: [128]u8 = undefined;
    const host_text = try hostToText(host, &host_buf);
    const req_path = if (parsed.path.percent_encoded.len == 0) "/" else parsed.path.percent_encoded;
    const is_https = std.ascii.eqlIgnoreCase(parsed.scheme, "https");

    var list = std.ArrayList(Cookie).empty;
    defer list.deinit(allocator);
    for (cookies) |cookie| {
        if (!domainMatches(cookie, host_text)) continue;
        if (!pathMatches(cookie.path, req_path)) continue;
        if (cookie.secure and !is_https) continue;
        try list.append(allocator, try dupCookie(allocator, cookie));
    }
    return list.toOwnedSlice(allocator);
}

pub fn filterByOrigins(allocator: std.mem.Allocator, cookies: []const Cookie, origins: []const []const u8) ![]Cookie {
    if (origins.len == 0) return dupCookies(allocator, cookies);
    var list = std.ArrayList(Cookie).empty;
    defer list.deinit(allocator);
    for (cookies) |cookie| {
        var matched = false;
        for (origins) |origin| {
            const parsed = std.Uri.parse(origin) catch continue;
            const host = parsed.host orelse continue;
            var host_buf: [128]u8 = undefined;
            const host_text = hostToText(host, &host_buf) catch continue;
            const req_path = if (parsed.path.percent_encoded.len == 0) "/" else parsed.path.percent_encoded;
            const is_https = std.ascii.eqlIgnoreCase(parsed.scheme, "https");
            if (domainMatches(cookie, host_text) and pathMatches(cookie.path, req_path) and (!cookie.secure or is_https)) {
                matched = true;
                break;
            }
        }
        if (matched) try list.append(allocator, try dupCookie(allocator, cookie));
    }
    return list.toOwnedSlice(allocator);
}

fn domainMatches(cookie: Cookie, host: []const u8) bool {
    if (cookie.host_only) return std.ascii.eqlIgnoreCase(cookie.domain, host);
    if (std.ascii.eqlIgnoreCase(cookie.domain, host)) return true;
    if (host.len <= cookie.domain.len) return false;
    if (!std.ascii.eqlIgnoreCase(host[host.len - cookie.domain.len ..], cookie.domain)) return false;
    return host[host.len - cookie.domain.len - 1] == '.';
}

fn pathMatches(cookie_path: []const u8, req_path: []const u8) bool {
    return std.mem.startsWith(u8, req_path, cookie_path);
}

fn hostToText(host: std.Uri.Component, buf: []u8) ![]const u8 {
    _ = buf;
    return switch (host) {
        .raw => |h| h,
        .percent_encoded => |h| h,
    };
}

fn dupCookies(allocator: std.mem.Allocator, cookies: []const Cookie) ![]Cookie {
    var out = try allocator.alloc(Cookie, cookies.len);
    errdefer allocator.free(out);
    for (cookies, 0..) |cookie, i| out[i] = try dupCookie(allocator, cookie);
    return out;
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

test "VAL-FILTER-001 name allowlist single" {
    const in = try makeCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, in);
    const out = try filterByNames(std.testing.allocator, in, &.{"session"});
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expectEqualStrings("session", out[0].name);
}

test "VAL-FILTER-002 name allowlist multiple OR" {
    const in = try makeCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, in);
    const out = try filterByNames(std.testing.allocator, in, &.{ "session", "csrf" });
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 2), out.len);
}

test "VAL-FILTER-003 url host path secure scope" {
    const in = try makeCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, in);
    const out = try filterByUrl(std.testing.allocator, in, "https://example.com/foo");
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 3), out.len);
}

test "VAL-FILTER-004 origins multiple values" {
    const in = try makeCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, in);
    const out = try filterByOrigins(std.testing.allocator, in, &.{ "https://nope.com/", "https://example.com/foo" });
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 3), out.len);
}

test "VAL-FILTER-005 default excludes expired" {
    const in = try makeCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, in);
    const out = try filterExpired(std.testing.allocator, in, false, 100);
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 3), out.len);
}

test "VAL-FILTER-006 include_expired includes them" {
    const in = try makeCookies(std.testing.allocator);
    defer freeCookies(std.testing.allocator, in);
    const out = try filterExpired(std.testing.allocator, in, true, 100);
    defer freeCookies(std.testing.allocator, out);
    try std.testing.expectEqual(@as(usize, 4), out.len);
}

fn makeCookies(allocator: std.mem.Allocator) ![]Cookie {
    var out = try allocator.alloc(Cookie, 4);
    out[0] = try Cookie.fromRawDomain(allocator, "example.com", "session", "1", "/foo", 1000, false, false, null, .{});
    out[1] = try Cookie.fromRawDomain(allocator, ".example.com", "csrf", "2", "/", 1000, true, false, null, .{});
    out[2] = try Cookie.fromRawDomain(allocator, "other.com", "x", "3", "/", 1000, false, false, null, .{});
    out[3] = try Cookie.fromRawDomain(allocator, "example.com", "old", "4", "/", 1, false, false, null, .{});
    return out;
}

fn freeCookies(allocator: std.mem.Allocator, cookies: []Cookie) void {
    for (cookies) |c| c.deinit(allocator);
    allocator.free(cookies);
}
