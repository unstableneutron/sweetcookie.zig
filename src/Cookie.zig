const std = @import("std");

pub const Browser = enum {
    firefox,
    safari,
    chrome,
    chromium,
    edge,
    brave,
    vivaldi,
    opera,
    arc,
};

pub const SameSite = enum {
    Strict,
    Lax,
    None,
};

pub const Source = struct {
    browser: ?Browser = null,
    profile: ?[]const u8 = null,
    origin: ?[]const u8 = null,
};

pub const Cookie = struct {
    name: []const u8 = "",
    value: []const u8 = "",
    host_only: bool = true,
    domain: []const u8 = "",
    raw_domain: []const u8 = "",
    path: []const u8 = "/",
    expires: ?i64 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,
    source: Source = .{},

    pub fn fromRawDomain(
        allocator: std.mem.Allocator,
        raw_domain: []const u8,
        name: []const u8,
        value: []const u8,
        path: []const u8,
        expires: ?i64,
        secure: bool,
        http_only: bool,
        same_site: ?SameSite,
        source: Source,
    ) !Cookie {
        var domain = raw_domain;
        var host_only = true;
        if (std.mem.startsWith(u8, raw_domain, ".")) {
            host_only = false;
            domain = raw_domain[1..];
        }
        if (std.net.Address.parseIp(domain, 0)) |_| {
            host_only = true;
        } else |_| {}

        const duped_profile = if (source.profile) |profile| try allocator.dupe(u8, profile) else null;
        errdefer if (duped_profile) |profile| allocator.free(profile);

        const duped_origin = if (source.origin) |origin| try allocator.dupe(u8, origin) else null;
        errdefer if (duped_origin) |origin| allocator.free(origin);

        return .{
            .name = try allocator.dupe(u8, name),
            .value = try allocator.dupe(u8, value),
            .host_only = host_only,
            .domain = try allocator.dupe(u8, domain),
            .raw_domain = try allocator.dupe(u8, raw_domain),
            .path = try allocator.dupe(u8, path),
            .expires = expires,
            .secure = secure,
            .http_only = http_only,
            .same_site = same_site,
            .source = .{
                .browser = source.browser,
                .profile = duped_profile,
                .origin = duped_origin,
            },
        };
    }

    pub fn deinit(self: Cookie, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
        allocator.free(self.domain);
        allocator.free(self.raw_domain);
        allocator.free(self.path);
        if (self.source.profile) |profile| allocator.free(profile);
        if (self.source.origin) |origin| allocator.free(origin);
    }
};

test "fromRawDomain leading dot strips normalized domain and sets host_only false" {
    const cookie = try Cookie.fromRawDomain(
        std.testing.allocator,
        ".example.com",
        "n",
        "v",
        "/",
        null,
        false,
        false,
        null,
        .{},
    );
    defer cookie.deinit(std.testing.allocator);

    try std.testing.expectEqual(false, cookie.host_only);
    try std.testing.expectEqualStrings("example.com", cookie.domain);
    try std.testing.expectEqualStrings(".example.com", cookie.raw_domain);
}

test "fromRawDomain no leading dot keeps host_only true" {
    const cookie = try Cookie.fromRawDomain(
        std.testing.allocator,
        "example.com",
        "n",
        "v",
        "/",
        null,
        false,
        false,
        null,
        .{},
    );
    defer cookie.deinit(std.testing.allocator);

    try std.testing.expectEqual(true, cookie.host_only);
    try std.testing.expectEqualStrings("example.com", cookie.domain);
}

test "fromRawDomain ipv4 and ipv6 are always host_only true" {
    const ipv4 = try Cookie.fromRawDomain(
        std.testing.allocator,
        "127.0.0.1",
        "n",
        "v",
        "/",
        null,
        false,
        false,
        null,
        .{},
    );
    defer ipv4.deinit(std.testing.allocator);

    const ipv6 = try Cookie.fromRawDomain(
        std.testing.allocator,
        "::1",
        "n",
        "v",
        "/",
        null,
        false,
        false,
        null,
        .{},
    );
    defer ipv6.deinit(std.testing.allocator);

    try std.testing.expectEqual(true, ipv4.host_only);
    try std.testing.expectEqual(true, ipv6.host_only);
}
