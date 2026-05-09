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

pub const Mode = enum {
    merge,
    replace,
};

pub const Cookie = struct {
    name: []const u8 = "",
    value: []const u8 = "",
    domain: []const u8 = "",
    raw_domain: []const u8 = "",
    host_only: bool = true,
    path: []const u8 = "/",
    expires: ?i64 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,
    browser: ?Browser = null,
};

pub const Options = struct {
    browser: ?Browser = null,
    mode: Mode = .merge,
};

pub const Warning = struct {
    kind: []const u8,
    message: []const u8,
};

pub const Result = struct {
    cookies: []const Cookie,
    warnings: []const Warning,

    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

pub fn get(allocator: std.mem.Allocator, options: Options) !Result {
    _ = allocator;
    _ = options;
    return .{
        .cookies = &.{},
        .warnings = &.{},
    };
}

test "public API exposes stub result" {
    const result = try get(std.testing.allocator, .{});
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), result.cookies.len);
    try std.testing.expectEqual(@as(usize, 0), result.warnings.len);
}
