const std = @import("std");
const sqlite = @import("../util/sqlite.zig");
const Cookie = @import("../Cookie.zig").Cookie;
const SameSite = @import("../Cookie.zig").SameSite;

const select_cookies =
    \\SELECT name, value, host, path, expiry, isSecure, isHttpOnly, sameSite
    \\FROM moz_cookies
    \\ORDER BY id
;

pub fn readCookies(allocator: std.mem.Allocator, db_path: []const u8, profile: ?[]const u8) ![]Cookie {
    var db = try sqlite.Db.openReadOnly(db_path);
    defer db.close();
    var stmt = try db.prepare(select_cookies);
    defer stmt.finalize();

    var cookies = std.ArrayList(Cookie).empty;
    errdefer {
        for (cookies.items) |cookie| cookie.deinit(allocator);
        cookies.deinit(allocator);
    }

    while (try stmt.step()) {
        const name = stmt.columnText(0) orelse "";
        const value = stmt.columnText(1) orelse "";
        const host = stmt.columnText(2) orelse "";
        const path = stmt.columnText(3) orelse "/";
        const expiry = stmt.columnInt64(4);
        const secure = stmt.columnInt64(5) != 0;
        const http_only = stmt.columnInt64(6) != 0;
        const same_site = firefoxSameSite(stmt.columnInt64(7));
        try cookies.append(allocator, try Cookie.fromRawDomain(
            allocator,
            host,
            name,
            value,
            path,
            expiry,
            secure,
            http_only,
            same_site,
            .{ .browser = .firefox, .profile = profile },
        ));
    }

    return cookies.toOwnedSlice(allocator);
}

pub fn firefoxSameSite(value: i64) ?SameSite {
    return switch (value) {
        0 => .None,
        1 => .Lax,
        2 => .Strict,
        else => null,
    };
}

test "firefox sameSite values map to canonical enum" {
    try std.testing.expectEqual(SameSite.None, firefoxSameSite(0).?);
    try std.testing.expectEqual(SameSite.Lax, firefoxSameSite(1).?);
    try std.testing.expectEqual(SameSite.Strict, firefoxSameSite(2).?);
    try std.testing.expect(firefoxSameSite(3) == null);
}
