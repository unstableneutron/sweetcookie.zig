const std = @import("std");
const CookieMod = @import("Cookie.zig");

pub const Warning = struct {
    kind: []const u8,
    message: []const u8,
};

pub const Result = struct {
    cookies: []const CookieMod.Cookie,
    warnings: []const Warning,

    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        for (self.cookies) |cookie| {
            cookie.deinit(allocator);
        }
        allocator.free(self.cookies);

        for (self.warnings) |warning| {
            allocator.free(warning.kind);
            allocator.free(warning.message);
        }
        allocator.free(self.warnings);
    }
};

test "Result.deinit frees owned slices" {
    const cookie = try CookieMod.Cookie.fromRawDomain(
        std.testing.allocator,
        ".example.com",
        "name",
        "value",
        "/",
        1,
        true,
        false,
        .Lax,
        .{ .browser = .firefox, .profile = "p", .origin = "o" },
    );

    var cookies = try std.testing.allocator.alloc(CookieMod.Cookie, 1);
    cookies[0] = cookie;

    var warnings = try std.testing.allocator.alloc(Warning, 1);
    warnings[0] = .{
        .kind = try std.testing.allocator.dupe(u8, "k"),
        .message = try std.testing.allocator.dupe(u8, "m"),
    };

    const result: Result = .{
        .cookies = cookies,
        .warnings = warnings,
    };
    result.deinit(std.testing.allocator);
}
