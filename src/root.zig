const std = @import("std");

const CookieMod = @import("Cookie.zig");
const OptionsMod = @import("Options.zig");
const ResultMod = @import("Result.zig");

pub const Browser = CookieMod.Browser;
pub const SameSite = CookieMod.SameSite;
pub const Source = CookieMod.Source;
pub const Cookie = CookieMod.Cookie;

pub const Mode = OptionsMod.Mode;
pub const Options = OptionsMod.Options;

pub const Warning = ResultMod.Warning;
pub const Result = ResultMod.Result;

pub fn get(allocator: std.mem.Allocator, options: Options) !Result {
    _ = options;
    return .{
        .cookies = try allocator.alloc(Cookie, 0),
        .warnings = try allocator.alloc(Warning, 0),
    };
}

test "public API exposes stub result" {
    const result = try get(std.testing.allocator, .{});
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), result.cookies.len);
    try std.testing.expectEqual(@as(usize, 0), result.warnings.len);
}
