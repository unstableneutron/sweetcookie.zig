const Cookie = @import("Cookie.zig");

pub const Mode = enum {
    merge,
    replace,
};

pub const Inline = struct {
    json: ?[]const u8 = null,
    base64: ?[]const u8 = null,
    file: ?[]const u8 = null,
};

pub const Options = struct {
    browser: ?Cookie.Browser = null,
    mode: Mode = .merge,
    inline_input: Inline = .{},
    url: ?[]const u8 = null,
    origins: []const []const u8 = &.{},
    names: []const []const u8 = &.{},
    include_expired: bool = false,
};
