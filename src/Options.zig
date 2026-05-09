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
    browsers: []const Cookie.Browser = &.{},
    mode: Mode = .merge,
    inline_input: Inline = .{},
    url: ?[]const u8 = null,
    origins: []const []const u8 = &.{},
    names: []const []const u8 = &.{},
    include_expired: bool = false,
    all_domains: bool = false,
    firefox_profile: ?[]const u8 = null,
    firefox_profile_root: ?[]const u8 = null,
    firefox_cookies_file: ?[]const u8 = null,
    safari_cookies_file: ?[]const u8 = null,
    safari_cookies_root: ?[]const u8 = null,
    chrome_profile: ?[]const u8 = null,
    chrome_profile_root: ?[]const u8 = null,
    chrome_cookies_db: ?[]const u8 = null,
};
