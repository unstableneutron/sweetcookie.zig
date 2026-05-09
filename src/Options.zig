const Cookie = @import("Cookie.zig");

pub const Mode = enum {
    merge,
    replace,
};

pub const Options = struct {
    browser: ?Cookie.Browser = null,
    mode: Mode = .merge,
};
