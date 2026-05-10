const std = @import("std");
const Options = @import("../Options.zig").Options;
const CookieMod = @import("../Cookie.zig");
const Cookie = CookieMod.Cookie;
const Browser = CookieMod.Browser;
const Warning = @import("../Result.zig").Warning;
const snapshot = @import("../snapshot.zig");
const paths = @import("paths.zig");
const db = @import("db.zig");

pub const Collection = struct {
    cookies: []Cookie,
    warnings: []Warning,
};

pub fn collect(allocator: std.mem.Allocator, options: Options, browser: Browser) !Collection {
    const resolved = try resolveCookiesFile(allocator, options, browser);
    defer resolved.deinit(allocator);

    const snap = try snapshot.copyForRead(allocator, resolved.cookies_file);
    defer {
        snapshot.cleanup(snap.tmp_dir) catch {};
        snap.deinit(allocator);
    }

    var warnings = std.ArrayList(Warning).empty;
    errdefer {
        for (warnings.items) |warning| {
            allocator.free(warning.kind);
            allocator.free(warning.message);
        }
        warnings.deinit(allocator);
    }
    const cookies = try db.readCookies(allocator, snap.target, browser, resolved.profile_name, &warnings);
    errdefer {
        for (cookies) |cookie| cookie.deinit(allocator);
        allocator.free(cookies);
    }
    return .{ .cookies = cookies, .warnings = try warnings.toOwnedSlice(allocator) };
}

const Resolved = struct {
    cookies_file: []u8,
    profile_name: ?[]u8 = null,
    root: ?[]u8 = null,

    fn deinit(self: Resolved, allocator: std.mem.Allocator) void {
        allocator.free(self.cookies_file);
        if (self.profile_name) |name| allocator.free(name);
        if (self.root) |root| allocator.free(root);
    }
};

fn resolveCookiesFile(allocator: std.mem.Allocator, options: Options, browser: Browser) !Resolved {
    if (options.chrome_cookies_db) |path| {
        return .{ .cookies_file = try allocator.dupe(u8, path) };
    }
    const profile_name = options.chrome_profile orelse "Default";
    if (options.chrome_profile_root) |root| {
        const cookies_file = try paths.cookiesFileFromRoot(allocator, root, profile_name);
        errdefer allocator.free(cookies_file);
        return .{
            .cookies_file = cookies_file,
            .profile_name = try allocator.dupe(u8, profile_name),
        };
    }
    const root = try paths.defaultProfileRootGated(allocator, browser, options.allow_real_browser);
    errdefer allocator.free(root);
    const cookies_file = try paths.cookiesFileFromRoot(allocator, root, profile_name);
    errdefer allocator.free(cookies_file);
    return .{
        .cookies_file = cookies_file,
        .profile_name = try allocator.dupe(u8, profile_name),
        .root = root,
    };
}

pub fn isChromiumBrowser(browser: Browser) bool {
    return switch (browser) {
        .chrome, .chromium, .edge, .brave, .vivaldi, .opera, .arc => true,
        else => false,
    };
}

test "chromium root module declarations are reachable" {
    std.testing.refAllDecls(@This());
}
