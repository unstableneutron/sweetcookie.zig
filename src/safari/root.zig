const std = @import("std");
const Options = @import("../Options.zig").Options;
const Cookie = @import("../Cookie.zig").Cookie;
const snapshot = @import("../snapshot.zig");
const binarycookies = @import("binarycookies.zig");
const paths = @import("paths.zig");
const builtin = @import("builtin");

pub fn collect(allocator: std.mem.Allocator, options: Options) ![]Cookie {
    const resolved = try resolveCookiesFile(allocator, options);
    defer resolved.deinit(allocator);

    const snap = try snapshot.copyForRead(allocator, resolved.cookies_file);
    defer {
        snapshot.cleanup(snap.tmp_dir) catch {};
        snap.deinit(allocator);
    }

    const bytes = try std.fs.cwd().readFileAlloc(allocator, snap.target, 64 * 1024 * 1024);
    defer allocator.free(bytes);
    return binarycookies.parse(allocator, bytes);
}

const Resolved = struct {
    cookies_file: []u8,
    candidates: ?[][]const u8 = null,

    fn deinit(self: Resolved, allocator: std.mem.Allocator) void {
        allocator.free(self.cookies_file);
        if (self.candidates) |candidates| paths.freeCookieFiles(allocator, candidates);
    }
};

fn resolveCookiesFile(allocator: std.mem.Allocator, options: Options) !Resolved {
    if (options.safari_cookies_file) |path| {
        return .{ .cookies_file = try allocator.dupe(u8, path) };
    }

    if (builtin.os.tag != .macos) return error.SafariDefaultDiscoveryDarwinOnly;

    if (options.safari_cookies_root) |root| {
        const selected = try paths.selectExistingCookieFileWithBackup(allocator, root, options.allow_real_browser, null);
        errdefer allocator.free(selected);
        return .{ .cookies_file = selected };
    }

    const candidates = try paths.defaultCookieFiles(allocator, options.allow_real_browser);
    errdefer paths.freeCookieFiles(allocator, candidates);
    const selected = try paths.selectExistingFromCandidatesWithBackup(allocator, candidates, options.allow_real_browser, null);
    errdefer allocator.free(selected);
    return .{ .cookies_file = selected, .candidates = candidates };
}

test "safari root module declarations are reachable" {
    std.testing.refAllDecls(@This());
}
