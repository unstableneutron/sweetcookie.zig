const std = @import("std");
const Options = @import("../Options.zig").Options;
const Cookie = @import("../Cookie.zig").Cookie;
const snapshot = @import("../snapshot.zig");
const profiles_ini = @import("profiles_ini.zig");
const paths = @import("paths.zig");
const db = @import("db.zig");

pub fn collect(allocator: std.mem.Allocator, options: Options) ![]Cookie {
    const resolved = try resolveCookiesFile(allocator, options);
    defer resolved.deinit(allocator);

    const snap = try snapshot.copyForRead(allocator, resolved.cookies_file);
    defer {
        snapshot.cleanup(snap.tmp_dir) catch {};
        snap.deinit(allocator);
    }

    return db.readCookies(allocator, snap.target, resolved.profile_name);
}

const Resolved = struct {
    cookies_file: []u8,
    profile_name: ?[]u8 = null,
    ini: ?profiles_ini.ProfilesIni = null,
    roots: ?[][]const u8 = null,

    fn deinit(self: Resolved, allocator: std.mem.Allocator) void {
        allocator.free(self.cookies_file);
        if (self.profile_name) |name| allocator.free(name);
        if (self.ini) |ini| ini.deinit(allocator);
        if (self.roots) |roots| paths.freeProfileRoots(allocator, roots);
    }
};

fn resolveCookiesFile(allocator: std.mem.Allocator, options: Options) !Resolved {
    if (options.firefox_cookies_file) |path| {
        return .{ .cookies_file = try allocator.dupe(u8, path) };
    }

    if (options.firefox_profile_root) |root| {
        return resolveFromRoot(allocator, root, options.firefox_profile, null);
    }

    const roots = try paths.defaultProfileRoots(allocator, options.allow_real_browser);
    errdefer paths.freeProfileRoots(allocator, roots);
    if (roots.len == 0) return error.MissingProfilesIni;
    return resolveFromRoot(allocator, roots[0], options.firefox_profile, roots);
}

fn resolveFromRoot(allocator: std.mem.Allocator, root: []const u8, profile_name: ?[]const u8, owned_roots: ?[][]const u8) !Resolved {
    const selected = try profiles_ini.loadAndSelect(allocator, root, profile_name);
    errdefer selected.ini.deinit(allocator);
    const cookies_file = try std.fs.path.join(allocator, &.{ selected.profile.resolved_path, "cookies.sqlite" });
    errdefer allocator.free(cookies_file);
    const selected_name = try allocator.dupe(u8, selected.profile.name);
    errdefer allocator.free(selected_name);
    return .{
        .cookies_file = cookies_file,
        .profile_name = selected_name,
        .ini = selected.ini,
        .roots = owned_roots,
    };
}

test "firefox root module declarations are reachable" {
    std.testing.refAllDecls(@This());
}
