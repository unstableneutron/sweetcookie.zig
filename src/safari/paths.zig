const std = @import("std");
const builtin = @import("builtin");
const realbrowser = @import("../realbrowser.zig");

const sandbox_relative = [_][]const u8{ "Library", "Containers", "com.apple.Safari", "Data", "Library", "Cookies", "Cookies.binarycookies" };
const legacy_relative = [_][]const u8{ "Library", "Cookies", "Cookies.binarycookies" };

pub fn defaultCookieFiles(allocator: std.mem.Allocator, allow_real_browser: bool) ![][]const u8 {
    if (builtin.os.tag != .macos) return error.SafariDefaultDiscoveryDarwinOnly;
    if (!allow_real_browser) {
        const gated = realbrowser.gateOrBackup(allocator, .{
            .allow_real_browser = false,
            .browser = .safari,
            .profile_dir = "/sweetcookie/not-accessed/safari",
        });
        _ = gated catch |err| return err;
        unreachable;
    }

    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    const files = try cookieFilesUnderRoot(allocator, home);
    errdefer freeCookieFiles(allocator, files);

    const profile_dir = std.fs.path.dirname(files[0]) orelse home;
    const backup = try realbrowser.gateOrBackup(allocator, .{
        .allow_real_browser = true,
        .browser = .safari,
        .profile_dir = profile_dir,
    });
    allocator.free(backup);
    return files;
}

pub fn cookieFilesUnderRoot(allocator: std.mem.Allocator, root: []const u8) ![][]const u8 {
    const files = try allocator.alloc([]const u8, 2);
    errdefer allocator.free(files);
    files[0] = try joinRelative(allocator, root, &sandbox_relative);
    errdefer allocator.free(files[0]);
    files[1] = try joinRelative(allocator, root, &legacy_relative);
    return files;
}

pub fn freeCookieFiles(allocator: std.mem.Allocator, files: [][]const u8) void {
    for (files) |file| allocator.free(file);
    allocator.free(files);
}

fn joinRelative(allocator: std.mem.Allocator, root: []const u8, parts: []const []const u8) ![]u8 {
    var list = std.ArrayList([]const u8).empty;
    defer list.deinit(allocator);
    try list.append(allocator, root);
    for (parts) |part| try list.append(allocator, part);
    return std.fs.path.join(allocator, list.items);
}

test "safari default cookie files are gated before path access" {
    if (builtin.os.tag != .macos) {
        try std.testing.expectError(error.SafariDefaultDiscoveryDarwinOnly, defaultCookieFiles(std.testing.allocator, false));
    } else {
        try std.testing.expectError(error.RealBrowserNotPermitted, defaultCookieFiles(std.testing.allocator, false));
    }
}

test "safari cookie root yields sandbox and legacy paths" {
    const files = try cookieFilesUnderRoot(std.testing.allocator, "/tmp/home");
    defer freeCookieFiles(std.testing.allocator, files);
    try std.testing.expectEqual(@as(usize, 2), files.len);
    try std.testing.expect(std.mem.endsWith(u8, files[0], "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"));
    try std.testing.expect(std.mem.endsWith(u8, files[1], "Library/Cookies/Cookies.binarycookies"));
}
