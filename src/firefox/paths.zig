const std = @import("std");
const builtin = @import("builtin");
const realbrowser = @import("../realbrowser.zig");

pub fn defaultProfileRoots(allocator: std.mem.Allocator, allow_real_browser: bool) ![][]const u8 {
    if (!allow_real_browser) {
        const gated = realbrowser.gateOrBackup(allocator, .{
            .allow_real_browser = false,
            .browser = .firefox,
            .profile_dir = "/sweetcookie/not-accessed/firefox",
        });
        _ = gated catch |err| return err;
        unreachable;
    }

    const root = try defaultProfileRoot(allocator);
    errdefer allocator.free(root);
    const backup = try realbrowser.gateOrBackup(allocator, .{
        .allow_real_browser = true,
        .browser = .firefox,
        .profile_dir = root,
    });
    allocator.free(backup);

    const roots = try allocator.alloc([]const u8, 1);
    roots[0] = root;
    return roots;
}

pub fn freeProfileRoots(allocator: std.mem.Allocator, roots: [][]const u8) void {
    for (roots) |root| allocator.free(root);
    allocator.free(roots);
}

pub fn defaultProfileRoot(allocator: std.mem.Allocator) ![]u8 {
    return switch (builtin.os.tag) {
        .macos => homeJoin(allocator, &.{ "Library", "Application Support", "Firefox" }),
        .linux => homeJoin(allocator, &.{ ".mozilla", "firefox" }),
        .windows => appDataJoin(allocator, &.{ "Mozilla", "Firefox" }),
        else => error.UnsupportedPlatform,
    };
}

fn homeJoin(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return joinWithPrefix(allocator, home, parts);
}

fn appDataJoin(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    const appdata = try std.process.getEnvVarOwned(allocator, "APPDATA");
    defer allocator.free(appdata);
    return joinWithPrefix(allocator, appdata, parts);
}

fn joinWithPrefix(allocator: std.mem.Allocator, prefix: []const u8, parts: []const []const u8) ![]u8 {
    var list = std.ArrayList([]const u8).empty;
    defer list.deinit(allocator);
    try list.append(allocator, prefix);
    for (parts) |part| try list.append(allocator, part);
    return std.fs.path.join(allocator, list.items);
}

test "firefox default profile roots are gated before path access" {
    try std.testing.expectError(error.RealBrowserNotPermitted, defaultProfileRoots(std.testing.allocator, false));
}
