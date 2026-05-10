const std = @import("std");
const builtin = @import("builtin");
const Browser = @import("../Cookie.zig").Browser;
const realbrowser = @import("../realbrowser.zig");

pub fn defaultProfileRoot(allocator: std.mem.Allocator, browser: Browser) ![]u8 {
    return switch (builtin.os.tag) {
        .macos => homeJoin(allocator, macosParts(browser)),
        .linux => homeJoin(allocator, linuxParts(browser)),
        .windows => windowsJoin(allocator, browser),
        else => error.UnsupportedPlatform,
    };
}

pub fn defaultProfileRootGated(allocator: std.mem.Allocator, browser: Browser, allow_real_browser: bool) ![]u8 {
    if (!allow_real_browser) {
        const gated = realbrowser.gateOrBackup(allocator, .{
            .allow_real_browser = false,
            .browser = browser,
            .profile_dir = "/sweetcookie/not-accessed/chromium",
        });
        _ = gated catch |err| return err;
        unreachable;
    }
    const root = try defaultProfileRoot(allocator, browser);
    errdefer allocator.free(root);
    const backup = try realbrowser.gateOrBackup(allocator, .{
        .allow_real_browser = true,
        .browser = browser,
        .profile_dir = root,
    });
    allocator.free(backup);
    return root;
}

pub fn cookiesFileFromRoot(allocator: std.mem.Allocator, root: []const u8, profile: ?[]const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ root, profile orelse "Default", "Cookies" });
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

fn localAppDataJoin(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    const local = try std.process.getEnvVarOwned(allocator, "LOCALAPPDATA");
    defer allocator.free(local);
    return joinWithPrefix(allocator, local, parts);
}

fn joinWithPrefix(allocator: std.mem.Allocator, prefix: []const u8, parts: []const []const u8) ![]u8 {
    var list = std.ArrayList([]const u8).empty;
    defer list.deinit(allocator);
    try list.append(allocator, prefix);
    for (parts) |part| try list.append(allocator, part);
    return std.fs.path.join(allocator, list.items);
}

fn macosParts(browser: Browser) []const []const u8 {
    return switch (browser) {
        .chrome => &.{ "Library", "Application Support", "Google", "Chrome" },
        .chromium => &.{ "Library", "Application Support", "Chromium" },
        .edge => &.{ "Library", "Application Support", "Microsoft Edge" },
        .brave => &.{ "Library", "Application Support", "BraveSoftware", "Brave-Browser" },
        .vivaldi => &.{ "Library", "Application Support", "Vivaldi" },
        .opera => &.{ "Library", "Application Support", "com.operasoftware.Opera" },
        .arc => &.{ "Library", "Application Support", "Arc" },
        else => &.{"Library"},
    };
}

fn linuxParts(browser: Browser) []const []const u8 {
    return switch (browser) {
        .chrome => &.{ ".config", "google-chrome" },
        .chromium => &.{ ".config", "chromium" },
        .edge => &.{ ".config", "microsoft-edge" },
        .brave => &.{ ".config", "BraveSoftware", "Brave-Browser" },
        .vivaldi => &.{ ".config", "vivaldi" },
        .opera => &.{ ".config", "opera" },
        .arc => &.{ ".config", "arc" },
        else => &.{".config"},
    };
}

fn windowsJoin(allocator: std.mem.Allocator, browser: Browser) ![]u8 {
    return switch (browser) {
        .chrome => localAppDataJoin(allocator, &.{ "Google", "Chrome", "User Data" }),
        .chromium => localAppDataJoin(allocator, &.{ "Chromium", "User Data" }),
        .edge => localAppDataJoin(allocator, &.{ "Microsoft", "Edge", "User Data" }),
        .brave => localAppDataJoin(allocator, &.{ "BraveSoftware", "Brave-Browser", "User Data" }),
        .vivaldi => localAppDataJoin(allocator, &.{ "Vivaldi", "User Data" }),
        .opera => appDataJoin(allocator, &.{ "Opera Software", "Opera Stable" }),
        .arc => localAppDataJoin(allocator, &.{ "Arc", "User Data" }),
        else => error.UnsupportedPlatform,
    };
}

test "chromium default profile roots are gated before path access" {
    try std.testing.expectError(error.RealBrowserNotPermitted, defaultProfileRootGated(std.testing.allocator, .chrome, false));
}

test "chromium cookies file uses Default profile unless overridden" {
    const default = try cookiesFileFromRoot(std.testing.allocator, "/tmp/root", null);
    defer std.testing.allocator.free(default);
    try std.testing.expect(std.mem.endsWith(u8, default, "Default/Cookies"));

    const profile = try cookiesFileFromRoot(std.testing.allocator, "/tmp/root", "Profile 2");
    defer std.testing.allocator.free(profile);
    try std.testing.expect(std.mem.endsWith(u8, profile, "Profile 2/Cookies"));
}
