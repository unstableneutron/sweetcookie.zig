const std = @import("std");
const Browser = @import("Cookie.zig").Browser;
const tar = @import("util/tar.zig");

pub const GateOptions = struct {
    allow_real_browser: bool,
    browser: Browser,
    profile_dir: []const u8,
    tmp_dir: ?[]const u8 = null,
};

pub fn allowRealBrowserFromEnv() bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, "SWEETCOOKIE_ALLOW_REAL_BROWSER") catch return false;
    defer std.heap.page_allocator.free(value);
    return std.mem.eql(u8, value, "1");
}

pub fn gateOrBackup(allocator: std.mem.Allocator, opts: GateOptions) ![]u8 {
    if (!opts.allow_real_browser) return error.RealBrowserNotPermitted;

    const tmp_root = if (opts.tmp_dir) |dir|
        try allocator.dupe(u8, dir)
    else
        std.process.getEnvVarOwned(allocator, "TMPDIR") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => try allocator.dupe(u8, "/tmp"),
            else => return err,
        };
    defer allocator.free(tmp_root);

    const ts = std.time.timestamp();
    const backup_name = try std.fmt.allocPrint(allocator, "sweetcookie-backup-{d}-{s}.tar", .{ ts, @tagName(opts.browser) });
    defer allocator.free(backup_name);
    const backup_path = try std.fs.path.join(allocator, &.{ tmp_root, backup_name });
    errdefer allocator.free(backup_path);

    try tar.writeDirectoryTar(allocator, opts.profile_dir, backup_path);
    try printBackupPath(backup_path);
    return backup_path;
}

fn printBackupPath(path: []const u8) !void {
    var buffer: [512]u8 = undefined;
    var writer = std.fs.File.stderr().writer(&buffer);
    const stderr = &writer.interface;
    try stderr.print("backup written to {s}\n", .{path});
    try stderr.flush();
}

test "gateOrBackup rejects before touching fake profile path when not allowed" {
    const result = gateOrBackup(std.testing.allocator, .{
        .allow_real_browser = false,
        .browser = .firefox,
        .profile_dir = "/definitely/not/a/real/browser/profile",
    });
    try std.testing.expectError(error.RealBrowserNotPermitted, result);
}

test "gateOrBackup writes backup tarball and reports path when allowed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("profile");
    try tmp.dir.writeFile(.{ .sub_path = "profile/cookies.sqlite", .data = "db" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const profile = try std.fs.path.join(std.testing.allocator, &.{ root, "profile" });
    defer std.testing.allocator.free(profile);

    const backup = try gateOrBackup(std.testing.allocator, .{
        .allow_real_browser = true,
        .browser = .firefox,
        .profile_dir = profile,
        .tmp_dir = root,
    });
    defer std.testing.allocator.free(backup);

    try std.testing.expect(std.mem.indexOf(u8, backup, "sweetcookie-backup-") != null);
    try std.testing.expect(std.mem.endsWith(u8, backup, "-firefox.tar"));
    const stat = try std.fs.statFileAbsolute(backup);
    try std.testing.expect(stat.size > 0);
}
