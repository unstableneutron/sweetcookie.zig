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
    return files;
}

pub fn selectExistingCookieFileWithBackup(allocator: std.mem.Allocator, root: []const u8, allow_real_browser: bool, tmp_dir: ?[]const u8) ![]u8 {
    const files = try cookieFilesUnderRoot(allocator, root);
    defer freeCookieFiles(allocator, files);
    return selectExistingFromCandidatesWithBackup(allocator, files, allow_real_browser, tmp_dir);
}

pub fn selectExistingFromCandidatesWithBackup(allocator: std.mem.Allocator, candidates: []const []const u8, allow_real_browser: bool, tmp_dir: ?[]const u8) ![]u8 {
    const selected = try firstExisting(allocator, candidates);
    errdefer allocator.free(selected);
    const profile_dir = std.fs.path.dirname(selected) orelse return error.NotFound;
    const backup = try realbrowser.gateOrBackup(allocator, .{
        .allow_real_browser = allow_real_browser,
        .browser = .safari,
        .profile_dir = profile_dir,
        .tmp_dir = tmp_dir,
    });
    allocator.free(backup);
    return selected;
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

fn firstExisting(allocator: std.mem.Allocator, candidates: []const []const u8) ![]u8 {
    for (candidates) |candidate| {
        std.fs.accessAbsolute(candidate, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return allocator.dupe(u8, candidate);
    }
    return error.NotFound;
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

test "safari default selection backs up sandboxed candidate when only sandboxed exists" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    try writeCandidate(&tmp, &sandbox_relative, "sandbox-marker");

    const selected = try selectExistingCookieFileWithBackup(std.testing.allocator, root, true, root);
    defer std.testing.allocator.free(selected);
    try std.testing.expect(std.mem.indexOf(u8, selected, "Containers/com.apple.Safari") != null);
    try expectSingleBackupContaining(root, "sandbox-marker");
}

test "safari default selection backs up legacy candidate when only legacy exists" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    try writeCandidate(&tmp, &legacy_relative, "legacy-marker");

    const selected = try selectExistingCookieFileWithBackup(std.testing.allocator, root, true, root);
    defer std.testing.allocator.free(selected);
    try std.testing.expect(std.mem.indexOf(u8, selected, "Library/Cookies/Cookies.binarycookies") != null);
    try expectSingleBackupContaining(root, "legacy-marker");
}

test "safari default selection prefers and backs up sandboxed when both candidates exist" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    try writeCandidate(&tmp, &sandbox_relative, "sandbox-marker");
    try writeCandidate(&tmp, &legacy_relative, "legacy-marker");

    const selected = try selectExistingCookieFileWithBackup(std.testing.allocator, root, true, root);
    defer std.testing.allocator.free(selected);
    try std.testing.expect(std.mem.indexOf(u8, selected, "Containers/com.apple.Safari") != null);
    try expectSingleBackupContaining(root, "sandbox-marker");
}

test "safari default selection returns NotFound without backup when neither candidate exists" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    try std.testing.expectError(error.NotFound, selectExistingCookieFileWithBackup(std.testing.allocator, root, true, root));
    try expectBackupCount(root, 0);
}

fn writeCandidate(tmp: *std.testing.TmpDir, parts: []const []const u8, marker: []const u8) !void {
    var dir_parts = std.ArrayList([]const u8).empty;
    defer dir_parts.deinit(std.testing.allocator);
    for (parts[0 .. parts.len - 1]) |part| try dir_parts.append(std.testing.allocator, part);
    const dir_path = try std.fs.path.join(std.testing.allocator, dir_parts.items);
    defer std.testing.allocator.free(dir_path);
    try tmp.dir.makePath(dir_path);
    const file_path = try std.fs.path.join(std.testing.allocator, parts);
    defer std.testing.allocator.free(file_path);
    try tmp.dir.writeFile(.{ .sub_path = file_path, .data = marker });
}

fn expectSingleBackupContaining(root: []const u8, marker: []const u8) !void {
    try expectBackupCount(root, 1);
    var dir = try std.fs.openDirAbsolute(root, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "sweetcookie-backup-")) continue;
        const path = try std.fs.path.join(std.testing.allocator, &.{ root, entry.name });
        defer std.testing.allocator.free(path);
        const bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 1024 * 1024);
        defer std.testing.allocator.free(bytes);
        try std.testing.expect(std.mem.indexOf(u8, bytes, marker) != null);
        return;
    }
    return error.TestExpectedBackup;
}

fn expectBackupCount(root: []const u8, expected: usize) !void {
    var count: usize = 0;
    var dir = try std.fs.openDirAbsolute(root, .{ .iterate = true });
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.name, "sweetcookie-backup-")) count += 1;
    }
    try std.testing.expectEqual(expected, count);
}
