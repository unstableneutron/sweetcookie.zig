const std = @import("std");
const builtin = @import("builtin");

pub fn writeAtomically(path: []const u8, data: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| {
        try makePath(parent);
    }

    const tmp_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.tmp", .{path});
    defer std.heap.page_allocator.free(tmp_path);

    var tmp_file = try createFile(tmp_path);
    defer tmp_file.close();
    if (builtin.os.tag != .windows) {
        // Windows path keeps atomic write but skips POSIX mode bits.
        try tmp_file.chmod(0o600);
    }
    try tmp_file.writeAll(data);
    try tmp_file.sync();
    try rename(tmp_path, path);
}

fn makePath(path: []const u8) !void {
    if (path.len == 0) return;
    if (std.fs.path.isAbsolute(path)) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        try root.makePath(path[1..]);
        return;
    }
    try std.fs.cwd().makePath(path);
}

fn createFile(path: []const u8) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return std.fs.createFileAbsolute(path, .{ .truncate = true, .read = false });
    }
    return std.fs.cwd().createFile(path, .{ .truncate = true, .read = false });
}

fn rename(old_path: []const u8, new_path: []const u8) !void {
    if (std.fs.path.isAbsolute(old_path) and std.fs.path.isAbsolute(new_path)) {
        try std.fs.renameAbsolute(old_path, new_path);
        return;
    }
    try std.fs.cwd().rename(old_path, new_path);
}

test "VAL-EXPORT-009 output file created with 0600 mode" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const out_path = try tmp.dir.realpathAlloc(std.testing.allocator, "a.json");
    defer std.testing.allocator.free(out_path);
    try writeAtomically(out_path, "{\"ok\":true}\n");
    const stat = try std.fs.statFileAbsolute(out_path);
    try std.testing.expectEqual(@as(u32, 0o600), stat.mode & 0o777);
}

test "VAL-EXPORT-010 output file creates missing parent dirs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const out_path = try std.fs.path.join(std.testing.allocator, &.{ root, "sub", "dir", "b.json" });
    defer std.testing.allocator.free(out_path);
    try writeAtomically(out_path, "{\"ok\":true}\n");
    const stat = try std.fs.statFileAbsolute(out_path);
    try std.testing.expectEqual(@as(u32, 0o600), stat.mode & 0o777);
}

test "VAL-EXPORT-011 existing output file overwritten to 0600" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sub");
    try tmp.dir.writeFile(.{ .sub_path = "sub/c.json", .data = "old" });
    const out_path = try tmp.dir.realpathAlloc(std.testing.allocator, "sub/c.json");
    defer std.testing.allocator.free(out_path);
    try std.posix.chmod(out_path, 0o644);
    try writeAtomically(out_path, "new");
    const stat = try std.fs.statFileAbsolute(out_path);
    try std.testing.expectEqual(@as(u32, 0o600), stat.mode & 0o777);
}
