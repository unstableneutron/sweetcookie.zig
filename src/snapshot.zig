const std = @import("std");

const sidecars = [_][]const u8{ "-wal", "-shm", "-journal" };

pub const Snapshot = struct {
    tmp_dir: []u8,
    target: []u8,

    pub fn deinit(self: Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.tmp_dir);
        allocator.free(self.target);
    }
};

pub fn copyForRead(allocator: std.mem.Allocator, src_path: []const u8) !Snapshot {
    const base_name = std.fs.path.basename(src_path);
    if (base_name.len == 0) return error.InvalidPath;

    const tmp_dir = try makeTmpDir(allocator);
    errdefer {
        cleanup(tmp_dir) catch {};
        allocator.free(tmp_dir);
    }

    var dest_dir = try std.fs.openDirAbsolute(tmp_dir, .{});
    defer dest_dir.close();

    var src_dir = try openParentDir(src_path);
    defer src_dir.close();

    const src_file = try src_dir.dir.openFile(src_dir.base_name, .{ .mode = .read_only });
    defer src_file.close();
    _ = try src_file.stat();

    try src_dir.dir.copyFile(src_dir.base_name, dest_dir, base_name, .{});
    for (sidecars) |suffix| {
        const sidecar_name = try std.fmt.allocPrint(allocator, "{s}{s}", .{ src_dir.base_name, suffix });
        defer allocator.free(sidecar_name);
        const dest_sidecar = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base_name, suffix });
        defer allocator.free(dest_sidecar);
        src_dir.dir.copyFile(sidecar_name, dest_dir, dest_sidecar, .{}) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    const target = try std.fs.path.join(allocator, &.{ tmp_dir, base_name });
    errdefer allocator.free(target);
    return .{ .tmp_dir = tmp_dir, .target = target };
}

pub fn cleanup(tmp_dir: []const u8) !void {
    if (std.fs.path.isAbsolute(tmp_dir)) {
        const parent = std.fs.path.dirname(tmp_dir) orelse "/";
        const base_name = std.fs.path.basename(tmp_dir);
        var parent_dir = try std.fs.openDirAbsolute(parent, .{});
        defer parent_dir.close();
        try parent_dir.deleteTree(base_name);
        return;
    }
    try std.fs.cwd().deleteTree(tmp_dir);
}

const ParentDir = struct {
    dir: std.fs.Dir,
    base_name: []const u8,

    fn close(self: *ParentDir) void {
        self.dir.close();
    }
};

fn openParentDir(path: []const u8) !ParentDir {
    const parent = std.fs.path.dirname(path) orelse ".";
    const base_name = std.fs.path.basename(path);
    const dir = if (std.fs.path.isAbsolute(parent))
        try std.fs.openDirAbsolute(parent, .{})
    else
        try std.fs.cwd().openDir(parent, .{});
    return .{ .dir = dir, .base_name = base_name };
}

fn makeTmpDir(allocator: std.mem.Allocator) ![]u8 {
    const tmp_root = std.process.getEnvVarOwned(allocator, "TMPDIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, "/tmp"),
        else => return err,
    };
    defer allocator.free(tmp_root);

    var random_bytes: [16]u8 = undefined;
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        std.crypto.random.bytes(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        const name = try std.fmt.allocPrint(allocator, "sweetcookie-snapshot-{s}", .{&hex});
        defer allocator.free(name);
        const path = try std.fs.path.join(allocator, &.{ tmp_root, name });
        errdefer allocator.free(path);
        if (std.fs.makeDirAbsolute(path)) |_| {
            return path;
        } else |err| switch (err) {
            error.PathAlreadyExists => allocator.free(path),
            else => return err,
        }
    }
    return error.PathAlreadyExists;
}

test "copyForRead copies source and present sidecars" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "cookies.sqlite", .data = "db" });
    try tmp.dir.writeFile(.{ .sub_path = "cookies.sqlite-wal", .data = "wal" });
    try tmp.dir.writeFile(.{ .sub_path = "cookies.sqlite-shm", .data = "shm" });
    try tmp.dir.writeFile(.{ .sub_path = "cookies.sqlite-journal", .data = "journal" });
    const src = try tmp.dir.realpathAlloc(std.testing.allocator, "cookies.sqlite");
    defer std.testing.allocator.free(src);

    const snap = try copyForRead(std.testing.allocator, src);
    defer {
        cleanup(snap.tmp_dir) catch {};
        snap.deinit(std.testing.allocator);
    }

    const copied = try std.fs.cwd().readFileAlloc(std.testing.allocator, snap.target, 1024);
    defer std.testing.allocator.free(copied);
    try std.testing.expectEqualStrings("db", copied);

    const wal = try std.fmt.allocPrint(std.testing.allocator, "{s}-wal", .{snap.target});
    defer std.testing.allocator.free(wal);
    const copied_wal = try std.fs.cwd().readFileAlloc(std.testing.allocator, wal, 1024);
    defer std.testing.allocator.free(copied_wal);
    try std.testing.expectEqualStrings("wal", copied_wal);

    const shm = try std.fmt.allocPrint(std.testing.allocator, "{s}-shm", .{snap.target});
    defer std.testing.allocator.free(shm);
    const copied_shm = try std.fs.cwd().readFileAlloc(std.testing.allocator, shm, 1024);
    defer std.testing.allocator.free(copied_shm);
    try std.testing.expectEqualStrings("shm", copied_shm);

    const journal = try std.fmt.allocPrint(std.testing.allocator, "{s}-journal", .{snap.target});
    defer std.testing.allocator.free(journal);
    const copied_journal = try std.fs.cwd().readFileAlloc(std.testing.allocator, journal, 1024);
    defer std.testing.allocator.free(copied_journal);
    try std.testing.expectEqualStrings("journal", copied_journal);
}

test "copyForRead omits absent sidecars without error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "Cookies", .data = "db" });
    const src = try tmp.dir.realpathAlloc(std.testing.allocator, "Cookies");
    defer std.testing.allocator.free(src);

    const snap = try copyForRead(std.testing.allocator, src);
    defer {
        cleanup(snap.tmp_dir) catch {};
        snap.deinit(std.testing.allocator);
    }

    const copied = try std.fs.cwd().readFileAlloc(std.testing.allocator, snap.target, 1024);
    defer std.testing.allocator.free(copied);
    try std.testing.expectEqualStrings("db", copied);
}

test "cleanup removes snapshot tmpdir and contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "cookies.sqlite", .data = "db" });
    const src = try tmp.dir.realpathAlloc(std.testing.allocator, "cookies.sqlite");
    defer std.testing.allocator.free(src);

    const snap = try copyForRead(std.testing.allocator, src);
    const tmp_dir = try std.testing.allocator.dupe(u8, snap.tmp_dir);
    defer std.testing.allocator.free(tmp_dir);
    snap.deinit(std.testing.allocator);

    try cleanup(tmp_dir);
    try std.testing.expectError(error.FileNotFound, std.fs.openDirAbsolute(tmp_dir, .{}));
}
