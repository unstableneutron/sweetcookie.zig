const std = @import("std");

pub fn writeDirectoryTar(allocator: std.mem.Allocator, profile_dir: []const u8, out_path: []const u8) !void {
    var out = try std.fs.createFileAbsolute(out_path, .{ .truncate = true });
    defer out.close();
    var writer_buf: [8192]u8 = undefined;
    var file_writer = out.writer(&writer_buf);
    const writer = &file_writer.interface;

    var root = try std.fs.openDirAbsolute(profile_dir, .{ .iterate = true });
    defer root.close();
    try writeDir(allocator, writer, root, "");
    try writer.writeAll(&([_]u8{0} ** 1024));
    try writer.flush();
}

fn writeDir(allocator: std.mem.Allocator, writer: anytype, dir: std.fs.Dir, prefix: []const u8) !void {
    var iterator = dir.iterate();
    while (try iterator.next()) |entry| {
        const rel = if (prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, entry.name });
        defer allocator.free(rel);

        switch (entry.kind) {
            .directory => {
                const header_name = try std.fmt.allocPrint(allocator, "{s}/", .{rel});
                defer allocator.free(header_name);
                try writeHeader(writer, header_name, 0, '5');
                var child = try dir.openDir(entry.name, .{ .iterate = true });
                defer child.close();
                try writeDir(allocator, writer, child, rel);
            },
            .file => {
                const stat = try dir.statFile(entry.name);
                try writeHeader(writer, rel, stat.size, '0');
                var file = try dir.openFile(entry.name, .{ .mode = .read_only });
                defer file.close();
                try copyFileBytes(writer, file, stat.size);
            },
            else => {},
        }
    }
}

fn copyFileBytes(writer: anytype, file: std.fs.File, size: u64) !void {
    var reader_buf: [8192]u8 = undefined;
    var file_reader = file.reader(&reader_buf);
    const reader = &file_reader.interface;
    var remaining = size;
    while (remaining > 0) {
        var buf: [8192]u8 = undefined;
        const max_read = @min(buf.len, remaining);
        const n = try reader.readSliceShort(buf[0..max_read]);
        if (n == 0) return error.UnexpectedEndOfFile;
        try writer.writeAll(buf[0..n]);
        remaining -= n;
    }
    try writePadding(writer, size);
}

fn writeHeader(writer: anytype, name: []const u8, size: u64, typeflag: u8) !void {
    if (name.len > 100) return error.TarPathTooLong;
    var header = [_]u8{0} ** 512;
    std.mem.copyForwards(u8, header[0..100], name);
    try writeOctal(header[100..108], 0o644);
    try writeOctal(header[108..116], 0);
    try writeOctal(header[116..124], 0);
    try writeOctal(header[124..136], size);
    try writeOctal(header[136..148], @intCast(std.time.timestamp()));
    @memset(header[148..156], ' ');
    header[156] = typeflag;
    std.mem.copyForwards(u8, header[257..263], "ustar\x00");
    std.mem.copyForwards(u8, header[263..265], "00");
    var sum: u64 = 0;
    for (header) |byte| sum += byte;
    try writeChecksum(header[148..156], sum);
    try writer.writeAll(&header);
}

fn writeOctal(field: []u8, value: u64) !void {
    @memset(field, 0);
    const digits_len = field.len - 1;
    const printed = try std.fmt.bufPrint(field[0..digits_len], "{o}", .{value});
    if (printed.len > digits_len) return error.TarValueTooLarge;
    if (printed.len < digits_len) {
        const shift = digits_len - printed.len;
        std.mem.copyBackwards(u8, field[shift..digits_len], field[0..printed.len]);
        @memset(field[0..shift], '0');
    }
}

fn writeChecksum(field: []u8, sum: u64) !void {
    @memset(field, 0);
    const printed = try std.fmt.bufPrint(field[0..6], "{o}", .{sum});
    if (printed.len > 6) return error.TarValueTooLarge;
    if (printed.len < 6) {
        const shift = 6 - printed.len;
        std.mem.copyBackwards(u8, field[shift..6], field[0..printed.len]);
        @memset(field[0..shift], '0');
    }
    field[6] = 0;
    field[7] = ' ';
}

fn writePadding(writer: anytype, size: u64) !void {
    const rem = size % 512;
    if (rem == 0) return;
    var zeros = [_]u8{0} ** 512;
    try writer.writeAll(zeros[0 .. 512 - rem]);
}

test "writeDirectoryTar writes a nonempty tarball for a directory tree" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("profile/sub");
    try tmp.dir.writeFile(.{ .sub_path = "profile/Cookies", .data = "cookie-db" });
    try tmp.dir.writeFile(.{ .sub_path = "profile/sub/state", .data = "state" });
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const profile = try std.fs.path.join(std.testing.allocator, &.{ root, "profile" });
    defer std.testing.allocator.free(profile);
    const out = try std.fs.path.join(std.testing.allocator, &.{ root, "backup.tar" });
    defer std.testing.allocator.free(out);

    try writeDirectoryTar(std.testing.allocator, profile, out);

    const stat = try std.fs.statFileAbsolute(out);
    try std.testing.expect(stat.size > 1024);
    try std.testing.expectEqual(@as(u64, 0), stat.size % 512);
}
