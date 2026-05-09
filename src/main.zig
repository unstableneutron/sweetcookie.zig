const std = @import("std");
const sweetcookie = @import("sweetcookie");

const version = "0.0.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        try printHelp();
        std.process.exit(2);
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "--version")) {
        try printVersion();
        return;
    }
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "help")) {
        try printHelp();
        return;
    }
    if (std.mem.eql(u8, cmd, "version")) {
        try printVersion();
        return;
    }

    if (std.mem.eql(u8, cmd, "export")) {
        try runExport(allocator, args[2..]);
        return;
    }
    if (std.mem.eql(u8, cmd, "header")) {
        try runHeader(allocator, args[2..]);
        return;
    }
    if (std.mem.startsWith(u8, cmd, "-")) {
        try printErr("unknown option '{s}'\n", .{cmd});
    } else {
        try printErr("unknown subcommand '{s}'\n", .{cmd});
    }
    std.process.exit(2);
}

fn printVersion() !void {
    var buffer: [128]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&buffer);
    const stdout = &writer.interface;
    try stdout.print("{s}\n", .{version});
    try stdout.flush();
}

fn printHelp() !void {
    var buffer: [1024]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&buffer);
    const stdout = &writer.interface;
    try stdout.writeAll(
        \\sweetcookie
        \\Version: 0.0.0
        \\
        \\usage:
        \\  sweetcookie [OPTIONS]
        \\
        \\COMMANDS:
        \\  export   Export cookies.
        \\  header   Print a Cookie header.
        \\  version  Print the sweetcookie version.
        \\  help     Print help.
        \\
        \\OPTIONS:
        \\  -h, --help  Show this help output.
        \\
    );
    try stdout.flush();
}

fn runExport(allocator: std.mem.Allocator, args: []const [:0]u8) !void {
    var fmt: []const u8 = "lightpanda-json";
    var out_path: ?[]const u8 = null;
    var inline_json: ?[]const u8 = null;
    var inline_base64: ?[]const u8 = null;
    var inline_file: ?[]const u8 = null;
    var url: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--format")) {
            i += 1;
            if (i >= args.len) return usageError("option '--format' requires value\n");
            fmt = args[i];
        } else if (std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return usageError("option '--output' requires value\n");
            out_path = args[i];
        } else if (std.mem.eql(u8, arg, "--inline-json")) {
            i += 1;
            if (i >= args.len) return usageError("option '--inline-json' requires value\n");
            inline_json = args[i];
        } else if (std.mem.eql(u8, arg, "--inline-base64")) {
            i += 1;
            if (i >= args.len) return usageError("option '--inline-base64' requires value\n");
            inline_base64 = args[i];
        } else if (std.mem.eql(u8, arg, "--inline-file")) {
            i += 1;
            if (i >= args.len) return usageError("option '--inline-file' requires value\n");
            inline_file = args[i];
        } else if (std.mem.eql(u8, arg, "--url")) {
            i += 1;
            if (i >= args.len) return usageError("option '--url' requires value\n");
            url = args[i];
        } else {
            return usageErrorFmt("unknown option '{s}'\n", .{arg});
        }
    }

    if (inline_json == null and inline_base64 == null and inline_file == null) {
        try printErr("no input source provided\n", .{});
        std.process.exit(1);
    }

    const result = sweetcookie.get(allocator, .{
        .inline_input = .{ .json = inline_json, .base64 = inline_base64, .file = inline_file },
        .url = url,
    }) catch |err| return runtimeError(err);
    defer result.deinit(allocator);

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);
    if (std.mem.eql(u8, fmt, "lightpanda-json")) {
        try sweetcookie.exporter.writeLightpandaJson(writer, result.cookies);
    } else if (std.mem.eql(u8, fmt, "sweet-cookie-json")) {
        try sweetcookie.exporter.writeSweetCookieJson(writer, result.cookies, .{ .generated_at_unix = std.time.timestamp(), .target_url = url });
    } else if (std.mem.eql(u8, fmt, "cookie-header")) {
        const header_url = url orelse {
            try printErr("--url is required for cookie-header format\n", .{});
            std.process.exit(1);
        };
        try sweetcookie.exporter.writeCookieHeader(writer, result.cookies, header_url);
    } else {
        return usageErrorFmt("unknown format '{s}'\n", .{fmt});
    }

    if (out_path) |path| {
        try sweetcookie.output.writeAtomically(path, buf.items);
        return;
    }

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;
    try stdout.writeAll(buf.items);
    try stdout.writeByte('\n');
    try stdout.flush();
}

fn runHeader(allocator: std.mem.Allocator, args: []const [:0]u8) !void {
    var url: ?[]const u8 = null;
    var inline_json: ?[]const u8 = null;
    var inline_base64: ?[]const u8 = null;
    var inline_file: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--url")) {
            i += 1;
            if (i >= args.len) return usageError("option '--url' requires value\n");
            url = args[i];
        } else if (std.mem.eql(u8, arg, "--inline-json")) {
            i += 1;
            if (i >= args.len) return usageError("option '--inline-json' requires value\n");
            inline_json = args[i];
        } else if (std.mem.eql(u8, arg, "--inline-base64")) {
            i += 1;
            if (i >= args.len) return usageError("option '--inline-base64' requires value\n");
            inline_base64 = args[i];
        } else if (std.mem.eql(u8, arg, "--inline-file")) {
            i += 1;
            if (i >= args.len) return usageError("option '--inline-file' requires value\n");
            inline_file = args[i];
        } else {
            return usageErrorFmt("unknown option '{s}'\n", .{arg});
        }
    }
    if (url == null) {
        try printErr("--url is required\n", .{});
        std.process.exit(1);
    }

    const result = sweetcookie.get(allocator, .{
        .inline_input = .{ .json = inline_json, .base64 = inline_base64, .file = inline_file },
    }) catch |err| return runtimeError(err);
    defer result.deinit(allocator);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;
    try sweetcookie.exporter.writeCookieHeader(stdout, result.cookies, url.?);
    try stdout.writeByte('\n');
    try stdout.flush();
}

fn runtimeError(err: anyerror) noreturn {
    printErr("runtime error: {s}\n", .{@errorName(err)}) catch {};
    std.process.exit(1);
}

fn usageError(msg: []const u8) noreturn {
    printErr("{s}", .{msg}) catch {};
    std.process.exit(2);
}

fn usageErrorFmt(comptime fmt: []const u8, args: anytype) noreturn {
    printErr(fmt, args) catch {};
    std.process.exit(2);
}

fn printErr(comptime fmt: []const u8, args: anytype) !void {
    var buffer: [256]u8 = undefined;
    var writer = std.fs.File.stderr().writer(&buffer);
    const stderr = &writer.interface;
    try stderr.print(fmt, args);
    try stderr.flush();
}
