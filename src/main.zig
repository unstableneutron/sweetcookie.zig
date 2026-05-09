const std = @import("std");
const cli = @import("cli");
const sweetcookie = @import("sweetcookie");

const version = "0.0.0";

var export_format: []const u8 = "lightpanda-json";
var header_url: ?[]const u8 = null;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        try printHelp();
        std.process.exit(2);
    }

    if (std.mem.eql(u8, args[1], "--version")) {
        try printVersion();
        return;
    }

    try rejectUnsupportedArgs(args);

    var runner = try cli.AppRunner.init(allocator);
    const app = try makeApp(&runner);
    try runner.run(&app);
}

fn rejectUnsupportedArgs(args: []const [:0]u8) !void {
    const command = args[1];

    if (std.mem.eql(u8, command, "--help") or
        std.mem.eql(u8, command, "-h") or
        std.mem.eql(u8, command, "version") or
        std.mem.eql(u8, command, "help"))
    {
        return;
    }

    if (std.mem.eql(u8, command, "export")) {
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--format")) {
                i += 1;
                if (i >= args.len) {
                    try printErr("option '--format' requires value\n", .{});
                    std.process.exit(2);
                }
            } else if (!std.mem.startsWith(u8, arg, "--format=")) {
                try printErr("unknown option '{s}'\n", .{arg});
                std.process.exit(2);
            }
        }
        return;
    }

    if (std.mem.eql(u8, command, "header")) {
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--url")) {
                i += 1;
                if (i >= args.len) {
                    try printErr("option '--url' requires value\n", .{});
                    std.process.exit(2);
                }
            } else if (!std.mem.startsWith(u8, arg, "--url=")) {
                try printErr("unknown option '{s}'\n", .{arg});
                std.process.exit(2);
            }
        }
        return;
    }

    if (std.mem.startsWith(u8, command, "-")) {
        try printErr("unknown option '{s}'\n", .{command});
    } else {
        try printErr("unknown subcommand '{s}'\n", .{command});
    }
    std.process.exit(2);
}

fn makeApp(runner: *cli.AppRunner) !cli.App {
    const export_options = try runner.allocOptions(&.{
        .{
            .long_name = "format",
            .help = "Output format.",
            .value_ref = runner.mkRef(&export_format),
        },
    });

    const header_options = try runner.allocOptions(&.{
        .{
            .long_name = "url",
            .help = "Request URL for Cookie header output.",
            .value_ref = runner.mkRef(&header_url),
        },
    });

    const commands = try runner.allocCommands(&.{
        .{
            .name = "export",
            .description = cli.Description{ .one_line = "Export cookies." },
            .options = export_options,
            .target = cli.CommandTarget{ .action = cli.CommandAction{ .exec = exportCommand } },
        },
        .{
            .name = "header",
            .description = cli.Description{ .one_line = "Print a Cookie header." },
            .options = header_options,
            .target = cli.CommandTarget{ .action = cli.CommandAction{ .exec = headerCommand } },
        },
        .{
            .name = "version",
            .description = cli.Description{ .one_line = "Print the sweetcookie version." },
            .target = cli.CommandTarget{ .action = cli.CommandAction{ .exec = versionCommand } },
        },
        .{
            .name = "help",
            .description = cli.Description{ .one_line = "Print help." },
            .target = cli.CommandTarget{ .action = cli.CommandAction{ .exec = helpCommand } },
        },
    });

    return cli.App{
        .command = cli.Command{
            .name = "sweetcookie",
            .description = cli.Description{ .one_line = "Extract and export browser cookies." },
            .target = cli.CommandTarget{ .subcommands = commands },
        },
        .version = version,
        .help_config = .{ .color_usage = .never },
    };
}

fn exportCommand() !void {
    _ = export_format;
    _ = sweetcookie.Options{};
    try printErr("no input source provided\n", .{});
    std.process.exit(1);
}

fn headerCommand() !void {
    if (header_url == null) {
        try printErr("--url is required\n", .{});
        std.process.exit(1);
    }
}

fn versionCommand() !void {
    try printVersion();
}

fn helpCommand() !void {
    try printHelp();
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

fn printErr(comptime fmt: []const u8, args: anytype) !void {
    var buffer: [256]u8 = undefined;
    var writer = std.fs.File.stderr().writer(&buffer);
    const stderr = &writer.interface;
    try stderr.print(fmt, args);
    try stderr.flush();
}

test "CLI imports sam701 zig-cli API types" {
    const app = cli.App{
        .command = cli.Command{
            .name = "sweetcookie",
            .target = cli.CommandTarget{ .subcommands = &.{} },
        },
    };

    try std.testing.expectEqualStrings("sweetcookie", app.command.name);
}
