const std = @import("std");
const sweetcookie = @import("sweetcookie");
const _cli = @import("cli");

const version = "0.0.0";
const Parsed = struct {
    options: sweetcookie.Options = .{},
    format: []const u8 = "lightpanda-json",
    output: ?[]const u8 = null,
    debug: bool = false,
    yes: bool = false,

    fn deinit(self: Parsed, allocator: std.mem.Allocator) void {
        allocator.free(self.options.origins);
        allocator.free(self.options.names);
        allocator.free(self.options.browsers);
    }
};

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
    if (std.mem.eql(u8, args[1], "--version")) {
        try printVersion();
        return;
    }
    if (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        try printHelp();
        return;
    }

    if (std.mem.eql(u8, args[1], "help")) return printHelp();
    if (std.mem.eql(u8, args[1], "version")) return printVersion();
    if (std.mem.eql(u8, args[1], "export")) {
        const parsed = parseArgs(allocator, args[2..]) catch |err| usageErrorFmt("usage error: {s}\n", .{@errorName(err)});
        defer parsed.deinit(allocator);
        return runExport(allocator, parsed) catch |err| {
            renderRuntimeError(allocator, err, parsed) catch {};
            std.process.exit(1);
        };
    }
    if (std.mem.eql(u8, args[1], "header")) {
        const parsed = parseArgs(allocator, args[2..]) catch |err| usageErrorFmt("usage error: {s}\n", .{@errorName(err)});
        defer parsed.deinit(allocator);
        return runHeader(allocator, parsed) catch |err| {
            renderRuntimeError(allocator, err, parsed) catch {};
            std.process.exit(1);
        };
    }
    usageErrorFmt("unknown subcommand '{s}'\n", .{args[1]});
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
        \\  sweetcookie <command> [OPTIONS]
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

fn runExport(allocator: std.mem.Allocator, parsed: Parsed) !void {
    if (!hasInputSource(parsed.options)) {
        return error.NoInputSource;
    }
    if (requiresAllDomains(parsed.options)) {
        return usageErrorFmt("chromium broad export requires --all-domains\n", .{});
    }
    try confirmAllDomainsIfNeeded(parsed);

    const result = try sweetcookie.get(allocator, parsed.options);
    defer result.deinit(allocator);
    emitWarnings(result.warnings) catch {};
    if (parsed.debug) debugCookies(result.cookies) catch {};

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);
    if (std.mem.eql(u8, parsed.format, "lightpanda-json")) {
        try sweetcookie.exporter.writeLightpandaJson(writer, result.cookies);
    } else if (std.mem.eql(u8, parsed.format, "sweet-cookie-json")) {
        try sweetcookie.exporter.writeSweetCookieJson(writer, result.cookies, .{ .generated_at_unix = std.time.timestamp(), .target_url = parsed.options.url });
    } else if (std.mem.eql(u8, parsed.format, "cookie-header")) {
        const header_url = parsed.options.url orelse {
            try printErr("--url is required for cookie-header format\n", .{});
            return error.MissingUrl;
        };
        try sweetcookie.exporter.writeCookieHeader(writer, result.cookies, header_url);
    } else {
        return usageErrorFmt("unknown format '{s}'\n", .{parsed.format});
    }

    if (parsed.output) |path| {
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

fn runHeader(allocator: std.mem.Allocator, parsed: Parsed) !void {
    if (parsed.options.url == null) {
        return error.MissingUrl;
    }
    if (!hasInputSource(parsed.options)) {
        return error.NoInputSource;
    }

    const result = try sweetcookie.get(allocator, parsed.options);
    defer result.deinit(allocator);
    emitWarnings(result.warnings) catch {};
    if (parsed.debug) debugCookies(result.cookies) catch {};

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;
    try sweetcookie.exporter.writeCookieHeader(stdout, result.cookies, parsed.options.url.?);
    try stdout.writeByte('\n');
    try stdout.flush();
}

fn hasInputSource(options: sweetcookie.Options) bool {
    if (options.inline_input.json != null or options.inline_input.base64 != null or options.inline_input.file != null) return true;
    for (options.browsers) |browser| {
        if (browser == .firefox) return true;
        if (browser == .safari) return true;
        if (isChromium(browser)) return true;
    }
    return false;
}

fn requiresAllDomains(options: sweetcookie.Options) bool {
    if (options.all_domains) return false;
    if (options.url != null or options.origins.len != 0 or options.names.len != 0) return false;
    for (options.browsers) |browser| {
        if (isChromium(browser)) return true;
    }
    return false;
}

fn isChromium(browser: sweetcookie.Browser) bool {
    return switch (browser) {
        .chrome, .chromium, .edge, .brave, .vivaldi, .opera, .arc => true,
        else => false,
    };
}

fn renderRuntimeError(allocator: std.mem.Allocator, err: anyerror, parsed: Parsed) !void {
    switch (err) {
        error.SyntaxError, error.UnexpectedEndOfInput, error.InvalidNumber, error.InvalidTopLevelTrailingWhitespace, error.InvalidCharacter, error.InvalidEscapeCharacter, error.InvalidUnicodeHexSymbol, error.InvalidUtf8Byte, error.InvalidLiteral, error.InvalidStructuralCharacter, error.InvalidStringChar, error.InvalidUseOfSurrogateHalf => {
            if (parsed.options.inline_input.base64 != null and (err == error.InvalidCharacter or err == error.InvalidPadding)) {
                try printErr("failed to decode base64 input: {s}\n", .{@errorName(err)});
                return;
            }
            if (try jsonLocationForError(allocator, parsed)) |loc| {
                try printErr("parse error at line {d}, column {d}: {s}\n", .{ loc.line, loc.column, @errorName(err) });
                return;
            }
            try printErr("parse error: {s}\n", .{@errorName(err)});
        },
        error.InvalidPadding => try printErr("failed to decode base64 input: {s}\n", .{@errorName(err)}),
        error.FileNotFound => {
            if (parsed.options.inline_input.file) |path| {
                try printErr("inline file not found: {s}\n", .{path});
            } else {
                try printErr("file not found\n", .{});
            }
        },
        error.MissingProfilesIni => try printErr("profiles.ini not found under Firefox profile root\n", .{}),
        error.FirefoxProfileNotFound => try printErr("Firefox profile not found in profiles.ini\n", .{}),
        error.RealBrowserNotPermitted => try printErr("default browser profile discovery requires SWEETCOOKIE_ALLOW_REAL_BROWSER=1\n", .{}),
        error.SafariDefaultDiscoveryDarwinOnly => try printErr("Safari default cookie discovery is darwin/macOS-only; pass --safari-cookies-file on this platform\n", .{}),
        error.NotADatabase, error.Corrupt, error.SqlError => try printErr("not a database\n", .{}),
        error.CannotOpen => try printErr("file not found or cannot open\n", .{}),
        error.MissingUrl => try printErr("header subcommand requires --url\n", .{}),
        error.NoInputSource => try printErr("no input source provided; pass --inline-json/--inline-file/--inline-base64 or a --browser flag\n", .{}),
        error.AllDomainsConfirmationDeclined => try printErr("broad export declined\n", .{}),
        else => try printErr("runtime error: {s}\n", .{@errorName(err)}),
    }
}

const JsonLocation = struct {
    line: u64,
    column: u64,
};

fn jsonLocationForError(allocator: std.mem.Allocator, parsed: Parsed) !?JsonLocation {
    if (parsed.options.inline_input.json) |json| return jsonLocation(allocator, json);
    if (parsed.options.inline_input.file) |path| {
        const file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch return null;
        defer file.close();
        const content = file.readToEndAlloc(allocator, 8 * 1024 * 1024) catch return null;
        defer allocator.free(content);
        return jsonLocation(allocator, content);
    }
    return null;
}

fn jsonLocation(allocator: std.mem.Allocator, input: []const u8) ?JsonLocation {
    var scanner = std.json.Scanner.initCompleteInput(allocator, input);
    defer scanner.deinit();
    var diagnostics = std.json.Diagnostics{};
    scanner.enableDiagnostics(&diagnostics);
    var parsed = std.json.parseFromTokenSource(std.json.Value, allocator, &scanner, .{}) catch {
        return .{ .line = diagnostics.getLine(), .column = diagnostics.getColumn() };
    };
    parsed.deinit();
    return null;
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

fn parseArgs(allocator: std.mem.Allocator, args: []const [:0]u8) !Parsed {
    var out = Parsed{ .options = .{ .allow_real_browser = sweetcookie.realbrowser.allowRealBrowserFromEnv() } };
    var origins = std.ArrayList([]const u8).empty;
    defer origins.deinit(allocator);
    var names = std.ArrayList([]const u8).empty;
    defer names.deinit(allocator);
    var browsers = std.ArrayList(sweetcookie.Browser).empty;
    defer browsers.deinit(allocator);
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--inline-json")) {
            out.options.inline_input.json = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--inline-base64")) {
            out.options.inline_input.base64 = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--inline-file")) {
            out.options.inline_input.file = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--url")) {
            out.options.url = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--origins")) {
            try origins.append(allocator, try nextArg(args, &i));
        } else if (std.mem.eql(u8, arg, "--name")) {
            try names.append(allocator, try nextArg(args, &i));
        } else if (std.mem.eql(u8, arg, "--include-expired")) {
            out.options.include_expired = true;
        } else if (std.mem.eql(u8, arg, "--format")) {
            out.format = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--output")) {
            out.output = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--debug")) {
            out.debug = true;
        } else if (std.mem.eql(u8, arg, "--browser")) {
            try browsers.append(allocator, try parseBrowser(try nextArg(args, &i)));
        } else if (std.mem.eql(u8, arg, "--mode")) {
            out.options.mode = try parseMode(try nextArg(args, &i));
        } else if (std.mem.eql(u8, arg, "--all-domains")) {
            out.options.all_domains = true;
        } else if (std.mem.eql(u8, arg, "--yes")) {
            out.yes = true;
        } else if (std.mem.eql(u8, arg, "--firefox-profile")) {
            out.options.firefox_profile = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--firefox-profile-root")) {
            out.options.firefox_profile_root = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--firefox-cookies-file")) {
            out.options.firefox_cookies_file = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--safari-cookies-file")) {
            out.options.safari_cookies_file = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--safari-cookies-root")) {
            out.options.safari_cookies_root = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--chrome-profile")) {
            out.options.chrome_profile = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--chrome-profile-root")) {
            out.options.chrome_profile_root = try nextArg(args, &i);
        } else if (std.mem.eql(u8, arg, "--chrome-cookies-db")) {
            out.options.chrome_cookies_db = try nextArg(args, &i);
        } else {
            return error.UnknownOption;
        }
    }
    out.options.origins = try origins.toOwnedSlice(allocator);
    out.options.names = try names.toOwnedSlice(allocator);
    out.options.browsers = try browsers.toOwnedSlice(allocator);
    return out;
}

fn parseBrowser(v: []const u8) !sweetcookie.Browser {
    inline for (std.meta.fields(sweetcookie.Browser)) |f| if (std.mem.eql(u8, v, f.name)) return @enumFromInt(f.value);
    return error.InvalidBrowser;
}
fn parseMode(v: []const u8) !sweetcookie.Mode {
    if (std.mem.eql(u8, v, "merge")) return .merge;
    if (std.mem.eql(u8, v, "replace")) return .replace;
    return error.InvalidMode;
}
fn nextArg(args: []const [:0]u8, i: *usize) ![]const u8 {
    i.* += 1;
    if (i.* >= args.len) return error.MissingOptionValue;
    return args[i.*];
}

fn emitWarnings(warnings: []const sweetcookie.Warning) !void {
    for (warnings) |w| {
        try printErr("warning: kind={s} message=<len={d}>\n", .{ w.kind, w.message.len });
    }
}

fn debugCookies(cookies: []const sweetcookie.Cookie) !void {
    for (cookies) |c| {
        try printErr("debug: cookie name={s} domain={s} path={s} value=<len={d}>\n", .{ c.name, c.domain, c.path, c.value.len });
    }
}

fn confirmAllDomainsIfNeeded(parsed: Parsed) !void {
    if (!parsed.options.all_domains or parsed.yes) return;
    if (!std.fs.File.stdin().isTty()) return;

    try printErr("Broad export of cookies will include credentials. Type \"yes\" to continue: ", .{});
    var input_buf: [64]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&input_buf);
    const stdin = &stdin_reader.interface;
    var answer: [8]u8 = undefined;
    var len: usize = 0;
    while (true) {
        const byte = stdin.takeByte() catch |err| switch (err) {
            error.EndOfStream => return error.AllDomainsConfirmationDeclined,
            else => return err,
        };
        if (byte == '\n' or byte == '\r') break;
        if (len >= answer.len) return error.AllDomainsConfirmationDeclined;
        answer[len] = byte;
        len += 1;
    }
    if (!std.mem.eql(u8, answer[0..len], "yes")) return error.AllDomainsConfirmationDeclined;
}
