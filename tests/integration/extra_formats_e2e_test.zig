const std = @import("std");
const echo_server = @import("echo_server");

const exe = "zig-out/bin/sweetcookie";
const fixture_json =
    \\[
    \\  {"name":"sid","value":"fixture","domain":"127.0.0.1","path":"/","expires":4102444800,"sameSite":"Lax"},
    \\  {"name":"theme","value":"dark","domain":"127.0.0.1","path":"/","expires":4102444800}
    \\]
;
const echo_url = "http://127.0.0.1:3110/echo";

fn run(argv: []const []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    });
}

fn runCwd(argv: []const []const u8, cwd: []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = argv,
        .cwd = cwd,
        .max_output_bytes = 4 * 1024 * 1024,
    });
}

fn expectExit0(res: std.process.Child.RunResult) !void {
    try std.testing.expect(res.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), res.term.Exited);
}

fn commandAvailable(name: []const u8, label: []const u8) !void {
    const res = try run(&.{ "which", name });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    if (res.term != .Exited or res.term.Exited != 0) {
        std.debug.print("{s} unavailable: required executable '{s}' not found\n", .{ label, name });
        return error.SkipZigTest;
    }
}

fn tmpPath(tmp: *std.testing.TmpDir, parts: []const []const u8) ![]u8 {
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    var list = std.ArrayList([]const u8).empty;
    defer list.deinit(std.testing.allocator);
    try list.append(std.testing.allocator, root);
    for (parts) |part| try list.append(std.testing.allocator, part);
    return std.fs.path.join(std.testing.allocator, list.items);
}

fn exportFixture(format: []const u8, output: []const u8) !void {
    const res = try run(&.{ exe, "export", "--inline-json", fixture_json, "--format", format, "--output", output });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    if (res.term != .Exited or res.term.Exited != 0) {
        std.debug.print("export --format {s} failed\nstdout:\n{s}\nstderr:\n{s}\n", .{ format, res.stdout, res.stderr });
    }
    try expectExit0(res);
}

fn installNodePackage(cwd: []const u8, package: []const u8, label: []const u8) !void {
    const res = try runCwd(&.{ "npm", "install", "--no-save", "--silent", package }, cwd);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    if (res.term != .Exited or res.term.Exited != 0) {
        std.debug.print("{s} unavailable: npm install {s} failed\nstdout:\n{s}\nstderr:\n{s}\n", .{ label, package, res.stdout, res.stderr });
        return error.SkipZigTest;
    }
}

test "VAL-NETSCAPE-020 curl receives cookie from Netscape jar" {
    try commandAvailable("curl", "curl");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try tmpPath(&tmp, &.{"cookies.txt"});
    defer std.testing.allocator.free(jar_path);
    try exportFixture("netscape", jar_path);

    var server = try echo_server.EchoServer.start(std.testing.allocator);
    defer server.deinit();

    const res = try run(&.{ "curl", "-b", jar_path, "-s", echo_url });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    try expectExit0(res);
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "sid=fixture"));
}

test "VAL-HTTPIE-013 HTTPie session sends Cookie header" {
    try commandAvailable("http", "httpie");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const session_path = try tmpPath(&tmp, &.{"session.json"});
    defer std.testing.allocator.free(session_path);
    try exportFixture("httpie", session_path);

    var server = try echo_server.EchoServer.start(std.testing.allocator);
    defer server.deinit();

    const session_arg = try std.fmt.allocPrint(std.testing.allocator, "--session-read-only={s}", .{session_path});
    defer std.testing.allocator.free(session_arg);
    const res = try run(&.{ "http", session_arg, "-p", "H", "GET", echo_url });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    if (res.term != .Exited or res.term.Exited != 0) {
        std.debug.print("httpie request failed\nstdout:\n{s}\nstderr:\n{s}\n", .{ res.stdout, res.stderr });
    }
    try expectExit0(res);
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "Cookie:"));
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "sid=fixture"));
}

test "VAL-PLAYWRIGHT-014 Playwright storage state imports cookie" {
    try commandAvailable("node", "playwright");
    try commandAvailable("npx", "playwright");
    try commandAvailable("npm", "playwright");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try tmpPath(&tmp, &.{"state.json"});
    defer std.testing.allocator.free(state_path);
    try exportFixture("playwright", state_path);
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    try installNodePackage(root, "playwright", "playwright");

    const install = try runCwd(&.{ "npx", "playwright", "install", "chromium" }, root);
    defer std.testing.allocator.free(install.stdout);
    defer std.testing.allocator.free(install.stderr);
    if (install.term != .Exited or install.term.Exited != 0) {
        std.debug.print("playwright unavailable: npx playwright install chromium failed\nstdout:\n{s}\nstderr:\n{s}\n", .{ install.stdout, install.stderr });
        return error.SkipZigTest;
    }

    try tmp.dir.writeFile(.{ .sub_path = "playwright-import.cjs", .data = 
        \\const { chromium } = require('playwright');
        \\(async () => {
        \\  const browser = await chromium.launch({ headless: true });
        \\  const context = await browser.newContext({ storageState: process.argv[2] });
        \\  const page = await context.newPage();
        \\  await page.goto('http://127.0.0.1:3110/echo');
        \\  const cookies = await context.cookies('http://127.0.0.1:3110/');
        \\  await browser.close();
        \\  if (!cookies.some((cookie) => cookie.name === 'sid' && cookie.value === 'fixture')) {
        \\    throw new Error('cookie missing');
        \\  }
        \\  console.log('cookie present');
        \\})().catch((err) => {
        \\  console.error(err);
        \\  process.exit(1);
        \\});
        \\
    });
    const script_path = try tmpPath(&tmp, &.{"playwright-import.cjs"});
    defer std.testing.allocator.free(script_path);

    var server = try echo_server.EchoServer.start(std.testing.allocator);
    defer server.deinit();

    const res = try runCwd(&.{ "node", script_path, state_path }, root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    if (res.term != .Exited or res.term.Exited != 0) {
        std.debug.print("playwright import failed\nstdout:\n{s}\nstderr:\n{s}\n", .{ res.stdout, res.stderr });
    }
    try expectExit0(res);
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "cookie present"));
}

test "VAL-PUPPETEER-012 Puppeteer setCookie accepts exported array" {
    try commandAvailable("node", "puppeteer");
    try commandAvailable("npm", "puppeteer");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cookies_path = try tmpPath(&tmp, &.{"cookies.json"});
    defer std.testing.allocator.free(cookies_path);
    try exportFixture("puppeteer", cookies_path);
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    try installNodePackage(root, "puppeteer", "puppeteer");

    try tmp.dir.writeFile(.{ .sub_path = "puppeteer-import.cjs", .data = 
        \\const fs = require('fs');
        \\const puppeteer = require('puppeteer');
        \\(async () => {
        \\  const browser = await puppeteer.launch({ headless: true });
        \\  const page = await browser.newPage();
        \\  const cookies = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
        \\  await page.setCookie(...cookies);
        \\  const response = await page.goto('http://127.0.0.1:3110/echo');
        \\  const body = await response.text();
        \\  await browser.close();
        \\  if (!body.includes('sid=fixture')) throw new Error(`cookie missing: ${body}`);
        \\  console.log('setCookie ok');
        \\})().catch((err) => {
        \\  console.error(err);
        \\  process.exit(1);
        \\});
        \\
    });
    const script_path = try tmpPath(&tmp, &.{"puppeteer-import.cjs"});
    defer std.testing.allocator.free(script_path);

    var server = try echo_server.EchoServer.start(std.testing.allocator);
    defer server.deinit();

    const res = try runCwd(&.{ "node", script_path, cookies_path }, root);
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    if (res.term != .Exited or res.term.Exited != 0) {
        std.debug.print("puppeteer import failed\nstdout:\n{s}\nstderr:\n{s}\n", .{ res.stdout, res.stderr });
    }
    try expectExit0(res);
    try std.testing.expect(std.mem.containsAtLeast(u8, res.stdout, 1, "setCookie ok"));
}
