const std = @import("std");

const repo_root = ".";
const readme_path = "README.md";

fn runBlock(allocator: std.mem.Allocator, script: []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "bash", "-c", script },
        .cwd = repo_root,
        .max_output_bytes = 1024 * 1024,
    });
}

fn checkBlockSyntax(allocator: std.mem.Allocator, script: []const u8) !std.process.Child.RunResult {
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "bash", "-n", "-c", script },
        .cwd = repo_root,
        .max_output_bytes = 1024 * 1024,
    });
}

fn expectExit0(result: std.process.Child.RunResult, context: []const u8) !void {
    if (result.term != .Exited or result.term.Exited != 0) {
        std.debug.print("README shell block failed in {s}\nstdout:\n{s}\nstderr:\n{s}\n", .{ context, result.stdout, result.stderr });
    }
    try std.testing.expect(result.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), result.term.Exited);
}

fn expectContains(readme: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, readme, needle) != null);
}

test "README has required usage documentation sections" {
    const allocator = std.testing.allocator;
    const readme = try std.fs.cwd().readFileAlloc(allocator, readme_path, 1024 * 1024);
    defer allocator.free(readme);

    try expectContains(readme, "## Project overview");
    try expectContains(readme, "## Installation");
    try expectContains(readme, "## Library usage");
    try expectContains(readme, "## CLI usage");
    try expectContains(readme, "## Cookie model semantics");
    try expectContains(readme, "## Security notes");
    try expectContains(readme, "import(\"sweetcookie\")");
    try expectContains(readme, "--all-domains");
    try expectContains(readme, "0600");
    try expectContains(readme, "SWEETCOOKIE_ALLOW_REAL_BROWSER=1");
}

test "README fenced shell examples pass bash syntax and exit zero" {
    const allocator = std.testing.allocator;
    const readme = try std.fs.cwd().readFileAlloc(allocator, readme_path, 1024 * 1024);
    defer allocator.free(readme);

    var search_from: usize = 0;
    var shell_blocks: usize = 0;
    while (std.mem.indexOfPos(u8, readme, search_from, "```sh")) |fence_start| {
        const line_end = std.mem.indexOfScalarPos(u8, readme, fence_start, '\n') orelse return error.MalformedFence;
        const body_start = line_end + 1;
        const fence_end = std.mem.indexOfPos(u8, readme, body_start, "```") orelse return error.MalformedFence;
        const block = readme[body_start..fence_end];
        shell_blocks += 1;

        const syntax = try checkBlockSyntax(allocator, block);
        defer allocator.free(syntax.stdout);
        defer allocator.free(syntax.stderr);
        try expectExit0(syntax, "bash -n");

        const result = try runBlock(allocator, block);
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try expectExit0(result, "bash");

        search_from = fence_end + 3;
    }

    try std.testing.expect(shell_blocks >= 4);
}
