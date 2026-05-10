const std = @import("std");

const CookieMod = @import("Cookie.zig");
const OptionsMod = @import("Options.zig");
const ResultMod = @import("Result.zig");
const inline_src = @import("inline_src.zig");
const filter = @import("filter.zig");
const dedupe = @import("dedupe.zig");
pub const exporter = @import("exporter.zig");
pub const output = @import("output.zig");
pub const snapshot = @import("snapshot.zig");
pub const realbrowser = @import("realbrowser.zig");
pub const sqlite = @import("util/sqlite.zig");

pub const Browser = CookieMod.Browser;
pub const SameSite = CookieMod.SameSite;
pub const Source = CookieMod.Source;
pub const Cookie = CookieMod.Cookie;

pub const Mode = OptionsMod.Mode;
pub const Options = OptionsMod.Options;

pub const Warning = ResultMod.Warning;
pub const Result = ResultMod.Result;

pub fn get(allocator: std.mem.Allocator, options: Options) !Result {
    var cookies = try allocator.alloc(Cookie, 0);
    errdefer {
        for (cookies) |c| c.deinit(allocator);
        allocator.free(cookies);
    }

    if (options.inline_input.json) |json| {
        const parsed = try inline_src.parseInlineJson(allocator, json);
        cookies = try appendCookies(allocator, cookies, parsed);
    }
    if (options.inline_input.base64) |b64| {
        const parsed = try inline_src.parseInlineBase64(allocator, b64);
        cookies = try appendCookies(allocator, cookies, parsed);
    }
    if (options.inline_input.file) |path| {
        const parsed = try inline_src.parseInlineFile(allocator, path);
        cookies = try appendCookies(allocator, cookies, parsed);
    }

    const by_url = try filter.filterByUrl(allocator, cookies, options.url);
    freeCookies(allocator, cookies);
    const by_origins = try filter.filterByOrigins(allocator, by_url, options.origins);
    freeCookies(allocator, by_url);
    const by_names = try filter.filterByNames(allocator, by_origins, options.names);
    freeCookies(allocator, by_origins);
    const non_expired = try filter.filterExpired(allocator, by_names, options.include_expired, std.time.timestamp());
    freeCookies(allocator, by_names);
    cookies = try dedupe.dedupeLastWins(allocator, non_expired);
    freeCookies(allocator, non_expired);

    return .{
        .cookies = cookies,
        .warnings = try allocator.alloc(Warning, 0),
    };
}

fn appendCookies(allocator: std.mem.Allocator, existing: []Cookie, added: []Cookie) ![]Cookie {
    const out = try allocator.alloc(Cookie, existing.len + added.len);
    var i: usize = 0;
    for (existing) |c| {
        out[i] = c;
        i += 1;
    }
    for (added) |c| {
        out[i] = c;
        i += 1;
    }
    allocator.free(existing);
    allocator.free(added);
    return out;
}

fn freeCookies(allocator: std.mem.Allocator, cookies: []Cookie) void {
    for (cookies) |c| c.deinit(allocator);
    allocator.free(cookies);
}

test "public API get runs inline then filter and dedupe" {
    const input =
        \\[
        \\{"name":"a","value":"1","domain":"example.com","path":"/","expires":4102444800},
        \\{"name":"a","value":"2","domain":"EXAMPLE.COM","path":"/","expires":4102444800}
        \\]
    ;
    const result = try get(std.testing.allocator, .{
        .inline_input = .{ .json = input },
        .url = "https://example.com/",
    });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.cookies.len);
    try std.testing.expectEqualStrings("2", result.cookies[0].value);
    try std.testing.expectEqual(@as(usize, 0), result.warnings.len);
}

test "exporter writes lightpanda json array" {
    const cookies = try std.testing.allocator.alloc(Cookie, 1);
    defer std.testing.allocator.free(cookies);
    cookies[0] = try Cookie.fromRawDomain(std.testing.allocator, ".example.com", "a", "1", "/", 1, false, false, null, .{});
    defer cookies[0].deinit(std.testing.allocator);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try exporter.writeLightpandaJson(out.writer(std.testing.allocator), cookies);
    try std.testing.expect(out.items.len > 0);
}

test "util sqlite module declarations are test reachable" {
    std.testing.refAllDecls(sqlite);
}
