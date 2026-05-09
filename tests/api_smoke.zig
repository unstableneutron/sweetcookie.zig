const std = @import("std");
const sweetcookie = @import("sweetcookie");

pub fn main() !void {
    const cookie = sweetcookie.Cookie{};
    const options = sweetcookie.Options{};
    const warning = sweetcookie.Warning{ .kind = "smoke", .message = "ok" };
    const result = sweetcookie.Result{ .cookies = &.{cookie}, .warnings = &.{warning} };
    const browser = sweetcookie.Browser.firefox;
    const same_site = sweetcookie.SameSite.Lax;
    const mode = sweetcookie.Mode.merge;

    _ = browser;
    _ = same_site;
    _ = mode;
    result.deinit(std.heap.page_allocator);
    _ = try sweetcookie.get(std.heap.page_allocator, options);
}
