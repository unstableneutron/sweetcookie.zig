const std = @import("std");

pub const apple_unix_offset_seconds: i64 = 978_307_200;
pub const chromium_unix_offset_seconds: i64 = 11_644_473_600;

pub fn appleSecondsToUnix(apple_seconds: f64) i64 {
    return apple_unix_offset_seconds + @as(i64, @intFromFloat(apple_seconds));
}

pub fn unixSecondsToApple(unix_seconds: i64) f64 {
    return @floatFromInt(unix_seconds - apple_unix_offset_seconds);
}

pub fn chromiumMicrosToUnix(chromium_micros: i64) i64 {
    return @divTrunc(chromium_micros, std.time.us_per_s) - chromium_unix_offset_seconds;
}

pub fn unixSecondsToChromiumMicros(unix_seconds: i64) i64 {
    return (unix_seconds + chromium_unix_offset_seconds) * std.time.us_per_s;
}

test "apple epoch zero converts exactly to unix epoch offset" {
    try std.testing.expectEqual(@as(i64, 978_307_200), appleSecondsToUnix(0.0));
    try std.testing.expectEqual(@as(f64, 0.0), unixSecondsToApple(978_307_200));
}

test "apple epoch known non-zero value converts exactly" {
    try std.testing.expectEqual(@as(i64, 1_672_531_200), appleSecondsToUnix(694_224_000.0));
    try std.testing.expectEqual(@as(f64, 694_224_000.0), unixSecondsToApple(1_672_531_200));
}

test "chromium epoch conversions round trip unix seconds" {
    try std.testing.expectEqual(@as(i64, 1_705_526_400), chromiumMicrosToUnix(13_350_000_000_000_000));
    try std.testing.expectEqual(@as(i64, 13_350_000_000_000_000), unixSecondsToChromiumMicros(1_705_526_400));
}
