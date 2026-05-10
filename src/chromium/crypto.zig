const std = @import("std");

pub const CryptoError = error{
    InvalidKeyLength,
    InvalidIvLength,
    InvalidNonceLength,
    InvalidTagLength,
    InvalidCiphertextLength,
    InvalidPadding,
    BadTag,
};

pub fn pbkdf2_hmac_sha1(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    dk_len: usize,
) ![]u8 {
    const out = try allocator.alloc(u8, dk_len);
    errdefer allocator.free(out);
    try std.crypto.pwhash.pbkdf2(out, password, salt, iterations, std.crypto.auth.hmac.HmacSha1);
    return out;
}

pub fn chromium_default_mac_key(allocator: std.mem.Allocator) ![]u8 {
    return pbkdf2_hmac_sha1(allocator, "peanuts", "saltysalt", 1003, 16);
}

pub fn aes128_cbc_decrypt(
    allocator: std.mem.Allocator,
    key: []const u8,
    iv: []const u8,
    ciphertext: []const u8,
) ![]u8 {
    if (key.len != 16) return error.InvalidKeyLength;
    if (iv.len != 16) return error.InvalidIvLength;
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return error.InvalidCiphertextLength;

    var key_block: [16]u8 = undefined;
    @memcpy(&key_block, key);
    var previous: [16]u8 = undefined;
    @memcpy(&previous, iv);

    const out = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(out);

    const aes = std.crypto.core.aes.Aes128.initDec(key_block);
    var offset: usize = 0;
    while (offset < ciphertext.len) : (offset += 16) {
        var decrypted: [16]u8 = undefined;
        aes.decrypt(&decrypted, ciphertext[offset..][0..16]);
        for (&decrypted, previous) |*byte, prev| {
            byte.* ^= prev;
        }
        @memcpy(out[offset..][0..16], &decrypted);
        @memcpy(&previous, ciphertext[offset..][0..16]);
    }

    const plaintext_len = try pkcs7UnpaddedLen(out);
    return try allocator.realloc(out, plaintext_len);
}

pub fn aes256_gcm_decrypt(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
) ![]u8 {
    const Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    if (key.len != Gcm.key_length) return error.InvalidKeyLength;
    if (nonce.len != Gcm.nonce_length) return error.InvalidNonceLength;
    if (tag.len != Gcm.tag_length) return error.InvalidTagLength;

    var key_block: [Gcm.key_length]u8 = undefined;
    @memcpy(&key_block, key);
    var nonce_block: [Gcm.nonce_length]u8 = undefined;
    @memcpy(&nonce_block, nonce);
    var tag_block: [Gcm.tag_length]u8 = undefined;
    @memcpy(&tag_block, tag);

    const out = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(out);

    Gcm.decrypt(out, ciphertext, tag_block, "", nonce_block, key_block) catch |err| switch (err) {
        error.AuthenticationFailed => return error.BadTag,
    };
    return out;
}

pub fn strip_hash_prefix(plaintext: []const u8, meta_version: i64) []const u8 {
    if (meta_version >= 24 and plaintext.len >= 32) return plaintext[32..];
    return plaintext;
}

fn pkcs7UnpaddedLen(buf: []const u8) CryptoError!usize {
    const pad_len = buf[buf.len - 1];
    if (pad_len == 0 or pad_len > 16 or pad_len > buf.len) return error.InvalidPadding;

    const padding = buf[buf.len - pad_len ..];
    for (padding) |byte| {
        if (byte != pad_len) return error.InvalidPadding;
    }
    return buf.len - pad_len;
}

test "pbkdf2_hmac_sha1 matches RFC 6070 vector 2" {
    const got = try pbkdf2_hmac_sha1(std.testing.allocator, "password", "salt", 2, 20);
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualSlices(u8, &hexToBytes("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"), got);
}

test "chromium_default_mac_key matches Chromium peanuts saltysalt key" {
    const got = try chromium_default_mac_key(std.testing.allocator);
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualSlices(u8, &hexToBytes("d9a09d499b4e1b7461f28e67972c6dbd"), got);
}

test "aes128_cbc_decrypt removes PKCS7 padding for known vector" {
    const key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
    const iv = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const ciphertext = hexToBytes("7f6a6799424a4051e8038b8bf881a637fecd04073e5a783dbcd8b5a0398a16a7");

    const plaintext = try aes128_cbc_decrypt(std.testing.allocator, &key, &iv, &ciphertext);
    defer std.testing.allocator.free(plaintext);

    try std.testing.expectEqualStrings("Single block msg", plaintext);
}

test "aes128_cbc_decrypt rejects invalid PKCS7 padding" {
    const key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
    const iv = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const ciphertext = hexToBytes("7649abac8119b246cee98e9b12e9197d");

    try std.testing.expectError(error.InvalidPadding, aes128_cbc_decrypt(std.testing.allocator, &key, &iv, &ciphertext));
}

test "aes256_gcm_decrypt matches known vector" {
    const key = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    const nonce = hexToBytes("000000000000000000000000");
    const ciphertext = hexToBytes("a6c22c51224008067521a8bacf9ebd7f110d");
    const tag = hexToBytes("92b98708cdc9973800feb2580d223ead");

    const plaintext = try aes256_gcm_decrypt(std.testing.allocator, &key, &nonce, &ciphertext, &tag);
    defer std.testing.allocator.free(plaintext);

    try std.testing.expectEqualStrings("hello chromium gcm", plaintext);
}

test "aes256_gcm_decrypt rejects bad tag" {
    const key = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    const nonce = hexToBytes("000000000000000000000000");
    const ciphertext = hexToBytes("a6c22c51224008067521a8bacf9ebd7f110d");
    const tag = hexToBytes("92b98708cdc9973800feb2580d223ead");
    var bad_tag = tag;
    bad_tag[0] ^= 0x01;

    try std.testing.expectError(error.BadTag, aes256_gcm_decrypt(std.testing.allocator, &key, &nonce, &ciphertext, &bad_tag));
}

test "strip_hash_prefix strips only for meta version 24 and later" {
    const prefixed = "0123456789abcdef0123456789abcdefreal-value";

    try std.testing.expectEqualStrings(prefixed, strip_hash_prefix(prefixed, 23));
    try std.testing.expectEqualStrings("real-value", strip_hash_prefix(prefixed, 24));
    try std.testing.expectEqualStrings("real-value", strip_hash_prefix(prefixed, 99));
}

test "strip_hash_prefix leaves short v24 plaintext unchanged" {
    try std.testing.expectEqualStrings("short", strip_hash_prefix("short", 24));
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
