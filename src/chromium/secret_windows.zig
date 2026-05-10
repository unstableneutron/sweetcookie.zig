const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const Browser = @import("../Cookie.zig").Browser;
const paths = @import("paths.zig");

pub const SecretError = error{
    UnsupportedPlatform,
    InvalidHexKey,
    NativeSecretFailed,
    InvalidCiphertextLength,
};

pub fn getStorageKey(allocator: std.mem.Allocator, browser_name: []const u8) ![]u8 {
    if (try keyFromTestEnv(allocator)) |key| return key;
    if (builtin.os.tag != .windows) return error.UnsupportedPlatform;
    const protected = protectedKeyFromBrowserLocalState(allocator, browser_name) catch return error.NativeSecretFailed;
    defer allocator.free(protected);
    const key = dpapiUnprotect(allocator, protected) catch return error.NativeSecretFailed;
    errdefer allocator.free(key);
    if (key.len != 32) return error.NativeSecretFailed;
    return key;
}

const DATA_BLOB = extern struct {
    cbData: windows.DWORD,
    pbData: ?[*]u8,
};

const BCRYPT_ALG_HANDLE = windows.HANDLE;
const BCRYPT_KEY_HANDLE = windows.HANDLE;
const NTSTATUS = windows.LONG;
const AES_ALG_ID = std.unicode.utf8ToUtf16LeStringLiteral("AES");
const BCRYPT_CHAINING_MODE = std.unicode.utf8ToUtf16LeStringLiteral("ChainingMode");
const BCRYPT_CHAIN_MODE_GCM = std.unicode.utf8ToUtf16LeStringLiteral("ChainingModeGCM");

extern "crypt32" fn CryptUnprotectData(
    pDataIn: *DATA_BLOB,
    ppszDataDescr: ?*?windows.LPWSTR,
    pOptionalEntropy: ?*DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: windows.DWORD,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn LocalFree(hMem: ?windows.HLOCAL) callconv(.winapi) ?windows.HLOCAL;

extern "bcrypt" fn BCryptOpenAlgorithmProvider(
    phAlgorithm: *BCRYPT_ALG_HANDLE,
    pszAlgId: windows.LPCWSTR,
    pszImplementation: ?windows.LPCWSTR,
    dwFlags: windows.ULONG,
) callconv(.winapi) NTSTATUS;

extern "bcrypt" fn BCryptCloseAlgorithmProvider(
    hAlgorithm: BCRYPT_ALG_HANDLE,
    dwFlags: windows.ULONG,
) callconv(.winapi) NTSTATUS;

extern "bcrypt" fn BCryptSetProperty(
    hObject: windows.HANDLE,
    pszProperty: windows.LPCWSTR,
    pbInput: [*]u8,
    cbInput: windows.ULONG,
    dwFlags: windows.ULONG,
) callconv(.winapi) NTSTATUS;

extern "bcrypt" fn BCryptGenerateSymmetricKey(
    hAlgorithm: BCRYPT_ALG_HANDLE,
    phKey: *BCRYPT_KEY_HANDLE,
    pbKeyObject: ?[*]u8,
    cbKeyObject: windows.ULONG,
    pbSecret: [*]u8,
    cbSecret: windows.ULONG,
    dwFlags: windows.ULONG,
) callconv(.winapi) NTSTATUS;

extern "bcrypt" fn BCryptDestroyKey(hKey: BCRYPT_KEY_HANDLE) callconv(.winapi) NTSTATUS;

extern "bcrypt" fn BCryptDecrypt(
    hKey: BCRYPT_KEY_HANDLE,
    pbInput: [*]u8,
    cbInput: windows.ULONG,
    pPaddingInfo: ?*anyopaque,
    pbIV: ?[*]u8,
    cbIV: windows.ULONG,
    pbOutput: ?[*]u8,
    cbOutput: windows.ULONG,
    pcbResult: *windows.ULONG,
    dwFlags: windows.ULONG,
) callconv(.winapi) NTSTATUS;

const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO = extern struct {
    cbSize: windows.ULONG,
    dwInfoVersion: windows.ULONG,
    pbNonce: ?[*]u8,
    cbNonce: windows.ULONG,
    pbAuthData: ?[*]u8,
    cbAuthData: windows.ULONG,
    pbTag: ?[*]u8,
    cbTag: windows.ULONG,
    pbMacContext: ?[*]u8,
    cbMacContext: windows.ULONG,
    cbAAD: windows.ULONG,
    cbData: windows.ULONGLONG,
    dwFlags: windows.ULONG,
};

pub fn dpapiUnprotect(allocator: std.mem.Allocator, protected: []const u8) ![]u8 {
    if (builtin.os.tag != .windows) return error.UnsupportedPlatform;
    var input = DATA_BLOB{
        .cbData = @intCast(protected.len),
        .pbData = @constCast(protected.ptr),
    };
    var output: DATA_BLOB = .{ .cbData = 0, .pbData = null };
    if (CryptUnprotectData(&input, null, null, null, null, 0, &output) == 0) return error.NativeSecretFailed;
    defer _ = LocalFree(@ptrCast(output.pbData));

    const out_ptr = output.pbData orelse return error.NativeSecretFailed;
    return allocator.dupe(u8, out_ptr[0..output.cbData]);
}

pub fn bcryptAesGcmDecrypt(
    allocator: std.mem.Allocator,
    key: []const u8,
    nonce: []const u8,
    ciphertext_and_tag: []const u8,
) ![]u8 {
    if (builtin.os.tag != .windows) return error.UnsupportedPlatform;
    if (ciphertext_and_tag.len < 16) return error.InvalidCiphertextLength;

    const ciphertext = ciphertext_and_tag[0 .. ciphertext_and_tag.len - 16];
    const tag = ciphertext_and_tag[ciphertext_and_tag.len - 16 ..];
    var alg: BCRYPT_ALG_HANDLE = undefined;
    if (BCryptOpenAlgorithmProvider(&alg, AES_ALG_ID, null, 0) != 0) return error.NativeSecretFailed;
    defer _ = BCryptCloseAlgorithmProvider(alg, 0);

    if (BCryptSetProperty(
        alg,
        BCRYPT_CHAINING_MODE,
        @ptrCast(@constCast(BCRYPT_CHAIN_MODE_GCM.ptr)),
        @intCast((BCRYPT_CHAIN_MODE_GCM.len + 1) * @sizeOf(u16)),
        0,
    ) != 0) return error.NativeSecretFailed;

    var key_handle: BCRYPT_KEY_HANDLE = undefined;
    if (BCryptGenerateSymmetricKey(alg, &key_handle, null, 0, @constCast(key.ptr), @intCast(key.len), 0) != 0) return error.NativeSecretFailed;
    defer _ = BCryptDestroyKey(key_handle);

    var auth_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO = .{
        .cbSize = @sizeOf(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
        .dwInfoVersion = 1,
        .pbNonce = @constCast(nonce.ptr),
        .cbNonce = @intCast(nonce.len),
        .pbAuthData = null,
        .cbAuthData = 0,
        .pbTag = @constCast(tag.ptr),
        .cbTag = @intCast(tag.len),
        .pbMacContext = null,
        .cbMacContext = 0,
        .cbAAD = 0,
        .cbData = 0,
        .dwFlags = 0,
    };
    const out = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(out);
    var out_len: windows.ULONG = 0;
    if (BCryptDecrypt(
        key_handle,
        @constCast(ciphertext.ptr),
        @intCast(ciphertext.len),
        &auth_info,
        null,
        0,
        out.ptr,
        @intCast(out.len),
        &out_len,
        0,
    ) != 0) return error.NativeSecretFailed;
    return allocator.realloc(out, out_len);
}

fn keyFromTestEnv(allocator: std.mem.Allocator) !?[]u8 {
    const hex = std.process.getEnvVarOwned(allocator, "SWEETCOOKIE_TEST_CHROMIUM_KEY") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    defer allocator.free(hex);
    if (hex.len % 2 != 0) return error.InvalidHexKey;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, hex) catch return error.InvalidHexKey;
    return out;
}

fn protectedKeyFromBrowserLocalState(allocator: std.mem.Allocator, browser_name: []const u8) ![]u8 {
    const browser = browserFromName(browser_name) orelse return error.NativeSecretFailed;
    const root = try paths.defaultProfileRoot(allocator, browser);
    defer allocator.free(root);
    const local_state = try std.fs.path.join(allocator, &.{ root, "Local State" });
    defer allocator.free(local_state);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, local_state, 4 * 1024 * 1024);
    defer allocator.free(bytes);
    return encryptedKeyFromLocalState(allocator, bytes);
}

fn browserFromName(name: []const u8) ?Browser {
    inline for (@typeInfo(Browser).@"enum".fields) |field| {
        if (std.ascii.eqlIgnoreCase(name, field.name)) return @enumFromInt(field.value);
    }
    return null;
}

fn encryptedKeyFromLocalState(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.NativeSecretFailed;
    const os_crypt = parsed.value.object.get("os_crypt") orelse return error.NativeSecretFailed;
    if (os_crypt != .object) return error.NativeSecretFailed;
    const encrypted_value = os_crypt.object.get("encrypted_key") orelse return error.NativeSecretFailed;
    if (encrypted_value != .string) return error.NativeSecretFailed;
    const encoded = encrypted_value.string;
    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, encoded);
    if (!std.mem.startsWith(u8, decoded, "DPAPI")) return error.NativeSecretFailed;
    const out = try allocator.dupe(u8, decoded[5..]);
    allocator.free(decoded);
    return out;
}

test "windows native secret symbols are addressable" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    try std.testing.expect(@intFromPtr(&CryptUnprotectData) != 0);
    try std.testing.expect(@intFromPtr(&BCryptOpenAlgorithmProvider) != 0);
    try std.testing.expect(@intFromPtr(&BCryptDecrypt) != 0);
}

test "windows Local State encrypted_key parser extracts DPAPI payload" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    const payload = try encryptedKeyFromLocalState(std.testing.allocator,
        \\{"os_crypt":{"encrypted_key":"RFBBUEkBAgME"}}
    );
    defer std.testing.allocator.free(payload);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, payload);
}
