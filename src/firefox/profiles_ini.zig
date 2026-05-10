const std = @import("std");

pub const Profile = struct {
    name: []const u8,
    path: []const u8,
    resolved_path: []const u8,
    is_relative: bool = false,
    is_default: bool = false,

    pub fn deinit(self: Profile, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.path);
        allocator.free(self.resolved_path);
    }
};

pub const ProfilesIni = struct {
    profiles: []Profile,

    pub fn deinit(self: ProfilesIni, allocator: std.mem.Allocator) void {
        for (self.profiles) |profile| profile.deinit(allocator);
        allocator.free(self.profiles);
    }

    pub fn select(self: ProfilesIni, name: ?[]const u8) !Profile {
        if (name) |wanted| {
            for (self.profiles) |profile| {
                if (std.mem.eql(u8, profile.name, wanted)) return profile;
            }
            return error.FirefoxProfileNotFound;
        }
        for (self.profiles) |profile| {
            if (profile.is_default) return profile;
        }
        if (self.profiles.len == 1) return self.profiles[0];
        return error.FirefoxProfileNotFound;
    }
};

const Builder = struct {
    active: bool = false,
    name: ?[]u8 = null,
    path: ?[]u8 = null,
    is_relative: bool = false,
    is_default: bool = false,

    fn reset(self: *Builder, allocator: std.mem.Allocator) void {
        if (self.name) |name| allocator.free(name);
        if (self.path) |path| allocator.free(path);
        self.* = .{};
    }

    fn finish(self: *Builder, allocator: std.mem.Allocator, profiles_root: []const u8, out: *std.ArrayList(Profile)) !void {
        defer self.* = .{};
        if (!self.active) {
            self.reset(allocator);
            return;
        }
        const path = self.path orelse {
            self.reset(allocator);
            return;
        };
        self.path = null;
        errdefer allocator.free(path);
        const name = self.name orelse try allocator.dupe(u8, "");
        self.name = null;
        errdefer allocator.free(name);

        const resolved_path = if (self.is_relative)
            try std.fs.path.join(allocator, &.{ profiles_root, path })
        else
            try allocator.dupe(u8, path);
        errdefer allocator.free(resolved_path);

        try out.append(allocator, .{
            .name = name,
            .path = path,
            .resolved_path = resolved_path,
            .is_relative = self.is_relative,
            .is_default = self.is_default,
        });
    }
};

pub fn parse(allocator: std.mem.Allocator, profiles_root: []const u8, contents: []const u8) !ProfilesIni {
    var profiles = std.ArrayList(Profile).empty;
    errdefer {
        for (profiles.items) |profile| profile.deinit(allocator);
        profiles.deinit(allocator);
    }

    var current = Builder{};
    defer current.reset(allocator);

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        if (line[0] == '[' and line[line.len - 1] == ']') {
            try current.finish(allocator, profiles_root, &profiles);
            const section = line[1 .. line.len - 1];
            current.active = std.mem.startsWith(u8, section, "Profile");
            continue;
        }

        if (!current.active) continue;
        const equals = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const value = std.mem.trim(u8, line[equals + 1 ..], " \t");
        if (std.mem.eql(u8, key, "Name")) {
            if (current.name) |old| allocator.free(old);
            current.name = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "Path")) {
            if (current.path) |old| allocator.free(old);
            current.path = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "IsRelative")) {
            current.is_relative = std.mem.eql(u8, value, "1");
        } else if (std.mem.eql(u8, key, "Default")) {
            current.is_default = std.mem.eql(u8, value, "1");
        }
    }
    try current.finish(allocator, profiles_root, &profiles);

    return .{ .profiles = try profiles.toOwnedSlice(allocator) };
}

pub fn load(allocator: std.mem.Allocator, profiles_root: []const u8) !ProfilesIni {
    const path = try std.fs.path.join(allocator, &.{ profiles_root, "profiles.ini" });
    defer allocator.free(path);
    const contents = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return error.MissingProfilesIni,
        else => return err,
    };
    defer allocator.free(contents);
    return parse(allocator, profiles_root, contents);
}

pub fn loadAndSelect(allocator: std.mem.Allocator, profiles_root: []const u8, name: ?[]const u8) !struct { ini: ProfilesIni, profile: Profile } {
    const ini = try load(allocator, profiles_root);
    errdefer ini.deinit(allocator);
    return .{ .ini = ini, .profile = try ini.select(name) };
}

test "profiles.ini parses a single relative profile and selects it" {
    const root = "/tmp/firefox-root";
    const ini = try parse(std.testing.allocator, root,
        \\[Profile0]
        \\Name=default
        \\IsRelative=1
        \\Path=Profiles/abc.default-release
        \\
    );
    defer ini.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), ini.profiles.len);
    const selected = try ini.select(null);
    try std.testing.expectEqualStrings("default", selected.name);
    try std.testing.expectEqual(true, selected.is_relative);
    try std.testing.expectEqualStrings("Profiles/abc.default-release", selected.path);
    try std.testing.expectEqualStrings("/tmp/firefox-root/Profiles/abc.default-release", selected.resolved_path);
}

test "profiles.ini selects default profile when no name is given" {
    const ini = try parse(std.testing.allocator, "/root",
        \\[Profile0]
        \\Name=other
        \\IsRelative=1
        \\Path=Profiles/other
        \\Default=0
        \\
        \\[Profile1]
        \\Name=work
        \\IsRelative=1
        \\Path=Profiles/work
        \\Default=1
        \\
    );
    defer ini.deinit(std.testing.allocator);

    const selected = try ini.select(null);
    try std.testing.expectEqualStrings("work", selected.name);
    try std.testing.expectEqualStrings("/root/Profiles/work", selected.resolved_path);
}

test "profiles.ini selects named profile regardless of default flag" {
    const ini = try parse(std.testing.allocator, "/root",
        \\[Profile0]
        \\Name=default
        \\IsRelative=1
        \\Path=Profiles/default
        \\Default=1
        \\
        \\[Profile1]
        \\Name=other
        \\IsRelative=1
        \\Path=Profiles/other
        \\Default=0
        \\
    );
    defer ini.deinit(std.testing.allocator);

    const selected = try ini.select("other");
    try std.testing.expectEqualStrings("other", selected.name);
    try std.testing.expectEqualStrings("/root/Profiles/other", selected.resolved_path);
}

test "profiles.ini reports missing file clearly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    try std.testing.expectError(error.MissingProfilesIni, load(std.testing.allocator, root));
}

test "profiles.ini preserves absolute path entries" {
    const ini = try parse(std.testing.allocator, "/root",
        \\[Profile0]
        \\Name=abs
        \\IsRelative=0
        \\Path=/var/tmp/firefox/abs
        \\Default=1
        \\
    );
    defer ini.deinit(std.testing.allocator);

    const selected = try ini.select(null);
    try std.testing.expectEqual(false, selected.is_relative);
    try std.testing.expectEqualStrings("/var/tmp/firefox/abs", selected.resolved_path);
}
