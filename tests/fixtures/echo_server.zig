const std = @import("std");

pub const port: u16 = 3110;
pub const address = "127.0.0.1";

pub const EchoServer = struct {
    allocator: std.mem.Allocator,
    server: *std.net.Server,
    thread: std.Thread,

    pub fn start(allocator: std.mem.Allocator) !EchoServer {
        const listen_address = try std.net.Address.parseIp(address, port);
        const server = try allocator.create(std.net.Server);
        errdefer allocator.destroy(server);
        server.* = try listen_address.listen(.{ .reuse_address = true, .kernel_backlog = 1 });
        errdefer server.deinit();

        const thread = try std.Thread.spawn(.{}, serveOnce, .{server});
        return .{ .allocator = allocator, .server = server, .thread = thread };
    }

    pub fn deinit(self: *EchoServer) void {
        self.server.deinit();
        self.thread.join();
        self.allocator.destroy(self.server);
    }
};

fn serveOnce(server: *std.net.Server) void {
    serveOnceFallible(server) catch |err| {
        std.debug.print("echo server failed: {s}\n", .{@errorName(err)});
    };
}

fn serveOnceFallible(server: *std.net.Server) !void {
    const connection = try server.accept();
    defer connection.stream.close();

    var send_buffer: [4096]u8 = undefined;
    var recv_buffer: [4096]u8 = undefined;
    var connection_reader = connection.stream.reader(&recv_buffer);
    var connection_writer = connection.stream.writer(&send_buffer);
    var http_server: std.http.Server = .init(connection_reader.interface(), &connection_writer.interface);
    var request = try http_server.receiveHead();

    var cookie_header: []const u8 = "";
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "cookie")) {
            cookie_header = header.value;
            break;
        }
    }

    if (!std.mem.eql(u8, request.head.target, "/echo")) {
        try request.respond("not found", .{ .status = .not_found, .keep_alive = false });
        return;
    }

    try request.respond(cookie_header, .{
        .keep_alive = false,
        .extra_headers = &.{.{ .name = "content-type", .value = "text/plain" }},
    });
}
