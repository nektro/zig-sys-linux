const std = @import("std");
const builtin = @import("builtin");
const linux = @import("sys-linux");

test {
    if (builtin.target.os.tag != .linux) return;
    _ = &linux.read;
    _ = &linux.getpid;
    _ = &linux.exit;
    _ = &linux.getenv;
    _ = &linux.openat;
    _ = &linux.close;
    _ = &linux.fstat;
    _ = &linux.readv;
    _ = &linux.mkdirat;
    _ = &linux.pthread_self;
    _ = &linux.gettid;
    _ = &linux.fstatat;
    _ = &linux.socket;
    _ = &linux.listen;
    _ = &linux.bind;
    _ = &linux.connect;
    _ = &linux.shutdown;
    _ = &linux.setsockopt;
    _ = &linux.accept4;
    _ = &linux.send;
    _ = &linux.recv;
    _ = &linux.getaddrinfo;
}
