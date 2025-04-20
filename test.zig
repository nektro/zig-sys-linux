const std = @import("std");
const builtin = @import("builtin");
const linux = @import("sys-linux");

test {
    if (builtin.target.os.tag != .linux) return;
    if (builtin.target.cpu.arch != .x86_64) return;
    _ = &linux.read;
    _ = &linux.write;
    _ = &linux.sched_yield;
}
