const std = @import("std");
const builtin = @import("builtin");
const linux = @import("sys-linux");

test {
    if (builtin.target.os.tag != .linux) return;
    if (builtin.target.cpu.arch != .x86_64) return;
    _ = &linux.read;
    _ = &linux.write;
    _ = &linux.sched_yield;
    _ = &linux.pause;
    _ = &linux.getpid;
    _ = &linux.fork;
    _ = &linux.vfork;
    _ = &linux.getuid;
    _ = &linux.getgid;
    _ = &linux.geteuid;
    _ = &linux.getegid;
    _ = &linux.getppid;
    _ = &linux.getpgrp;
    _ = &linux.setsid;
    _ = &linux.munlockall;
    _ = &linux.vhangup;
    _ = &linux.sync;
    _ = &linux.gettid;
    _ = &linux.inotify_init;
}
