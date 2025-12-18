const std = @import("std");
const builtin = @import("builtin");
const linux = @import("sys-linux");

test {
    if (builtin.target.os.tag != .linux) return;
}
