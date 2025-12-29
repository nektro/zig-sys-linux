const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

comptime {
    std.debug.assert(builtin.target.os.tag == .linux);
}

pub const errno = struct {
    pub const Error = error{
        Unexpected,
        EPERM,
        ENOENT,
        ESRCH,
        EINTR,
        EIO,
        ENXIO,
        E2BIG,
        ENOEXEC,
        EBADF,
        ECHILD,
        EAGAIN,
        ENOMEM,
        EACCES,
        EFAULT,
        ENOTBLK,
        EBUSY,
        EEXIST,
        EXDEV,
        ENODEV,
        ENOTDIR,
        EISDIR,
        EINVAL,
        ENFILE,
        EMFILE,
        ENOTTY,
        ETXTBSY,
        EFBIG,
        ENOSPC,
        ESPIPE,
        EROFS,
        EMLINK,
        EPIPE,
        EDOM,
        ERANGE,
        EDEADLK,
        ENAMETOOLONG,
        ENOLCK,
        ENOSYS,
        ENOTEMPTY,
        ELOOP,
        ENOMSG,
        EIDRM,
        ECHRNG,
        EL2NSYNC,
        EL3HLT,
        EL3RST,
        ELNRNG,
        EUNATCH,
        ENOCSI,
        EL2HLT,
        EBADE,
        EBADR,
        EXFULL,
        ENOANO,
        EBADRQC,
        EBADSLT,
        EDEADLOCK,
        EBFONT,
        ENOSTR,
        ENODATA,
        ETIME,
        ENOSR,
        ENONET,
        ENOPKG,
        EREMOTE,
        ENOLINK,
        EADV,
        ESRMNT,
        ECOMM,
        EPROTO,
        EMULTIHOP,
        EDOTDOT,
        EBADMSG,
        EOVERFLOW,
        ENOTUNIQ,
        EBADFD,
        EREMCHG,
        ELIBACC,
        ELIBBAD,
        ELIBSCN,
        ELIBMAX,
        ELIBEXEC,
        EILSEQ,
        ERESTART,
        ESTRPIPE,
        EUSERS,
        ENOTSOCK,
        EDESTADDRREQ,
        EMSGSIZE,
        EPROTOTYPE,
        ENOPROTOOPT,
        EPROTONOSUPPORT,
        ESOCKTNOSUPPORT,
        EOPNOTSUPP,
        EPFNOSUPPORT,
        EAFNOSUPPORT,
        EADDRINUSE,
        EADDRNOTAVAIL,
        ENETDOWN,
        ENETUNREACH,
        ENETRESET,
        ECONNABORTED,
        ECONNRESET,
        ENOBUFS,
        EISCONN,
        ENOTCONN,
        ESHUTDOWN,
        ETOOMANYREFS,
        ETIMEDOUT,
        ECONNREFUSED,
        EHOSTDOWN,
        EHOSTUNREACH,
        EALREADY,
        EINPROGRESS,
        ESTALE,
        EUCLEAN,
        ENOTNAM,
        ENAVAIL,
        EISNAM,
        EREMOTEIO,
        EDQUOT,
        ENOMEDIUM,
        EMEDIUMTYPE,
        ECANCELED,
        ENOKEY,
        EKEYEXPIRED,
        EKEYREVOKED,
        EKEYREJECTED,
        EOWNERDEAD,
        ENOTRECOVERABLE,
        ERFKILL,
        EHWPOISON,
    };

    pub const Enum = switch (builtin.target.cpu.arch) {
        .arc,
        .arm,
        .armeb,
        .aarch64,
        .aarch64_be,
        .csky,
        .hexagon,
        .loongarch32,
        .loongarch64,
        .m68k,
        .riscv32,
        .riscv64,
        .s390x,
        .sparc,
        .sparc64,
        .x86,
        .x86_64,
        .xtensa,
        => enum(c_ushort) {
            EPERM = 1,
            ENOENT = 2,
            ESRCH = 3,
            EINTR = 4,
            EIO = 5,
            ENXIO = 6,
            E2BIG = 7,
            ENOEXEC = 8,
            EBADF = 9,
            ECHILD = 10,
            EAGAIN = 11,
            ENOMEM = 12,
            EACCES = 13,
            EFAULT = 14,
            ENOTBLK = 15,
            EBUSY = 16,
            EEXIST = 17,
            EXDEV = 18,
            ENODEV = 19,
            ENOTDIR = 20,
            EISDIR = 21,
            EINVAL = 22,
            ENFILE = 23,
            EMFILE = 24,
            ENOTTY = 25,
            ETXTBSY = 26,
            EFBIG = 27,
            ENOSPC = 28,
            ESPIPE = 29,
            EROFS = 30,
            EMLINK = 31,
            EPIPE = 32,
            EDOM = 33,
            ERANGE = 34,
            EDEADLK = 35,
            ENAMETOOLONG = 36,
            ENOLCK = 37,
            ENOSYS = 38,
            ENOTEMPTY = 39,
            ELOOP = 40,
            ENOMSG = 42,
            EIDRM = 43,
            ECHRNG = 44,
            EL2NSYNC = 45,
            EL3HLT = 46,
            EL3RST = 47,
            ELNRNG = 48,
            EUNATCH = 49,
            ENOCSI = 50,
            EL2HLT = 51,
            EBADE = 52,
            EBADR = 53,
            EXFULL = 54,
            ENOANO = 55,
            EBADRQC = 56,
            EBADSLT = 57,
            EBFONT = 59,
            ENOSTR = 60,
            ENODATA = 61,
            ETIME = 62,
            ENOSR = 63,
            ENONET = 64,
            ENOPKG = 65,
            EREMOTE = 66,
            ENOLINK = 67,
            EADV = 68,
            ESRMNT = 69,
            ECOMM = 70,
            EPROTO = 71,
            EMULTIHOP = 72,
            EDOTDOT = 73,
            EBADMSG = 74,
            EOVERFLOW = 75,
            ENOTUNIQ = 76,
            EBADFD = 77,
            EREMCHG = 78,
            ELIBACC = 79,
            ELIBBAD = 80,
            ELIBSCN = 81,
            ELIBMAX = 82,
            ELIBEXEC = 83,
            EILSEQ = 84,
            ERESTART = 85,
            ESTRPIPE = 86,
            EUSERS = 87,
            ENOTSOCK = 88,
            EDESTADDRREQ = 89,
            EMSGSIZE = 90,
            EPROTOTYPE = 91,
            ENOPROTOOPT = 92,
            EPROTONOSUPPORT = 93,
            ESOCKTNOSUPPORT = 94,
            EOPNOTSUPP = 95,
            EPFNOSUPPORT = 96,
            EAFNOSUPPORT = 97,
            EADDRINUSE = 98,
            EADDRNOTAVAIL = 99,
            ENETDOWN = 100,
            ENETUNREACH = 101,
            ENETRESET = 102,
            ECONNABORTED = 103,
            ECONNRESET = 104,
            ENOBUFS = 105,
            EISCONN = 106,
            ENOTCONN = 107,
            ESHUTDOWN = 108,
            ETOOMANYREFS = 109,
            ETIMEDOUT = 110,
            ECONNREFUSED = 111,
            EHOSTDOWN = 112,
            EHOSTUNREACH = 113,
            EALREADY = 114,
            EINPROGRESS = 115,
            ESTALE = 116,
            EUCLEAN = 117,
            ENOTNAM = 118,
            ENAVAIL = 119,
            EISNAM = 120,
            EREMOTEIO = 121,
            EDQUOT = 122,
            ENOMEDIUM = 123,
            EMEDIUMTYPE = 124,
            ECANCELED = 125,
            ENOKEY = 126,
            EKEYEXPIRED = 127,
            EKEYREVOKED = 128,
            EKEYREJECTED = 129,
            EOWNERDEAD = 130,
            ENOTRECOVERABLE = 131,
            ERFKILL = 132,
            EHWPOISON = 133,
            _,
            pub const EWOULDBLOCK: Enum = .EAGAIN;
            pub const EDEADLOCK: Enum = .EDEADLK;
            pub const ENOTSUP: Enum = .EOPNOTSUPP;
        },
        .mips,
        .mipsel,
        => enum(c_ushort) {
            EPERM = 1,
            ENOENT = 2,
            ESRCH = 3,
            EINTR = 4,
            EIO = 5,
            ENXIO = 6,
            E2BIG = 7,
            ENOEXEC = 8,
            EBADF = 9,
            ECHILD = 10,
            EAGAIN = 11,
            ENOMEM = 12,
            EACCES = 13,
            EFAULT = 14,
            ENOTBLK = 15,
            EBUSY = 16,
            EEXIST = 17,
            EXDEV = 18,
            ENODEV = 19,
            ENOTDIR = 20,
            EISDIR = 21,
            EINVAL = 22,
            ENFILE = 23,
            EMFILE = 24,
            ENOTTY = 25,
            ETXTBSY = 26,
            EFBIG = 27,
            ENOSPC = 28,
            ESPIPE = 29,
            EROFS = 30,
            EMLINK = 31,
            EPIPE = 32,
            EDOM = 33,
            ERANGE = 34,
            ENOMSG = 35,
            EIDRM = 36,
            ECHRNG = 37,
            EL2NSYNC = 38,
            EL3HLT = 39,
            EL3RST = 40,
            ELNRNG = 41,
            EUNATCH = 42,
            ENOCSI = 43,
            EL2HLT = 44,
            EDEADLK = 45,
            ENOLCK = 46,
            EBADE = 50,
            EBADR = 51,
            EXFULL = 52,
            ENOANO = 53,
            EBADRQC = 54,
            EBADSLT = 55,
            EDEADLOCK = 56,
            EBFONT = 59,
            ENOSTR = 60,
            ENODATA = 61,
            ETIME = 62,
            ENOSR = 63,
            ENONET = 64,
            ENOPKG = 65,
            EREMOTE = 66,
            ENOLINK = 67,
            EADV = 68,
            ESRMNT = 69,
            ECOMM = 70,
            EPROTO = 71,
            EDOTDOT = 73,
            EMULTIHOP = 74,
            EBADMSG = 77,
            ENAMETOOLONG = 78,
            EOVERFLOW = 79,
            ENOTUNIQ = 80,
            EBADFD = 81,
            EREMCHG = 82,
            ELIBACC = 83,
            ELIBBAD = 84,
            ELIBSCN = 85,
            ELIBMAX = 86,
            ELIBEXEC = 87,
            EILSEQ = 88,
            ENOSYS = 89,
            ELOOP = 90,
            ERESTART = 91,
            ESTRPIPE = 92,
            ENOTEMPTY = 93,
            EUSERS = 94,
            ENOTSOCK = 95,
            EDESTADDRREQ = 96,
            EMSGSIZE = 97,
            EPROTOTYPE = 98,
            ENOPROTOOPT = 99,
            EPROTONOSUPPORT = 120,
            ESOCKTNOSUPPORT = 121,
            EOPNOTSUPP = 122,
            EPFNOSUPPORT = 123,
            EAFNOSUPPORT = 124,
            EADDRINUSE = 125,
            EADDRNOTAVAIL = 126,
            ENETDOWN = 127,
            ENETUNREACH = 128,
            ENETRESET = 129,
            ECONNABORTED = 130,
            ECONNRESET = 131,
            ENOBUFS = 132,
            EISCONN = 133,
            ENOTCONN = 134,
            EUCLEAN = 135,
            ENOTNAM = 137,
            ENAVAIL = 138,
            EISNAM = 139,
            EREMOTEIO = 140,
            ESHUTDOWN = 143,
            ETOOMANYREFS = 144,
            ETIMEDOUT = 145,
            ECONNREFUSED = 146,
            EHOSTDOWN = 147,
            EHOSTUNREACH = 148,
            EALREADY = 149,
            EINPROGRESS = 150,
            ESTALE = 151,
            ECANCELED = 158,
            ENOMEDIUM = 159,
            EMEDIUMTYPE = 160,
            ENOKEY = 161,
            EKEYEXPIRED = 162,
            EKEYREVOKED = 163,
            EKEYREJECTED = 164,
            EOWNERDEAD = 165,
            ENOTRECOVERABLE = 166,
            ERFKILL = 167,
            EHWPOISON = 168,
            EDQUOT = 1133,
            _,
            pub const ENOTSUP: Enum = .EOPNOTSUPP;
            pub const EWOULDBLOCK: Enum = .EAGAIN;
        },
        .mips64,
        .mips64el,
        => enum(c_ushort) {
            EPERM = 1,
            ENOENT = 2,
            ESRCH = 3,
            EINTR = 4,
            EIO = 5,
            ENXIO = 6,
            E2BIG = 7,
            ENOEXEC = 8,
            EBADF = 9,
            ECHILD = 10,
            EAGAIN = 11,
            ENOMEM = 12,
            EACCES = 13,
            EFAULT = 14,
            ENOTBLK = 15,
            EBUSY = 16,
            EEXIST = 17,
            EXDEV = 18,
            ENODEV = 19,
            ENOTDIR = 20,
            EISDIR = 21,
            EINVAL = 22,
            ENFILE = 23,
            EMFILE = 24,
            ENOTTY = 25,
            ETXTBSY = 26,
            EFBIG = 27,
            ENOSPC = 28,
            ESPIPE = 29,
            EROFS = 30,
            EMLINK = 31,
            EPIPE = 32,
            EDOM = 33,
            ERANGE = 34,
            ENOMSG = 35,
            EIDRM = 36,
            ECHRNG = 37,
            EL2NSYNC = 38,
            EL3HLT = 39,
            EL3RST = 40,
            ELNRNG = 41,
            EUNATCH = 42,
            ENOCSI = 43,
            EL2HLT = 44,
            EDEADLK = 45,
            ENOLCK = 46,
            EBADE = 50,
            EBADR = 51,
            EXFULL = 52,
            ENOANO = 53,
            EBADRQC = 54,
            EBADSLT = 55,
            EDEADLOCK = 56,
            EBFONT = 59,
            ENOSTR = 60,
            ENODATA = 61,
            ETIME = 62,
            ENOSR = 63,
            ENONET = 64,
            ENOPKG = 65,
            EREMOTE = 66,
            ENOLINK = 67,
            EADV = 68,
            ESRMNT = 69,
            ECOMM = 70,
            EPROTO = 71,
            EDOTDOT = 73,
            EMULTIHOP = 74,
            EBADMSG = 77,
            ENAMETOOLONG = 78,
            EOVERFLOW = 79,
            ENOTUNIQ = 80,
            EBADFD = 81,
            EREMCHG = 82,
            ELIBACC = 83,
            ELIBBAD = 84,
            ELIBSCN = 85,
            ELIBMAX = 86,
            ELIBEXEC = 87,
            EILSEQ = 88,
            ENOSYS = 89,
            ELOOP = 90,
            ERESTART = 91,
            ESTRPIPE = 92,
            ENOTEMPTY = 93,
            EUSERS = 94,
            ENOTSOCK = 95,
            EDESTADDRREQ = 96,
            EMSGSIZE = 97,
            EPROTOTYPE = 98,
            ENOPROTOOPT = 99,
            EPROTONOSUPPORT = 120,
            ESOCKTNOSUPPORT = 121,
            EOPNOTSUPP = 122,
            EPFNOSUPPORT = 123,
            EAFNOSUPPORT = 124,
            EADDRINUSE = 125,
            EADDRNOTAVAIL = 126,
            ENETDOWN = 127,
            ENETUNREACH = 128,
            ENETRESET = 129,
            ECONNABORTED = 130,
            ECONNRESET = 131,
            ENOBUFS = 132,
            EISCONN = 133,
            ENOTCONN = 134,
            EUCLEAN = 135,
            ENOTNAM = 137,
            ENAVAIL = 138,
            EISNAM = 139,
            EREMOTEIO = 140,
            ESHUTDOWN = 143,
            ETOOMANYREFS = 144,
            ETIMEDOUT = 145,
            ECONNREFUSED = 146,
            EHOSTDOWN = 147,
            EHOSTUNREACH = 148,
            EALREADY = 149,
            EINPROGRESS = 150,
            ESTALE = 151,
            ECANCELED = 158,
            ENOMEDIUM = 159,
            EMEDIUMTYPE = 160,
            ENOKEY = 161,
            EKEYEXPIRED = 162,
            EKEYREVOKED = 163,
            EKEYREJECTED = 164,
            EOWNERDEAD = 165,
            ENOTRECOVERABLE = 166,
            ERFKILL = 167,
            EHWPOISON = 168,
            EDQUOT = 1133,
            _,
            pub const ENOTSUP: Enum = .EOPNOTSUPP;
            pub const EWOULDBLOCK: Enum = .EAGAIN;
        },
        .powerpc,
        .powerpcle,
        => enum(c_ushort) {
            EPERM = 1,
            ENOENT = 2,
            ESRCH = 3,
            EINTR = 4,
            EIO = 5,
            ENXIO = 6,
            E2BIG = 7,
            ENOEXEC = 8,
            EBADF = 9,
            ECHILD = 10,
            EAGAIN = 11,
            ENOMEM = 12,
            EACCES = 13,
            EFAULT = 14,
            ENOTBLK = 15,
            EBUSY = 16,
            EEXIST = 17,
            EXDEV = 18,
            ENODEV = 19,
            ENOTDIR = 20,
            EISDIR = 21,
            EINVAL = 22,
            ENFILE = 23,
            EMFILE = 24,
            ENOTTY = 25,
            ETXTBSY = 26,
            EFBIG = 27,
            ENOSPC = 28,
            ESPIPE = 29,
            EROFS = 30,
            EMLINK = 31,
            EPIPE = 32,
            EDOM = 33,
            ERANGE = 34,
            EDEADLK = 35,
            ENAMETOOLONG = 36,
            ENOLCK = 37,
            ENOSYS = 38,
            ENOTEMPTY = 39,
            ELOOP = 40,
            ENOMSG = 42,
            EIDRM = 43,
            ECHRNG = 44,
            EL2NSYNC = 45,
            EL3HLT = 46,
            EL3RST = 47,
            ELNRNG = 48,
            EUNATCH = 49,
            ENOCSI = 50,
            EL2HLT = 51,
            EBADE = 52,
            EBADR = 53,
            EXFULL = 54,
            ENOANO = 55,
            EBADRQC = 56,
            EBADSLT = 57,
            EDEADLOCK = 58,
            EBFONT = 59,
            ENOSTR = 60,
            ENODATA = 61,
            ETIME = 62,
            ENOSR = 63,
            ENONET = 64,
            ENOPKG = 65,
            EREMOTE = 66,
            ENOLINK = 67,
            EADV = 68,
            ESRMNT = 69,
            ECOMM = 70,
            EPROTO = 71,
            EMULTIHOP = 72,
            EDOTDOT = 73,
            EBADMSG = 74,
            EOVERFLOW = 75,
            ENOTUNIQ = 76,
            EBADFD = 77,
            EREMCHG = 78,
            ELIBACC = 79,
            ELIBBAD = 80,
            ELIBSCN = 81,
            ELIBMAX = 82,
            ELIBEXEC = 83,
            EILSEQ = 84,
            ERESTART = 85,
            ESTRPIPE = 86,
            EUSERS = 87,
            ENOTSOCK = 88,
            EDESTADDRREQ = 89,
            EMSGSIZE = 90,
            EPROTOTYPE = 91,
            ENOPROTOOPT = 92,
            EPROTONOSUPPORT = 93,
            ESOCKTNOSUPPORT = 94,
            EOPNOTSUPP = 95,
            EPFNOSUPPORT = 96,
            EAFNOSUPPORT = 97,
            EADDRINUSE = 98,
            EADDRNOTAVAIL = 99,
            ENETDOWN = 100,
            ENETUNREACH = 101,
            ENETRESET = 102,
            ECONNABORTED = 103,
            ECONNRESET = 104,
            ENOBUFS = 105,
            EISCONN = 106,
            ENOTCONN = 107,
            ESHUTDOWN = 108,
            ETOOMANYREFS = 109,
            ETIMEDOUT = 110,
            ECONNREFUSED = 111,
            EHOSTDOWN = 112,
            EHOSTUNREACH = 113,
            EALREADY = 114,
            EINPROGRESS = 115,
            ESTALE = 116,
            EUCLEAN = 117,
            ENOTNAM = 118,
            ENAVAIL = 119,
            EISNAM = 120,
            EREMOTEIO = 121,
            EDQUOT = 122,
            ENOMEDIUM = 123,
            EMEDIUMTYPE = 124,
            ECANCELED = 125,
            ENOKEY = 126,
            EKEYEXPIRED = 127,
            EKEYREVOKED = 128,
            EKEYREJECTED = 129,
            EOWNERDEAD = 130,
            ENOTRECOVERABLE = 131,
            ERFKILL = 132,
            EHWPOISON = 133,
            _,
            pub const EWOULDBLOCK: Enum = .EAGAIN;
            pub const ENOTSUP: Enum = .EOPNOTSUPP;
        },
        .powerpc64,
        .powerpc64le,
        => enum(c_ushort) {
            EPERM = 1,
            ENOENT = 2,
            ESRCH = 3,
            EINTR = 4,
            EIO = 5,
            ENXIO = 6,
            E2BIG = 7,
            ENOEXEC = 8,
            EBADF = 9,
            ECHILD = 10,
            EAGAIN = 11,
            ENOMEM = 12,
            EACCES = 13,
            EFAULT = 14,
            ENOTBLK = 15,
            EBUSY = 16,
            EEXIST = 17,
            EXDEV = 18,
            ENODEV = 19,
            ENOTDIR = 20,
            EISDIR = 21,
            EINVAL = 22,
            ENFILE = 23,
            EMFILE = 24,
            ENOTTY = 25,
            ETXTBSY = 26,
            EFBIG = 27,
            ENOSPC = 28,
            ESPIPE = 29,
            EROFS = 30,
            EMLINK = 31,
            EPIPE = 32,
            EDOM = 33,
            ERANGE = 34,
            EDEADLK = 35,
            ENAMETOOLONG = 36,
            ENOLCK = 37,
            ENOSYS = 38,
            ENOTEMPTY = 39,
            ELOOP = 40,
            ENOMSG = 42,
            EIDRM = 43,
            ECHRNG = 44,
            EL2NSYNC = 45,
            EL3HLT = 46,
            EL3RST = 47,
            ELNRNG = 48,
            EUNATCH = 49,
            ENOCSI = 50,
            EL2HLT = 51,
            EBADE = 52,
            EBADR = 53,
            EXFULL = 54,
            ENOANO = 55,
            EBADRQC = 56,
            EBADSLT = 57,
            EDEADLOCK = 58,
            EBFONT = 59,
            ENOSTR = 60,
            ENODATA = 61,
            ETIME = 62,
            ENOSR = 63,
            ENONET = 64,
            ENOPKG = 65,
            EREMOTE = 66,
            ENOLINK = 67,
            EADV = 68,
            ESRMNT = 69,
            ECOMM = 70,
            EPROTO = 71,
            EMULTIHOP = 72,
            EDOTDOT = 73,
            EBADMSG = 74,
            EOVERFLOW = 75,
            ENOTUNIQ = 76,
            EBADFD = 77,
            EREMCHG = 78,
            ELIBACC = 79,
            ELIBBAD = 80,
            ELIBSCN = 81,
            ELIBMAX = 82,
            ELIBEXEC = 83,
            EILSEQ = 84,
            ERESTART = 85,
            ESTRPIPE = 86,
            EUSERS = 87,
            ENOTSOCK = 88,
            EDESTADDRREQ = 89,
            EMSGSIZE = 90,
            EPROTOTYPE = 91,
            ENOPROTOOPT = 92,
            EPROTONOSUPPORT = 93,
            ESOCKTNOSUPPORT = 94,
            EOPNOTSUPP = 95,
            EPFNOSUPPORT = 96,
            EAFNOSUPPORT = 97,
            EADDRINUSE = 98,
            EADDRNOTAVAIL = 99,
            ENETDOWN = 100,
            ENETUNREACH = 101,
            ENETRESET = 102,
            ECONNABORTED = 103,
            ECONNRESET = 104,
            ENOBUFS = 105,
            EISCONN = 106,
            ENOTCONN = 107,
            ESHUTDOWN = 108,
            ETOOMANYREFS = 109,
            ETIMEDOUT = 110,
            ECONNREFUSED = 111,
            EHOSTDOWN = 112,
            EHOSTUNREACH = 113,
            EALREADY = 114,
            EINPROGRESS = 115,
            ESTALE = 116,
            EUCLEAN = 117,
            ENOTNAM = 118,
            ENAVAIL = 119,
            EISNAM = 120,
            EREMOTEIO = 121,
            EDQUOT = 122,
            ENOMEDIUM = 123,
            EMEDIUMTYPE = 124,
            ECANCELED = 125,
            ENOKEY = 126,
            EKEYEXPIRED = 127,
            EKEYREVOKED = 128,
            EKEYREJECTED = 129,
            EOWNERDEAD = 130,
            ENOTRECOVERABLE = 131,
            ERFKILL = 132,
            EHWPOISON = 133,
            _,
            pub const EWOULDBLOCK: Enum = .EAGAIN;
            pub const ENOTSUP: Enum = .EOPNOTSUPP;
        },
        // alpha
        // nios2
        // microblaze
        // openrisc
        // parisc
        // sh
        // um
        // @compileError("TODO: " ++ @tagName(v)),
        .avr,
        .bpfel,
        .bpfeb,
        .msp430,
        .amdgcn,
        .thumb,
        .thumbeb,
        .propeller,
        .xcore,
        .nvptx,
        .nvptx64,
        .spirv,
        .spirv32,
        .spirv64,
        .kalimba,
        .lanai,
        .wasm32,
        .wasm64,
        .ve,
        => unreachable,
    };

    pub fn byName(name: []const u8) ?Error {
        inline for (comptime std.meta.fieldNames(Error)) |field_name| {
            if (std.mem.eql(u8, name, field_name)) {
                return @field(Error, field_name);
            }
        }
        return null;
    }

    const map = blk: {
        const KV = struct { []const u8, Error };
        var kvs: []const KV = &.{};
        for (std.meta.fields(Enum)) |field| {
            kvs = kvs ++ &[1]KV{.{ field.name, @field(Error, field.name) }};
        }
        break :blk std.StaticStringMap(Error).initComptime(kvs);
    };

    pub fn fromInt(code: c_int) Error {
        const errors_are_seqential = comptime blk: {
            if (@intFromEnum(Enum.EPERM) != 1) break :blk false;
            var prev: u16 = @intFromError(Error.EPERM);
            for (std.meta.fields(Error)[1..]) |field| {
                const int = @intFromError(@field(anyerror, field.name));
                if (int != prev + 1) break :blk false;
                prev = int;
            }
            break :blk true;
        };
        if (errors_are_seqential) {
            // avoid an inline for and N comparisons
            if (code < 1) return error.Unexpected;
            if (code > std.meta.fields(Enum).len) return error.Unexpected;
            const ucode: c_ushort = @intCast(code);
            return @errorCast(@errorFromInt(@intFromError(Error.EPERM) + ucode - @intFromEnum(Enum.EPERM)));
        }
        return map.get(std.enums.tagName(Enum, @enumFromInt(code)) orelse return error.Unexpected).?;
    }

    pub fn fromLibC() c_int {
        return libc.__errno_location().*;
    }
};

pub const libc = struct {
    /// void _Exit(int status);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/_Exit.html
    pub extern fn _Exit(status: c_int) noreturn;

    /// void _exit(int status);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/_exit.html
    pub extern fn _exit(status: c_int) noreturn;

    /// long a64l(const char *s);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/a64l.html
    pub extern fn a64l(s: [*]const u8) c_long;

    /// void abort(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/abort.html
    pub extern fn abort() void;

    /// int abs(int i);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/abs.html
    pub extern fn abs(i: c_int) c_int;

    /// int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/accept.html
    pub extern fn accept(socket: c_int, noalias address: ?*struct_sockaddr, noalias address_len: *socklen_t) c_int;

    /// int access(const char *path, int amode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/access.html
    pub extern fn access(path: [*:0]const u8, amode: c_int) c_int;

    /// double acos(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/acos.html
    pub extern fn acos(x: f64) f64;

    /// float acosf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/acosf.html
    pub extern fn acosf(x: f32) f32;

    /// double acosh(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/acosh.html
    pub extern fn acosh(x: f64) f64;

    /// float acoshf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/acoshf.html
    pub extern fn acoshf(x: f32) f32;

    /// long double acoshl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/acoshl.html
    pub extern fn acoshl(x: c_longdouble) c_longdouble;

    /// long double acosl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/acosl.html
    pub extern fn acosl(x: c_longdouble) c_longdouble;

    /// unsigned alarm(unsigned seconds);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/alarm.html
    pub extern fn alarm(seconds: c_uint) c_uint;

    /// double asin(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/asin.html
    pub extern fn asin(x: f64) f64;

    /// float asinf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/asinf.html
    pub extern fn asinf(x: f32) f32;

    /// double asinh(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/asinh.html
    pub extern fn asinh(x: f64) f64;

    /// float asinhf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/asinhf.html
    pub extern fn asinhf(x: f32) f32;

    /// long double asinhl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/asinhl.html
    pub extern fn asinhl(x: c_longdouble) c_longdouble;

    /// long double asinl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/asinl.html
    pub extern fn asinl(x: c_longdouble) c_longdouble;

    /// double atan(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atan.html
    pub extern fn atan(x: f64) f64;

    /// double atan2(double y, double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atan2.html
    pub extern fn atan2(y: f64, x: f64) f64;

    /// float atan2f(float y, float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atan2f.html
    pub extern fn atan2f(y: f32, x: f32) f32;

    /// long double atan2l(long double y, long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atan2l.html
    pub extern fn atan2l(y: c_longdouble, x: c_longdouble) c_longdouble;

    /// float atanf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atanf.html
    pub extern fn atanf(x: f32) f32;

    /// double atanh(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atanh.html
    pub extern fn atanh(x: f64) f64;

    /// float atanhf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atanhf.html
    pub extern fn atanhf(x: f32) f32;

    /// long double atanhl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atanhl.html
    pub extern fn atanhl(x: c_longdouble) c_longdouble;

    /// long double atanl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/atanl.html
    pub extern fn atanl(x: c_longdouble) c_longdouble;

    /// double cbrt(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/cbrt.html
    pub extern fn cbrt(x: f64) f64;

    /// float cbrtf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/cbrtf.html
    pub extern fn cbrtf(x: f32) f32;

    /// long double cbrtl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/cbrtl.html
    pub extern fn cbrtl(x: c_longdouble) c_longdouble;

    /// double ceil(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ceil.html
    pub extern fn ceil(x: f64) f64;

    /// float ceilf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ceilf.html
    pub extern fn ceilf(x: f32) f32;

    /// long double ceill(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ceill.html
    pub extern fn ceill(x: c_longdouble) c_longdouble;

    /// clock_t clock(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/clock.html
    pub extern fn clock() clock_t;

    /// int close(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/close.html
    pub extern fn close(fildes: c_int) c_int;

    /// void closelog(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/closelog.html
    pub extern fn closelog() void;

    /// double copysign(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/copysign.html
    pub extern fn copysign(x: f64, y: f64) f64;

    /// float copysignf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/copysignf.html
    pub extern fn copysignf(x: f32, y: f32) f32;

    /// long double copysignl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/copysignl.html
    pub extern fn copysignl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// double cos(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/cos.html
    pub extern fn cos(x: f64) f64;

    /// float cosf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/cosf.html
    pub extern fn cosf(x: f32) f32;

    /// double cosh(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/cosh.html
    pub extern fn cosh(x: f64) f64;

    /// float coshf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/coshf.html
    pub extern fn coshf(x: f32) f32;

    /// long double coshl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/coshl.html
    pub extern fn coshl(x: c_longdouble) c_longdouble;

    /// long double cosl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/cosl.html
    pub extern fn cosl(x: c_longdouble) c_longdouble;

    /// div_t div(int numer, int denom);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/div.html
    pub extern fn div(numer: c_int, denom: c_int) div_t;

    /// char *dlerror(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/dlerror.html
    pub extern fn dlerror() ?[*:0]u8;

    /// double drand48(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/drand48.html
    pub extern fn drand48() f64;

    /// int dup(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/dup.html
    pub extern fn dup(fildes: c_int) c_int;

    /// int dup2(int fildes, int fildes2);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/dup2.html
    pub extern fn dup2(fildes: c_int, fildes2: c_int) c_int;

    /// void endgrent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/endgrent.html
    pub extern fn endgrent() void;

    /// void endhostent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/endhostent.html
    pub extern fn endhostent() void;

    /// void endnetent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/endnetent.html
    pub extern fn endnetent() void;

    /// void endprotoent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/endprotoent.html
    pub extern fn endprotoent() void;

    /// void endpwent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/endpwent.html
    pub extern fn endpwent() void;

    /// void endservent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/endservent.html
    pub extern fn endservent() void;

    /// void endutxent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/endutxent.html
    pub extern fn endutxent() void;

    /// double erand48(unsigned short xsubi[3]);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/erand48.html
    pub extern fn erand48(xsubi: *[3]c_ushort) f64;

    /// double erf(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/erf.html
    pub extern fn erf(x: f64) f64;

    /// double erfc(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/erfc.html
    pub extern fn erfc(x: f64) f64;

    /// float erfcf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/erfcf.html
    pub extern fn erfcf(x: f32) f32;

    /// long double erfcl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/erfcl.html
    pub extern fn erfcl(x: c_longdouble) c_longdouble;

    /// float erff(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/erff.html
    pub extern fn erff(x: f32) f32;

    /// long double erfl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/erfl.html
    pub extern fn erfl(x: c_longdouble) c_longdouble;

    /// void exit(int status);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/exit.html
    pub extern fn exit(status: c_int) noreturn;

    /// double exp(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/exp.html
    pub extern fn exp(x: f64) f64;

    /// double exp2(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/exp2.html
    pub extern fn exp2(x: f64) f64;

    /// float exp2f(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/exp2f.html
    pub extern fn exp2f(x: f32) f32;

    /// long double exp2l(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/exp2l.html
    pub extern fn exp2l(x: c_longdouble) c_longdouble;

    /// float expf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/expf.html
    pub extern fn expf(x: f32) f32;

    /// long double expl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/expl.html
    pub extern fn expl(x: c_longdouble) c_longdouble;

    /// double expm1(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/expm1.html
    pub extern fn expm1(x: f64) f64;

    /// float expm1f(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/expm1f.html
    pub extern fn expm1f(x: f32) f32;

    /// long double expm1l(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/expm1l.html
    pub extern fn expm1l(x: c_longdouble) c_longdouble;

    /// double fabs(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fabs.html
    pub extern fn fabs(x: f64) f64;

    /// float fabsf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fabsf.html
    pub extern fn fabsf(x: f32) f32;

    /// long double fabsl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fabsl.html
    pub extern fn fabsl(x: c_longdouble) c_longdouble;

    /// int faccessat(int fd, const char *path, int amode, int flag);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/faccessat.html
    pub extern fn faccessat(fd: c_int, path: [*:0]const u8, amode: c_int, flag: c_int) c_int;

    /// int fchdir(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchdir.html
    pub extern fn fchdir(fildes: c_int) c_int;

    /// int fchmod(int fildes, mode_t mode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchmod.html
    pub extern fn fchmod(fildes: c_int, mode: mode_t) c_int;

    /// int fchmodat(int fd, const char *path, mode_t mode, int flag);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchmodat.html
    pub extern fn fchmodat(fd: c_int, path: [*:0]const u8, mode: mode_t, flag: c_int) c_int;

    /// int fchown(int fildes, uid_t owner, gid_t group);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchown.html
    pub extern fn fchown(fildes: c_int, owner: uid_t, group: gid_t) c_int;

    /// int fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchownat.html
    pub extern fn fchownat(fd: c_int, path: [*:0]const u8, owner: uid_t, group: gid_t, flag: c_int) c_int;

    /// int fdatasync(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fdatasync.html
    pub extern fn fdatasync(fildes: c_int) c_int;

    /// double fdim(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fdim.html
    pub extern fn fdim(x: f64, y: f64) f64;

    /// float fdimf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fdimf.html
    pub extern fn fdimf(x: f32, y: f32) f32;

    /// long double fdiml(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fdiml.html
    pub extern fn fdiml(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// int fegetround(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fegetround.html
    pub extern fn fegetround() c_int;

    /// int fesetround(int round);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fesetround.html
    pub extern fn fesetround(round: c_int) c_int;

    /// int fetestexcept(int excepts);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fetestexcept.html
    pub extern fn fetestexcept(excepts: c_int) c_int;

    /// int ffs(int i);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ffs.html
    pub extern fn ffs(i: c_int) c_int;

    /// double floor(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/floor.html
    pub extern fn floor(x: f64) f64;

    /// float floorf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/floorf.html
    pub extern fn floorf(x: f32) f32;

    /// long double floorl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/floorl.html
    pub extern fn floorl(x: c_longdouble) c_longdouble;

    /// double fma(double x, double y, double z);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fma.html
    pub extern fn fma(x: f64, y: f64, z: f64) f64;

    /// float fmaf(float x, float y, float z);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmaf.html
    pub extern fn fmaf(x: f32, y: f32, z: f32) f32;

    /// long double fmal(long double x, long double y, long double z);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmal.html
    pub extern fn fmal(x: c_longdouble, y: c_longdouble, z: c_longdouble) c_longdouble;

    /// double fmax(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmax.html
    pub extern fn fmax(x: f64, y: f64) f64;

    /// float fmaxf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmaxf.html
    pub extern fn fmaxf(x: f32, y: f32) f32;

    /// long double fmaxl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmaxl.html
    pub extern fn fmaxl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// double fmin(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmin.html
    pub extern fn fmin(x: f64, y: f64) f64;

    /// float fminf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fminf.html
    pub extern fn fminf(x: f32, y: f32) f32;

    /// long double fminl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fminl.html
    pub extern fn fminl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// double fmod(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmod.html
    pub extern fn fmod(x: f64, y: f64) f64;

    /// float fmodf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmodf.html
    pub extern fn fmodf(x: f32, y: f32) f32;

    /// long double fmodl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fmodl.html
    pub extern fn fmodl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// pid_t fork(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fork.html
    pub extern fn fork() pid_t;

    /// long fpathconf(int fildes, int name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fpathconf.html
    pub extern fn fpathconf(fildes: c_int, name: c_int) c_long;

    /// void free(void *ptr);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/free.html
    pub extern fn free(ptr: ?*anyopaque) void;

    /// void freelocale(locale_t locobj);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/freelocale.html
    pub extern fn freelocale(locobj: locale_t) void;

    /// double frexp(double num, int *exp);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/frexp.html
    pub extern fn frexp(x: f64, exp: *c_int) f64;

    /// float frexpf(float num, int *exp);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/frexpf.html
    pub extern fn frexpf(x: f32, exp: *c_int) f32;

    /// long double frexpl(long double num, int *exp);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/frexpl.html
    pub extern fn frexpl(x: c_longdouble, exp: *c_int) c_longdouble;

    /// int fstat(int fildes, struct stat *buf);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fstat.html
    pub extern fn fstat(fd: c_int, buf: *struct_stat) c_int;

    /// int fstatat(int fd, const char *restrict path, struct stat *restrict buf, int flag);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fstatat.html
    pub extern fn fstatat(fd: c_int, noalias path: [*:0]const u8, noalias buf: *struct_stat, flag: c_int) c_int;

    /// int fsync(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fsync.html
    pub extern fn fsync(fd: c_int) c_int;

    /// int getchar(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getchar.html
    pub extern fn getchar() c_int;

    /// int getchar_unlocked(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getchar_unlocked.html
    pub extern fn getchar_unlocked() c_int;

    /// gid_t getegid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getegid.html
    pub extern fn getegid() gid_t;

    /// char *getenv(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getenv.html
    pub extern fn getenv(name: [*:0]const u8) ?[*:0]u8;

    /// uid_t geteuid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/geteuid.html
    pub extern fn geteuid() uid_t;

    /// gid_t getgid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getgid.html
    pub extern fn getgid() gid_t;

    /// struct group *getgrent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getgrent.html
    pub extern fn getgrent() ?*struct_group;

    /// struct group *getgrgid(gid_t gid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getgrgid.html
    pub extern fn getgrgid(gid: gid_t) ?*struct_group;

    /// struct group *getgrnam(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getgrnam.html
    pub extern fn getgrnam(name: [*:0]const u8) ?*struct_group;

    /// struct hostent *gethostent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/gethostent.html
    pub extern fn gethostent() ?*struct_hostent;

    /// long gethostid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/gethostid.html
    pub extern fn gethostid() c_long;

    /// int gethostname(char *name, size_t namelen);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/gethostname.html
    pub extern fn gethostname(name: [*:0]u8, len: usize) c_int;

    /// struct netent *getnetbyaddr(uint32_t net, int type);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getnetbyaddr.html
    pub extern fn getnetbyaddr(net: u32, type: c_int) ?*struct_netent;

    /// struct netent *getnetbyname(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getnetbyname.html
    pub extern fn getnetbyname(name: [*:0]const u8) ?*struct_netent;

    /// struct netent *getnetent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getnetent.html
    pub extern fn getnetent() ?*struct_netent;

    /// pid_t getpgid(pid_t pid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getpgid.html
    pub extern fn getpgid(pid: pid_t) pid_t;

    /// pid_t getpgrp(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getpgrp.html
    pub extern fn getpgrp() pid_t;

    /// pid_t getpid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getpid.html
    pub extern fn getpid() pid_t;

    /// pid_t getppid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getppid.html
    pub extern fn getppid() pid_t;

    /// struct protoent *getprotobyname(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getprotobyname.html
    pub extern fn getprotobyname(name: [*:0]const u8) ?*struct_protoent;

    /// struct protoent *getprotobynumber(int proto);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getprotobynumber.html
    pub extern fn getprotobynumber(proto: c_int) ?*struct_protoent;

    /// struct protoent *getprotoent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getprotoent.html
    pub extern fn getprotoent() ?*struct_protoent;

    /// struct passwd *getpwent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getpwent.html
    pub extern fn getpwent() ?*struct_passwd;

    /// struct passwd *getpwnam(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getpwnam.html
    pub extern fn getpwnam(name: [*:0]const u8) ?*struct_passwd;

    /// struct passwd *getpwuid(uid_t uid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getpwuid.html
    pub extern fn getpwuid(uid: uid_t) ?*struct_passwd;

    /// char *gets(char *s);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/gets.html
    pub extern fn gets(s: [*]u8) [*:0]u8;

    /// struct servent *getservent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getservent.html
    pub extern fn getservent() ?*struct_servent;

    /// pid_t getsid(pid_t pid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getsid.html
    pub extern fn getsid(pid: pid_t) pid_t;

    /// uid_t getuid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getuid.html
    pub extern fn getuid() uid_t;

    /// struct utmpx *getutxent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getutxent.html
    pub extern fn getutxent() ?*struct_utmpx;

    /// wint_t getwchar(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getwchar.html
    pub extern fn getwchar() wint_t;

    /// int grantpt(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/grantpt.html
    pub extern fn grantpt(fd: c_int) c_int;

    /// void hdestroy(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/hdestroy.html
    pub extern fn hdestroy() void;

    /// uint32_t htonl(uint32_t hostlong);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/htonl.html
    pub extern fn htonl(hostlong: u32) u32;

    /// uint16_t htons(uint16_t hostshort);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/htons.html
    pub extern fn htons(hostshort: u16) u16;

    /// double hypot(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/hypot.html
    pub extern fn hypot(x: f64, y: f64) f64;

    /// float hypotf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/hypotf.html
    pub extern fn hypotf(x: f32, y: f32) f32;

    /// long double hypotl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/hypotl.html
    pub extern fn hypotl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// void if_freenameindex(struct if_nameindex *ptr);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/if_freenameindex.html
    pub extern fn if_freenameindex(ptr: *struct_if_nameindex) void;

    /// struct if_nameindex *if_nameindex(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/if_nameindex.html
    pub extern fn if_nameindex() ?*struct_if_nameindex;

    /// unsigned if_nametoindex(const char *ifname);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/if_nametoindex.html
    pub extern fn if_nametoindex(ifname: [*:0]const u8) c_uint;

    /// int ilogb(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ilogb.html
    pub extern fn ilogb(x: f64) c_int;

    /// int ilogbf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ilogbf.html
    pub extern fn ilogbf(x: f32) c_int;

    /// int ilogbl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ilogbl.html
    pub extern fn ilogbl(x: c_longdouble) c_int;

    /// intmax_t imaxabs(intmax_t j);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/imaxabs.html
    pub extern fn imaxabs(j: intmax_t) intmax_t;

    /// void insque(void *element, void *pred);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/insque.html
    pub extern fn insque(elem: *anyopaque, prev: ?*anyopaque) void;

    /// int isalnum(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isalnum.html
    pub extern fn isalnum(c: c_int) c_int;

    /// int isalnum_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isalnum_l.html
    pub extern fn isalnum_l(c: c_int, locale: locale_t) c_int;

    /// int isalpha(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isalpha.html
    pub extern fn isalpha(c: c_int) c_int;

    /// int isalpha_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isalpha_l.html
    pub extern fn isalpha_l(c: c_int, locale: locale_t) c_int;

    /// int isascii(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isascii.html
    pub extern fn isascii(c: c_int) c_int;

    /// int isastream(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isastream.html
    pub extern fn isastream(fd: c_int) c_int;

    /// int isatty(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isatty.html
    pub extern fn isatty(fd: c_int) c_int;

    /// int isblank(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isblank.html
    pub extern fn isblank(c: c_int) c_int;

    /// int isblank_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isblank_l.html
    pub extern fn isblank_l(c: c_int, locale: locale_t) c_int;

    /// int iscntrl(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iscntrl.html
    pub extern fn iscntrl(c: c_int) c_int;

    /// int iscntrl_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iscntrl_l.html
    pub extern fn iscntrl_l(c: c_int, locale: locale_t) c_int;

    /// int isdigit(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isdigit.html
    pub extern fn isdigit(c: c_int) c_int;

    /// int isdigit_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isdigit_l.html
    pub extern fn isdigit_l(c: c_int, locale: locale_t) c_int;

    /// int isgraph(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isgraph.html
    pub extern fn isgraph(c: c_int) c_int;

    /// int isgraph_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isgraph_l.html
    pub extern fn isgraph_l(c: c_int, locale: locale_t) c_int;

    /// int islower(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/islower.html
    pub extern fn islower(c: c_int) c_int;

    /// int islower_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/islower_l.html
    pub extern fn islower_l(c: c_int, locale: locale_t) c_int;

    /// int isprint(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isprint.html
    pub extern fn isprint(c: c_int) c_int;

    /// int isprint_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isprint_l.html
    pub extern fn isprint_l(c: c_int, locale: locale_t) c_int;

    /// int ispunct(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ispunct.html
    pub extern fn ispunct(c: c_int) c_int;

    /// int ispunct_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ispunct_l.html
    pub extern fn ispunct_l(c: c_int, locale: locale_t) c_int;

    /// int isspace(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isspace.html
    pub extern fn isspace(c: c_int) c_int;

    /// int isspace_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isspace_l.html
    pub extern fn isspace_l(c: c_int, locale: locale_t) c_int;

    /// int isupper(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isupper.html
    pub extern fn isupper(c: c_int) c_int;

    /// int isupper_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isupper_l.html
    pub extern fn isupper_l(c: c_int, locale: locale_t) c_int;

    /// int iswalnum(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswalnum.html
    pub extern fn iswalnum(wc: wint_t) c_int;

    /// int iswalnum_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswalnum_l.html
    pub extern fn iswalnum_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswalpha(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswalpha.html
    pub extern fn iswalpha(wc: wint_t) c_int;

    /// int iswalpha_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswalpha_l.html
    pub extern fn iswalpha_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswblank(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswblank.html
    pub extern fn iswblank(wc: wint_t) c_int;

    /// int iswblank_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswblank_l.html
    pub extern fn iswblank_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswcntrl(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswcntrl.html
    pub extern fn iswcntrl(wc: wint_t) c_int;

    /// int iswcntrl_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswcntrl_l.html
    pub extern fn iswcntrl_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswdigit(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswdigit.html
    pub extern fn iswdigit(wc: wint_t) c_int;

    /// int iswdigit_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswdigit_l.html
    pub extern fn iswdigit_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswgraph(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswgraph.html
    pub extern fn iswgraph(wc: wint_t) c_int;

    /// int iswgraph_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswgraph_l.html
    pub extern fn iswgraph_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswlower(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswlower.html
    pub extern fn iswlower(wc: wint_t) c_int;

    /// int iswlower_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswlower_l.html
    pub extern fn iswlower_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswprint(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswprint.html
    pub extern fn iswprint(wc: wint_t) c_int;

    /// int iswprint_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswprint_l.html
    pub extern fn iswprint_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswpunct(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswpunct.html
    pub extern fn iswpunct(wc: wint_t) c_int;

    /// int iswpunct_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswpunct_l.html
    pub extern fn iswpunct_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswspace(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswspace.html
    pub extern fn iswspace(wc: wint_t) c_int;

    /// int iswspace_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswspace_l.html
    pub extern fn iswspace_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswupper(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswupper.html
    pub extern fn iswupper(wc: wint_t) c_int;

    /// int iswupper_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswupper_l.html
    pub extern fn iswupper_l(wc: wint_t, locale: locale_t) c_int;

    /// int iswxdigit(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswxdigit.html
    pub extern fn iswxdigit(wc: wint_t) c_int;

    /// int iswxdigit_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/iswxdigit_l.html
    pub extern fn iswxdigit_l(wc: wint_t, locale: locale_t) c_int;

    /// int isxdigit(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isxdigit.html
    pub extern fn isxdigit(c: c_int) c_int;

    /// int isxdigit_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/isxdigit_l.html
    pub extern fn isxdigit_l(c: c_int, locale: locale_t) c_int;

    /// double j0(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/j0.html
    pub extern fn j0(x: f64) f64;

    /// double j1(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/j1.html
    pub extern fn j1(x: f64) f64;

    /// double jn(int n, double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/jn.html
    pub extern fn jn(n: c_int, x: f64) f64;

    /// long labs(long i);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/labs.html
    pub extern fn labs(i: c_long) c_long;

    /// double ldexp(double x, int exp);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ldexp.html
    pub extern fn ldexp(x: f64, exp: c_int) f64;

    /// float ldexpf(float x, int exp);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ldexpf.html
    pub extern fn ldexpf(x: f32, exp: c_int) f32;

    /// double lgamma(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lgamma.html
    pub extern fn lgamma(x: f64) f64;

    /// float lgammaf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lgammaf.html
    pub extern fn lgammaf(x: f32) f32;

    /// long double lgammal(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lgammal.html
    pub extern fn lgammal(x: c_longdouble) c_longdouble;

    /// int listen(int socket, int backlog);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/listen.html
    pub extern fn listen(socket: c_int, backlog: c_int) c_int;

    /// long long llabs(long long i);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/llabs.html
    pub extern fn llabs(x: c_longlong) c_longlong;

    /// long long llrint(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/llrint.html
    pub extern fn llrint(x: f64) c_longlong;

    /// long long llrintf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/llrintf.html
    pub extern fn llrintf(x: f32) c_longlong;

    /// long long llrintl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/llrintl.html
    pub extern fn llrintl(x: c_longdouble) c_longlong;

    /// long long llround(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/llround.html
    pub extern fn llround(x: f64) c_longlong;

    /// long long llroundf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/llroundf.html
    pub extern fn llroundf(x: f32) c_longlong;

    /// long long llroundl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/llroundl.html
    pub extern fn llroundl(x: c_longdouble) c_longlong;

    /// struct lconv *localeconv(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/localeconv.html
    pub extern fn localeconv() *struct_lconv;

    /// double log(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log.html
    pub extern fn log(x: f64) f64;

    /// double log1p(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log1p.html
    pub extern fn log1p(x: f64) f64;

    /// float log1pf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log1pf.html
    pub extern fn log1pf(x: f32) f32;

    /// long double log1pl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log1pl.html
    pub extern fn log1pl(x: c_longdouble) c_longdouble;

    /// double log2(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log2.html
    pub extern fn log2(x: f64) f64;

    /// float log2f(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log2f.html
    pub extern fn log2f(x: f32) f32;

    /// long double log2l(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log2l.html
    pub extern fn log2l(x: c_longdouble) c_longdouble;

    /// double log10(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log10.html
    pub extern fn log10(x: f64) f64;

    /// float log10f(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log10f.html
    pub extern fn log10f(x: f32) f32;

    /// long double log10l(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/log10l.html
    pub extern fn log10l(x: c_longdouble) c_longdouble;

    /// double logb(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/logb.html
    pub extern fn logb(x: f64) f64;

    /// float logbf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/logbf.html
    pub extern fn logbf(x: f32) f32;

    /// long double logbl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/logbl.html
    pub extern fn logbl(x: c_longdouble) c_longdouble;

    /// float logf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/logf.html
    pub extern fn logf(x: f32) f32;

    /// long double logl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/logl.html
    pub extern fn logl(x: c_longdouble) c_longdouble;

    /// long lrand48(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lrand48.html
    pub extern fn lrand48() c_long;

    /// long lrint(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lrint.html
    pub extern fn lrint(x: f64) c_long;

    /// long lrintf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lrintf.html
    pub extern fn lrintf(x: f32) c_long;

    /// long lrintl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lrintl.html
    pub extern fn lrintl(x: c_longdouble) c_long;

    /// long lround(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lround.html
    pub extern fn lround(x: f64) c_long;

    /// long lroundf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lroundf.html
    pub extern fn lroundf(x: f32) c_long;

    /// long lroundl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lroundl.html
    pub extern fn lroundl(x: c_longdouble) c_long;

    /// off_t lseek(int fildes, off_t offset, int whence);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/lseek.html
    pub extern fn lseek(fd: c_int, offset: off_t, whence: c_int) off_t;

    /// void *malloc(size_t size);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/malloc.html
    pub extern fn malloc(size: usize) ?*anyopaque;

    /// int mkdir(const char *path, mode_t mode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mkdir.html
    pub extern fn mkdir(path: [*:0]const u8, __mode: mode_t) c_int;

    /// int mkdirat(int fd, const char *path, mode_t mode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mkdirat.html
    pub extern fn mkdirat(fd: c_int, path: [*:0]const u8, mode: mode_t) c_int;

    /// char *mkdtemp(char *template);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mkdtemp.html
    pub extern fn mkdtemp(template: [*:0]u8) [*:0]u8;

    /// int mkfifo(const char *path, mode_t mode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mkfifo.html
    pub extern fn mkfifo(path: [*:0]const u8, mode: mode_t) c_int;

    /// int mkfifoat(int fd, const char *path, mode_t mode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mkfifoat.html
    pub extern fn mkfifoat(fd: c_int, path: [*:0]const u8, mode: mode_t) c_int;

    /// int mkstemp(char *template);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mkstemp.html
    pub extern fn mkstemp(template: [*:0]u8) c_int;

    /// int mlockall(int flags);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mlockall.html
    pub extern fn mlockall(flags: c_int) c_int;

    /// int mq_unlink(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mq_unlink.html
    pub extern fn mq_unlink(name: [*:0]const u8) c_int;

    /// long mrand48(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mrand48.html
    pub extern fn mrand48() c_long;

    /// int munlockall(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/munlockall.html
    pub extern fn munlockall() void;

    /// double nearbyint(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nearbyint.html
    pub extern fn nearbyint(x: f64) f64;

    /// float nearbyintf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nearbyintf.html
    pub extern fn nearbyintf(x: f32) f32;

    /// long double nearbyintl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nearbyintl.html
    pub extern fn nearbyintl(x: c_longdouble) c_longdouble;

    /// double nextafter(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nextafter.html
    pub extern fn nextafter(x: f64, y: f64) f64;

    /// float nextafterf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nextafterf.html
    pub extern fn nextafterf(x: f32, y: f32) f32;

    /// long double nextafterl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nextafterl.html
    pub extern fn nextafterl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// double nexttoward(double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nexttoward.html
    pub extern fn nexttoward(x: f64, y: c_longdouble) f64;

    /// float nexttowardf(float x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nexttowardf.html
    pub extern fn nexttowardf(x: f32, y: c_longdouble) f32;

    /// long double nexttowardl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nexttowardl.html
    pub extern fn nexttowardl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// int nice(int incr);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/nice.html
    pub extern fn nice(incr: c_int) c_int;

    /// uint32_t ntohl(uint32_t netlong);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ntohl.html
    pub extern fn ntohl(netlong: u32) u32;

    /// uint16_t ntohs(uint16_t netshort);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ntohs.html
    pub extern fn ntohs(netshort: u16) u16;

    /// int openat(int fd, const char *path, int oflag, ...);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/openat.html
    pub extern fn openat(fd: c_int, file: [*:0]const u8, oflag: c_int, ...) c_int;

    /// int pause(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pause.html
    pub extern fn pause() c_int;

    /// double pow(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pow.html
    pub extern fn pow(x: f64, y: f64) f64;

    /// float powf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/powf.html
    pub extern fn powf(x: f32, y: f32) f32;

    /// long double powl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/powl.html
    pub extern fn powl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// int pthread_cancel(pthread_t thread);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pthread_cancel.html
    pub extern fn pthread_cancel(thread: pthread_t) c_int;

    /// int pthread_detach(pthread_t thread);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pthread_detach.html
    pub extern fn pthread_detach(thread: pthread_t) c_int;

    /// int pthread_equal(pthread_t t1, pthread_t t2);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pthread_equal.html
    pub extern fn pthread_equal(thread1: pthread_t, thread2: pthread_t) c_int;

    /// int pthread_getconcurrency(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pthread_getconcurrency.html
    pub extern fn pthread_getconcurrency() c_int;

    /// int pthread_kill(pthread_t thread, int sig);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pthread_kill.html
    pub extern fn pthread_kill(thread: pthread_t, sig: c_int) c_int;

    /// pthread_t pthread_self(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pthread_self.html
    pub extern fn pthread_self() pthread_t;

    /// void pthread_testcancel(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/pthread_testcancel.html
    pub extern fn pthread_testcancel() void;

    /// int putchar(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/putchar.html
    pub extern fn putchar(c: c_int) c_int;

    /// int putchar_unlocked(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/putchar_unlocked.html
    pub extern fn putchar_unlocked(c: c_int) c_int;

    /// wint_t putwchar(wchar_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/putwchar.html
    pub extern fn putwchar(wc: wchar_t) wint_t;

    /// int raise(int sig);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/raise.html
    pub extern fn raise(sig: c_int) c_int;

    /// int rand(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/rand.html
    pub extern fn rand() c_int;

    /// long random(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/random.html
    pub extern fn random() c_long;

    /// ssize_t read(int fildes, void *buf, size_t nbyte);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/read.html
    pub extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;

    /// double remainder(double x, double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/remainder.html
    pub extern fn remainder(x: f64, y: f64) f64;

    /// float remainderf(float x, float y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/remainderf.html
    pub extern fn remainderf(x: f32, y: f32) f32;

    /// long double remainderl(long double x, long double y);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/remainderl.html
    pub extern fn remainderl(x: c_longdouble, y: c_longdouble) c_longdouble;

    /// double rint(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/rint.html
    pub extern fn rint(x: f64) f64;

    /// float rintf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/rintf.html
    pub extern fn rintf(x: f32) f32;

    /// long double rintl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/rintl.html
    pub extern fn rintl(x: c_longdouble) c_longdouble;

    /// int rmdir(const char *path);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/rmdir.html
    pub extern fn rmdir(path: [*:0]const u8) c_int;

    /// double round(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/round.html
    pub extern fn round(x: f64) f64;

    /// float roundf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/roundf.html
    pub extern fn roundf(x: f32) f32;

    /// long double roundl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/roundl.html
    pub extern fn roundl(x: c_longdouble) c_longdouble;

    /// double scalbln(double x, long n);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/scalbln.html
    pub extern fn scalbln(x: f64, n: c_long) f64;

    /// float scalblnf(float x, long n);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/scalblnf.html
    pub extern fn scalblnf(x: f32, n: c_long) f32;

    /// long double scalblnl(long double x, long n);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/scalblnl.html
    pub extern fn scalblnl(x: c_longdouble, n: c_long) c_longdouble;

    /// double scalbn(double x, int n);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/scalbn.html
    pub extern fn scalbn(x: f64, n: c_int) f64;

    /// float scalbnf(float x, int n);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/scalbnf.html
    pub extern fn scalbnf(x: f32, n: c_int) f32;

    /// long double scalbnl(long double x, int n);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/scalbnl.html
    pub extern fn scalbnl(x: c_longdouble, n: c_int) c_longdouble;

    /// int sched_get_priority_max(int policy);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sched_get_priority_max.html
    pub extern fn sched_get_priority_max(policy: c_int) c_int;

    /// int sched_get_priority_min(int policy);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sched_get_priority_min.html
    pub extern fn sched_get_priority_min(policy: c_int) c_int;

    /// int sched_getscheduler(pid_t pid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sched_getscheduler.html
    pub extern fn sched_getscheduler(pid: pid_t) c_int;

    /// int sched_yield(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sched_yield.html
    pub extern fn sched_yield() c_int;

    /// int sem_unlink(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sem_unlink.html
    pub extern fn sem_unlink(name: [*:0]const u8) c_int;

    /// int semctl(int semid, int semnum, int cmd, ...);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/semctl.html
    pub extern fn semctl(semid: c_int, semnum: c_int, cmd: c_int, ...) c_int;

    /// int setegid(gid_t gid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setegid.html
    pub extern fn setegid(gid: gid_t) c_int;

    /// int seteuid(uid_t uid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/seteuid.html
    pub extern fn seteuid(uid: uid_t) c_int;

    /// int setgid(gid_t gid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setgid.html
    pub extern fn setgid(gid: gid_t) c_int;

    /// void setgrent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setgrent.html
    pub extern fn setgrent() void;

    /// void sethostent(int stayopen);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sethostent.html
    pub extern fn sethostent(stayopen: c_int) void;

    /// int setlogmask(int maskpri);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setlogmask.html
    pub extern fn setlogmask(maskpri: c_int) c_int;

    /// void setnetent(int stayopen);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setnetent.html
    pub extern fn setnetent(stayopen: c_int) void;

    /// pid_t setpgrp(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setpgrp.html
    pub extern fn setpgrp() pid_t;

    /// void setprotoent(int stayopen);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setprotoent.html
    pub extern fn setprotoent(stayopen: c_int) void;

    /// void setpwent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setpwent.html
    pub extern fn setpwent() void;

    /// int setregid(gid_t rgid, gid_t egid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setregid.html
    pub extern fn setregid(rgid: gid_t, egid: gid_t) c_int;

    /// int setreuid(uid_t ruid, uid_t euid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setreuid.html
    pub extern fn setreuid(ruid: uid_t, euid: uid_t) c_int;

    /// void setservent(int stayopen);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setservent.html
    pub extern fn setservent(stayopen: c_int) void;

    /// pid_t setsid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setsid.html
    pub extern fn setsid() pid_t;

    /// int setuid(uid_t uid);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setuid.html
    pub extern fn setuid(uid: uid_t) c_int;

    /// void setutxent(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/setutxent.html
    pub extern fn setutxent() void;

    /// int shm_unlink(const char *name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/shm_unlink.html
    pub extern fn shm_unlink(name: [*:0]const u8) c_int;

    /// int shutdown(int socket, int how);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/shutdown.html
    pub extern fn shutdown(socket: c_int, how: c_int) c_int;

    /// int sighold(int sig);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sighold.html
    pub extern fn sighold(sig: c_int) c_int;

    /// int sigignore(int sig);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sigignore.html
    pub extern fn sigignore(sig: c_int) c_int;

    /// int siginterrupt(int sig, int flag);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/siginterrupt.html
    pub extern fn siginterrupt(sig: c_int, flag: c_int) c_int;

    /// int sigpause(int sig);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sigpause.html
    pub extern fn sigpause(sig: c_int) c_int;

    /// int sigrelse(int sig);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sigrelse.html
    pub extern fn sigrelse(sig: c_int) c_int;

    /// double sin(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sin.html
    pub extern fn sin(x: f64) f64;

    /// float sinf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sinf.html
    pub extern fn sinf(x: f32) f32;

    /// double sinh(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sinh.html
    pub extern fn sinh(x: f64) f64;

    /// float sinhf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sinhf.html
    pub extern fn sinhf(x: f32) f32;

    /// long double sinhl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sinhl.html
    pub extern fn sinhl(x: c_longdouble) c_longdouble;

    /// long double sinl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sinl.html
    pub extern fn sinl(x: c_longdouble) c_longdouble;

    /// unsigned sleep(unsigned seconds);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sleep.html
    pub extern fn sleep(seconds: c_uint) c_uint;

    /// int sockatmark(int s);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sockatmark.html
    pub extern fn sockatmark(s: c_int) c_int;

    /// int socket(int domain, int type, int protocol);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/socket.html
    pub extern fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;

    /// int socketpair(int domain, int type, int protocol, int socket_vector[2]);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/socketpair.html
    pub extern fn socketpair(domain: c_int, type: c_int, protocol: c_int, fds: *[2]c_int) c_int;

    /// double sqrt(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sqrt.html
    pub extern fn sqrt(x: f64) f64;

    /// float sqrtf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sqrtf.html
    pub extern fn sqrtf(x: f32) f32;

    /// long double sqrtl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sqrtl.html
    pub extern fn sqrtl(x: c_longdouble) c_longdouble;

    /// void srand(unsigned seed);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/srand.html
    pub extern fn srand(seed: c_uint) void;

    /// void srand48(long seedval);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/srand48.html
    pub extern fn srand48(seedval: c_long) void;

    /// void srandom(unsigned seed);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/srandom.html
    pub extern fn srandom(seed: c_uint) void;

    /// size_t strlen(const char *s);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/strlen.html
    pub extern fn strlen(s: [*:0]const u8) c_ulong;

    /// void sync(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sync.html
    pub extern fn sync() void;

    /// long sysconf(int name);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/sysconf.html
    pub extern fn sysconf(name: c_int) c_long;

    /// double tan(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tan.html
    pub extern fn tan(x: f64) f64;

    /// float tanf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tanf.html
    pub extern fn tanf(x: f32) f32;

    /// double tanh(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tanh.html
    pub extern fn tanh(x: f64) f64;

    /// float tanhf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tanhf.html
    pub extern fn tanhf(x: f32) f32;

    /// long double tanhl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tanhl.html
    pub extern fn tanhl(x: c_longdouble) c_longdouble;

    /// long double tanl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tanl.html
    pub extern fn tanl(x: c_longdouble) c_longdouble;

    /// int tcdrain(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tcdrain.html
    pub extern fn tcdrain(fd: c_int) c_int;

    /// int tcflow(int fildes, int action);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tcflow.html
    pub extern fn tcflow(fd: c_int, action: c_int) c_int;

    /// int tcflush(int fildes, int queue_selector);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tcflush.html
    pub extern fn tcflush(fd: c_int, queue_selector: c_int) c_int;

    /// pid_t tcgetpgrp(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tcgetpgrp.html
    pub extern fn tcgetpgrp(fd: c_int) pid_t;

    /// pid_t tcgetsid(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tcgetsid.html
    pub extern fn tcgetsid(fd: c_int) pid_t;

    /// int tcsendbreak(int fildes, int duration);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tcsendbreak.html
    pub extern fn tcsendbreak(fd: c_int, duration: c_int) c_int;

    /// double tgamma(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tgamma.html
    pub extern fn tgamma(x: f64) f64;

    /// float tgammaf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tgammaf.html
    pub extern fn tgammaf(x: f32) f32;

    /// long double tgammal(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tgammal.html
    pub extern fn tgammal(x: c_longdouble) c_longdouble;

    /// int toascii(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/toascii.html
    pub extern fn toascii(c: c_int) c_int;

    /// int tolower(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tolower.html
    pub extern fn tolower(c: c_int) c_int;

    /// int tolower_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tolower_l.html
    pub extern fn tolower_l(c: c_int, locale: locale_t) c_int;

    /// int toupper(int c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/toupper.html
    pub extern fn toupper(c: c_int) c_int;

    /// int toupper_l(int c, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/toupper_l.html
    pub extern fn toupper_l(c: c_int, locale: locale_t) c_int;

    /// wint_t towlower(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/towlower.html
    pub extern fn towlower(wc: wint_t) wint_t;

    /// wint_t towlower_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/towlower_l.html
    pub extern fn towlower_l(wc: wint_t, locale: locale_t) wint_t;

    /// wint_t towupper(wint_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/towupper.html
    pub extern fn towupper(wc: wint_t) wint_t;

    /// wint_t towupper_l(wint_t wc, locale_t locale);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/towupper_l.html
    pub extern fn towupper_l(wc: wint_t, locale: locale_t) wint_t;

    /// double trunc(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/trunc.html
    pub extern fn trunc(x: f64) f64;

    /// float truncf(float x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/truncf.html
    pub extern fn truncf(x: f32) f32;

    /// long double truncl(long double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/truncl.html
    pub extern fn truncl(x: c_longdouble) c_longdouble;

    /// void tzset(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/tzset.html
    pub extern fn tzset() void;

    /// long ulimit(int cmd, ...);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/ulimit.html
    pub extern fn ulimit(cmd: c_int, ...) c_long;

    /// mode_t umask(mode_t cmask);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/umask.html
    pub extern fn umask(cmask: mode_t) mode_t;

    /// int unlockpt(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/unlockpt.html
    pub extern fn unlockpt(fd: c_int) c_int;

    /// locale_t uselocale(locale_t newloc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/uselocale.html
    pub extern fn uselocale(newloc: locale_t) locale_t;

    /// int wctob(wint_t c);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/wctob.html
    pub extern fn wctob(c: wint_t) c_int;

    /// int wcwidth(wchar_t wc);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/wcwidth.html
    pub extern fn wcwidth(wc: wchar_t) c_int;

    /// double y0(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/y0.html
    pub extern fn y0(x: f64) f64;

    /// double y1(double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/y1.html
    pub extern fn y1(x: f64) f64;

    /// double yn(int n, double x);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/yn.html
    pub extern fn yn(n: c_int, x: f64) f64;

    //
    //

    pub extern fn __errno_location() *c_int;
    pub extern fn gettid() pid_t;
};

pub const clock_t = c_long;
pub const pid_t = c_int;
pub const gid_t = c_uint;
pub const uid_t = c_uint;
pub const struct_group = opaque {};
pub const struct_hostent = opaque {};
pub const struct_netent = opaque {};
pub const struct_protoent = opaque {};
pub const struct_passwd = opaque {};
pub const struct_servent = opaque {};
pub const struct_utmpx = opaque {};
pub const wint_t = c_uint;
pub const struct_if_nameindex = opaque {};
pub const struct_lconv = opaque {};
pub const pthread_t = c_ulong;
pub const FILE = opaque {};
pub const locale_t = *const opaque {};
pub const nl_catd = *const opaque {};
pub const intmax_t = i64;
pub const wchar_t = c_int;
pub const mode_t = c_uint;
pub const struct_sockaddr = linux.sockaddr;
pub const socklen_t = c_uint;
pub const clockid_t = c_int;
pub const struct_timespec = linux.timespec;
pub const DIR = opaque {};
pub const time_t = i64;
pub const div_t = extern struct { quot: c_int, rem: c_int };
pub const off_t = linux.off_t;
pub const ino_t = linux.ino_t;
pub const struct_stat = linux.Stat;
pub const struct_iovec = extern struct { base: [*]u8, len: usize };

pub const AT = struct {
    pub const FDCWD = -100;
    pub const SYMLINK_NOFOLLOW = 0x100;
    pub const REMOVEDIR = 0x200;
    pub const SYMLINK_FOLLOW = 0x400;
    pub const EACCESS = 0x200;
};

pub const O = struct {
    pub usingnamespace switch (builtin.target.cpu.arch) {
        // generic
        .x86_64,
        .riscv64,
        => struct {
            pub const CREAT = 0o100;
            pub const EXCL = 0o200;
            pub const NOCTTY = 0o400;
            pub const TRUNC = 0o1000;
            pub const APPEND = 0o2000;
            pub const NONBLOCK = 0o4000;
            pub const DSYNC = 0o10000;
            pub const SYNC = 0o4010000;
            pub const RSYNC = 0o4010000;
            pub const DIRECTORY = 0o200000;
            pub const NOFOLLOW = 0o400000;
            pub const CLOEXEC = 0o2000000;
            pub const ASYNC = 0o20000;
            pub const DIRECT = 0o40000;
            pub const LARGEFILE = 0o100000;
            pub const NOATIME = 0o1000000;
            pub const PATH = 0o10000000;
            pub const TMPFILE = 0o20200000;
            pub const NDELAY = O.NONBLOCK;
        },
        .aarch64,
        => struct {
            pub const CREAT = 0o100;
            pub const EXCL = 0o200;
            pub const NOCTTY = 0o400;
            pub const TRUNC = 0o1000;
            pub const APPEND = 0o2000;
            pub const NONBLOCK = 0o4000;
            pub const DSYNC = 0o10000;
            pub const SYNC = 0o4010000;
            pub const RSYNC = 0o4010000;
            pub const DIRECTORY = 0o40000;
            pub const NOFOLLOW = 0o100000;
            pub const CLOEXEC = 0o2000000;
            pub const ASYNC = 0o20000;
            pub const DIRECT = 0o200000;
            pub const LARGEFILE = 0o400000;
            pub const NOATIME = 0o1000000;
            pub const PATH = 0o10000000;
            pub const TMPFILE = 0o20040000;
            pub const NDELAY = O.NONBLOCK;
        },
        .powerpc64le,
        => struct {
            pub const CREAT = 0o100;
            pub const EXCL = 0o200;
            pub const NOCTTY = 0o400;
            pub const TRUNC = 0o1000;
            pub const APPEND = 0o2000;
            pub const NONBLOCK = 0o4000;
            pub const DSYNC = 0o10000;
            pub const SYNC = 0o4010000;
            pub const RSYNC = 0o4010000;
            pub const DIRECTORY = 0o40000;
            pub const NOFOLLOW = 0o100000;
            pub const CLOEXEC = 0o2000000;
            pub const ASYNC = 0o20000;
            pub const DIRECT = 0o400000;
            pub const LARGEFILE = 0o200000;
            pub const NOATIME = 0o1000000;
            pub const PATH = 0o10000000;
            pub const TMPFILE = 0o20040000;
            pub const NDELAY = O.NONBLOCK;
        },
        .mips64el,
        => struct {
            pub const CREAT = 0o400;
            pub const EXCL = 0o2000;
            pub const NOCTTY = 0o4000;
            pub const TRUNC = 0o1000;
            pub const APPEND = 0o010;
            pub const NONBLOCK = 0o200;
            pub const DSYNC = 0o020;
            pub const SYNC = 0o40020;
            pub const RSYNC = 0o40020;
            pub const DIRECTORY = 0o200000;
            pub const NOFOLLOW = 0o400000;
            pub const CLOEXEC = 0o2000000;
            pub const ASYNC = 0o10000;
            pub const DIRECT = 0o100000;
            pub const LARGEFILE = 0o20000;
            pub const NOATIME = 0o1000000;
            pub const PATH = 0o10000000;
            pub const TMPFILE = 0o20200000;
            pub const NDELAY = O.NONBLOCK;
        },
        else => @compileError("TODO"),
    };
    pub const SEARCH = O.PATH;
    pub const EXEC = O.PATH;
    pub const TTY_INIT = 0;
    pub const ACCMODE = (3 | O.SEARCH);
    pub const RDONLY = 0;
    pub const WRONLY = 1;
    pub const RDWR = 2;
};

pub const S = struct {
    pub const IFMT = 0o170000;
    pub const IFDIR = 0o040000;
    pub const IFCHR = 0o020000;
    pub const IFBLK = 0o060000;
    pub const IFREG = 0o100000;
    pub const IFIFO = 0o010000;
    pub const IFLNK = 0o120000;
    pub const IFSOCK = 0o140000;

    pub const ISUID = 0o4000;
    pub const ISGID = 0o2000;
    pub const ISVTX = 0o1000;
    pub const IRUSR = 0o400;
    pub const IWUSR = 0o200;
    pub const IXUSR = 0o100;
    pub const IRWXU = 0o700;
    pub const IRGRP = 0o040;
    pub const IWGRP = 0o020;
    pub const IXGRP = 0o010;
    pub const IRWXG = 0o070;
    pub const IROTH = 0o004;
    pub const IWOTH = 0o002;
    pub const IXOTH = 0o001;
    pub const IRWXO = 0o007;
};

pub const NAME_MAX = 255;
pub const PATH_MAX = 4096;
pub const NGROUPS_MAX = 32;
pub const ARG_MAX = 131072;
pub const IOV_MAX = 1024;
pub const SYMLOOP_MAX = 40;
pub const TZNAME_MAX = 6;
pub const TTY_NAME_MAX = 32;
pub const HOST_NAME_MAX = 255;

pub fn getpid() pid_t {
    return libc.getpid();
}

pub fn exit(status: c_int) noreturn {
    return libc.exit(status);
}

pub fn getenv(name: [:0]const u8) ?[:0]u8 {
    return std.mem.sliceTo(libc.getenv(name.ptr) orelse return null, 0);
}

pub fn openat(fd: c_int, file: [*:0]const u8, oflag: c_int) errno.Error!c_int {
    const rc = libc.openat(fd, file, oflag);
    if (rc == -1) return errno.fromInt(errno.fromLibC());
    return rc;
}

pub fn close(fd: c_int) errno.Error!void {
    const rc = libc.close(fd);
    if (rc == -1) return errno.fromInt(errno.fromLibC());
    std.debug.assert(rc == 0);
}

pub fn read(fd: c_int, buf: []u8) errno.Error!usize {
    const rc = libc.read(fd, buf.ptr, buf.len);
    if (rc == -1) return errno.fromInt(errno.fromLibC());
    std.debug.assert(rc >= 0);
    return @intCast(rc);
}

pub fn fstat(fd: c_int) errno.Error!struct_stat {
    var buf: struct_stat = undefined;
    const rc = libc.fstat(fd, &buf);
    if (rc == -1) return errno.fromInt(errno.fromLibC());
    std.debug.assert(rc == 0);
    return buf;
}

pub fn readv(fd: c_int, bufs: []const struct_iovec) errno.Error!usize {
    std.debug.assert(bufs.len > 0);
    std.debug.assert(bufs.len <= IOV_MAX);
    const rc = libc.readv(fd, bufs.ptr, @intCast(bufs.len));
    if (rc == -1) return errno.fromInt(errno.fromLibC());
    std.debug.assert(rc >= 0);
    return @intCast(rc);
}

pub fn mkdirat(fd: c_int, path: [*:0]const u8, mode: mode_t) errno.Error!void {
    const rc = libc.mkdirat(fd, path, mode);
    if (rc == -1) return errno.fromInt(errno.fromLibC());
    std.debug.assert(rc == 0);
}

pub fn pthread_self() pthread_t {
    return libc.pthread_self();
}

pub fn gettid() pid_t {
    return libc.gettid();
}

pub fn fstatat(fd: c_int, path: [*:0]const u8, flag: c_int) errno.Error!struct_stat {
    var buf: struct_stat = undefined;
    const rc = libc.fstatat(fd, path, &buf, flag);
    if (rc == -1) return errno.fromInt(errno.fromLibC());
    std.debug.assert(rc == 0);
    return buf;
}
