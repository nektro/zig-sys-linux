const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

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

    /// int fchdir(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchdir.html
    pub extern fn fchdir(fildes: c_int) c_int;

    /// int fchmod(int fildes, mode_t mode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchmod.html
    pub extern fn fchmod(fildes: c_int, mode: mode_t) c_int;

    /// int fchown(int fildes, uid_t owner, gid_t group);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fchown.html
    pub extern fn fchown(fildes: c_int, owner: uid_t, group: gid_t) c_int;

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

    /// int fstat(int fildes, struct stat *buf);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/fstat.html
    pub extern fn fstat(fd: c_int, buf: *struct_stat) c_int;

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

    /// long gethostid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/gethostid.html
    pub extern fn gethostid() c_long;

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

    /// uid_t getuid(void);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/getuid.html
    pub extern fn getuid() uid_t;

    /// int mkdirat(int fd, const char *path, mode_t mode);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/mkdirat.html
    pub extern fn mkdirat(fd: c_int, path: [*:0]const u8, mode: mode_t) c_int;

    /// int openat(int fd, const char *path, int oflag, ...);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/openat.html
    pub extern fn openat(fd: c_int, file: [*:0]const u8, oflag: c_int, ...) c_int;

    /// ssize_t read(int fildes, void *buf, size_t nbyte);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/read.html
    pub extern fn read(fd: c_int, buf: [*]u8, count: usize) isize;

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
