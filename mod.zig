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
    /// int close(int fildes);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/close.html
    pub extern fn close(fildes: c_int) c_int;

    /// void exit(int status);
    /// https://pubs.opengroup.org/onlinepubs/9699919799.orig/functions/exit.html
    pub extern fn exit(status: c_int) noreturn;











    //
    //

    pub extern fn __errno_location() *c_int;
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
        .x86_64,
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
