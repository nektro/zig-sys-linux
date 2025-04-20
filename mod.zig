const std = @import("std");
const errno = @import("errno");
const sys = std.os.linux;
const syscall0 = sys.syscall0;
const syscall1 = sys.syscall1;
const syscall2 = sys.syscall2;
const syscall3 = sys.syscall3;
const syscall4 = sys.syscall4;
const syscall5 = sys.syscall5;
const syscall6 = sys.syscall6;
const pid_t = sys.pid_t;
const uid_t = sys.uid_t;
const gid_t = sys.gid_t;

fn _errno(rc: usize) enum(c_ushort) { ok, _ } {
    const signed: isize = @bitCast(rc);
    const int = if (signed > -4096 and signed < 0) -signed else 0;
    return @enumFromInt(int);
}

// read
// ssize_t read(int fd, void buf[.count], size_t count);
// asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);
pub fn read(fd: c_int, buf: []u8) errno.Error!usize {
    const r = syscall3(.read, @intCast(fd), @intFromPtr(buf.ptr), buf.len);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// write
// ssize_t write(int fd, const void buf[.count], size_t count);
// asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);
pub fn write(fd: c_int, buf: []const u8) errno.Error!usize {
    const r = syscall3(.write, @intCast(fd), @intFromPtr(buf.ptr), buf.len);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// open
// int open(const char *pathname, int flags, ... /* mode_t mode */ );
// asmlinkage long sys_open(const char __user *filename, int flags, umode_t mode);
pub const open = @compileError("TODO: open");

// close
// int close(int fd);
// asmlinkage long sys_close(unsigned int fd);
pub const close = @compileError("TODO: close");

// stat
// int stat(const char *restrict pathname, struct stat *restrict statbuf);
// asmlinkage long sys_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
pub const stat = @compileError("TODO: stat");

// fstat
// int fstat(int fd, struct stat *statbuf);
// asmlinkage long sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf);
pub const fstat = @compileError("TODO: fstat");

// lstat
// int lstat(const char *restrict pathname, struct stat *restrict statbuf);
// asmlinkage long sys_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
pub const lstat = @compileError("TODO: lstat");

// poll
// int poll(struct pollfd *fds, nfds_t nfds, int timeout);
// asmlinkage long sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
pub const poll = @compileError("TODO: poll");

// lseek
// off_t lseek(int fd, off_t offset, int whence);
// asmlinkage long sys_lseek(unsigned int fd, off_t offset, unsigned int whence);
pub const lseek = @compileError("TODO: lseek");

// mmap
// void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
// asmlinkage long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);
pub const mmap = @compileError("TODO: mmap");

// mprotect
// int mprotect(void addr[.len], size_t len, int prot);
// asmlinkage long sys_mprotect(unsigned long start, size_t len, unsigned long prot);
pub const mprotect = @compileError("TODO: mprotect");

// munmap
// int munmap(void addr[.length], size_t length);
// asmlinkage long sys_munmap(unsigned long addr, size_t len);
pub const munmap = @compileError("TODO: munmap");

// brk
// int brk(void *addr);
// asmlinkage long sys_brk(unsigned long brk);
pub const brk = @compileError("TODO: brk");

// rt_sigaction
// int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
// asmlinkage long sys_rt_sigaction(int, const struct sigaction __user *, struct sigaction __user *, size_t);
pub const rt_sigaction = @compileError("TODO: rt_sigaction");

// rt_sigprocmask
// int sigprocmask(int how, const sigset_t *_Nullable restrict set, sigset_t *_Nullable restrict oldset);
// asmlinkage long sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize);
pub const rt_sigprocmask = @compileError("TODO: rt_sigprocmask");

// rt_sigreturn
// int sigreturn(...);
// asmlinkage long sys_rt_sigreturn(struct pt_regs *regs);
pub const rt_sigreturn = @compileError("TODO: rt_sigreturn");

// ioctl
// int ioctl(int fd, unsigned long op, ...);
// asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
pub const ioctl = @compileError("TODO: ioctl");

// pread64
// ssize_t pread(int fd, void buf[.count], size_t count, off_t offset);
// asmlinkage long sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
pub const pread64 = @compileError("TODO: pread64");

// pwrite64
// ssize_t pwrite(int fd, const void buf[.count], size_t count, off_t offset);
// asmlinkage long sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
pub const pwrite64 = @compileError("TODO: pwrite64");

// readv
// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
// asmlinkage long sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
pub const readv = @compileError("TODO: readv");

// writev
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
// asmlinkage long sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
pub const writev = @compileError("TODO: writev");

// access
// int access(const char *pathname, int mode);
// asmlinkage long sys_access(const char __user *filename, int mode);
pub const access = @compileError("TODO: access");

// pipe
// int pipe(int pipefd[2]);
// asmlinkage long sys_pipe(int __user *fildes);
pub const pipe = @compileError("TODO: pipe");

// select
// int select(int nfds, fd_set *_Nullable restrict readfds, fd_set *_Nullable restrict writefds, fd_set *_Nullable restrict exceptfds, struct timeval *_Nullable restrict timeout);
// asmlinkage long sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct __kernel_old_timeval __user *tvp);
pub const select = @compileError("TODO: select");

// sched_yield
// int sched_yield(void);
// asmlinkage long sys_sched_yield(void);
pub fn sched_yield() errno.Error!c_int {
    const r = syscall0(.sched_yield);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// mremap
// void *mremap(void old_address[.old_size], size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
// asmlinkage long sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);
pub const mremap = @compileError("TODO: mremap");

// msync
// int msync(void addr[.length], size_t length, int flags);
// asmlinkage long sys_msync(unsigned long start, size_t len, int flags);
pub const msync = @compileError("TODO: msync");

// mincore
// int mincore(void addr[.length], size_t length, unsigned char *vec);
// asmlinkage long sys_mincore(unsigned long start, size_t len, unsigned char __user * vec);
pub const mincore = @compileError("TODO: mincore");

// madvise
// int madvise(void addr[.length], size_t length, int advice);
// asmlinkage long sys_madvise(unsigned long start, size_t len, int behavior);
pub const madvise = @compileError("TODO: madvise");

// shmget
// int shmget(key_t key, size_t size, int shmflg);
// asmlinkage long sys_shmget(key_t key, size_t size, int flag);
pub const shmget = @compileError("TODO: shmget");

// shmat
// void *shmat(int shmid, const void *_Nullable shmaddr, int shmflg);
// asmlinkage long sys_shmat(int shmid, char __user *shmaddr, int shmflg);
pub const shmat = @compileError("TODO: shmat");

// shmctl
// int shmctl(int shmid, int op, struct shmid_ds *buf);
// asmlinkage long sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf);
pub const shmctl = @compileError("TODO: shmctl");

// dup
// int dup(int oldfd);
// asmlinkage long sys_dup(unsigned int fildes);
pub const dup = @compileError("TODO: dup");

// dup2
// int dup2(int oldfd, int newfd);
// asmlinkage long sys_dup2(unsigned int oldfd, unsigned int newfd);
pub const dup2 = @compileError("TODO: dup2");

// pause
// int pause(void);
// asmlinkage long sys_pause(void);
pub fn pause() errno.Error!c_int {
    const r = syscall0(.pause);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// nanosleep
// int nanosleep(const struct timespec *duration, struct timespec *_Nullable rem);
// asmlinkage long sys_nanosleep(struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);
pub const nanosleep = @compileError("TODO: nanosleep");

// getitimer
// int getitimer(int which, struct itimerval *curr_value);
// asmlinkage long sys_getitimer(int which, struct __kernel_old_itimerval __user *value);
pub const getitimer = @compileError("TODO: getitimer");

// alarm
// unsigned int alarm(unsigned int seconds);
// asmlinkage long sys_alarm(unsigned int seconds);
pub const alarm = @compileError("TODO: alarm");

// setitimer
// int setitimer(int which, const struct itimerval *restrict new_value, struct itimerval *_Nullable restrict old_value);
// asmlinkage long sys_setitimer(int which, struct __kernel_old_itimerval __user *value, struct __kernel_old_itimerval __user *ovalue);
pub const setitimer = @compileError("TODO: setitimer");

// getpid
// pid_t getpid(void);
// asmlinkage long sys_getpid(void);
pub fn getpid() errno.Error!pid_t {
    const r = syscall0(.getpid);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// sendfile
// ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset, size_t count);
// asmlinkage long sys_sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count);
pub const sendfile = @compileError("TODO: sendfile");

// socket
// int socket(int domain, int type, int protocol);
// asmlinkage long sys_socket(int, int, int);
pub const socket = @compileError("TODO: socket");

// connect
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
// asmlinkage long sys_connect(int, struct sockaddr __user *, int);
pub const connect = @compileError("TODO: connect");

// accept
// int accept(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen);
// asmlinkage long sys_accept(int, struct sockaddr __user *, int __user *);
pub const accept = @compileError("TODO: accept");

// sendto
// ssize_t sendto(int sockfd, const void buf[.len], size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
// asmlinkage long sys_sendto(int, void __user *, size_t, unsigned, struct sockaddr __user *, int);
pub const sendto = @compileError("TODO: sendto");

// recvfrom
// ssize_t recvfrom(int sockfd, void buf[restrict .len], size_t len, int flags, struct sockaddr *_Nullable restrict src_addr, socklen_t *_Nullable restrict addrlen);
// asmlinkage long sys_recvfrom(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *);
pub const recvfrom = @compileError("TODO: recvfrom");

// sendmsg
// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
// asmlinkage long sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags);
pub const sendmsg = @compileError("TODO: sendmsg");

// recvmsg
// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
// asmlinkage long sys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags);
pub const recvmsg = @compileError("TODO: recvmsg");

// shutdown
// int shutdown(int sockfd, int how);
// asmlinkage long sys_shutdown(int, int);
pub const shutdown = @compileError("TODO: shutdown");

// bind
// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
// asmlinkage long sys_bind(int, struct sockaddr __user *, int);
pub const bind = @compileError("TODO: bind");

// listen
// int listen(int sockfd, int backlog);
// asmlinkage long sys_listen(int, int);
pub const listen = @compileError("TODO: listen");

// getsockname
// int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
// asmlinkage long sys_getsockname(int, struct sockaddr __user *, int __user *);
pub const getsockname = @compileError("TODO: getsockname");

// getpeername
// int getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
// asmlinkage long sys_getpeername(int, struct sockaddr __user *, int __user *);
pub const getpeername = @compileError("TODO: getpeername");

// socketpair
// int socketpair(int domain, int type, int protocol, int sv[2]);
// asmlinkage long sys_socketpair(int, int, int, int __user *);
pub const socketpair = @compileError("TODO: socketpair");

// setsockopt
// int setsockopt(int sockfd, int level, int optname, const void optval[.optlen], socklen_t optlen);
// asmlinkage long sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen);
pub const setsockopt = @compileError("TODO: setsockopt");

// getsockopt
// int getsockopt(int sockfd, int level, int optname, void optval[restrict *.optlen], socklen_t *restrict optlen);
// asmlinkage long sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen);
pub const getsockopt = @compileError("TODO: getsockopt");

// clone
// int clone(int (*fn)(void *_Nullable), void *stack, int flags, void *_Nullable arg, ...  /* pid_t *_Nullable parent_tid, void *_Nullable tls, pid_t *_Nullable child_tid */ );
// asmlinkage long sys_clone(unsigned long, unsigned long, int __user *, int __user *, unsigned long);
pub const clone = @compileError("TODO: clone");

// fork
// pid_t fork(void);
// asmlinkage long sys_fork(void);
pub fn fork() errno.Error!pid_t {
    const r = syscall0(.fork);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// vfork
// pid_t vfork(void);
// asmlinkage long sys_vfork(void);
pub fn vfork() errno.Error!pid_t {
    const r = syscall0(.vfork);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// execve
// int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[]);
// asmlinkage long sys_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
pub const execve = @compileError("TODO: execve");

// exit
// [[noreturn]] void _exit(int status);
// asmlinkage long sys_exit(int error_code);
pub const exit = @compileError("TODO: exit");

// wait4
// pid_t wait4(pid_t pid, int *_Nullable wstatus, int options, struct rusage *_Nullable rusage);
// asmlinkage long sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru);
pub const wait4 = @compileError("TODO: wait4");

// kill
// int kill(pid_t pid, int sig);
// asmlinkage long sys_kill(pid_t pid, int sig);
pub const kill = @compileError("TODO: kill");

// uname
// int uname(struct utsname *buf);
// asmlinkage long sys_uname(struct old_utsname __user *);
pub const uname = @compileError("TODO: uname");

// semget
// int semget(key_t key, int nsems, int semflg);
// asmlinkage long sys_semget(key_t key, int nsems, int semflg);
pub const semget = @compileError("TODO: semget");

// semop
// int semop(int semid, struct sembuf *sops, size_t nsops);
// asmlinkage long sys_semop(int semid, struct sembuf __user *sops, unsigned nsops);
pub const semop = @compileError("TODO: semop");

// semctl
// int semctl(int semid, int semnum, int op, ...);
// asmlinkage long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);
pub const semctl = @compileError("TODO: semctl");

// shmdt
// int shmdt(const void *shmaddr);
// asmlinkage long sys_shmdt(char __user *shmaddr);
pub const shmdt = @compileError("TODO: shmdt");

// msgget
// int msgget(key_t key, int msgflg);
// asmlinkage long sys_msgget(key_t key, int msgflg);
pub const msgget = @compileError("TODO: msgget");

// msgsnd
// int msgsnd(int msqid, const void msgp[.msgsz], size_t msgsz, int msgflg);
// asmlinkage long sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg);
pub const msgsnd = @compileError("TODO: msgsnd");

// msgrcv
// ssize_t msgrcv(int msqid, void msgp[.msgsz], size_t msgsz, long msgtyp, int msgflg);
// asmlinkage long sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg);
pub const msgrcv = @compileError("TODO: msgrcv");

// msgctl
// int msgctl(int msqid, int op, struct msqid_ds *buf);
// asmlinkage long sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf);
pub const msgctl = @compileError("TODO: msgctl");

// fcntl
// int fcntl(int fd, int op, ... /* arg */ );
// asmlinkage long sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
pub const fcntl = @compileError("TODO: fcntl");

// flock
// int flock(int fd, int op);
// asmlinkage long sys_flock(unsigned int fd, unsigned int cmd);
pub const flock = @compileError("TODO: flock");

// fsync
// int fsync(int fd);
// asmlinkage long sys_fsync(unsigned int fd);
pub const fsync = @compileError("TODO: fsync");

// fdatasync
// int fdatasync(int fd);
// asmlinkage long sys_fdatasync(unsigned int fd);
pub const fdatasync = @compileError("TODO: fdatasync");

// truncate
// int truncate(const char *path, off_t length);
// asmlinkage long sys_truncate(const char __user *path, long length);
pub const truncate = @compileError("TODO: truncate");

// ftruncate
// int ftruncate(int fd, off_t length);
// asmlinkage long sys_ftruncate(unsigned int fd, off_t length);
pub const ftruncate = @compileError("TODO: ftruncate");

// getdents
// long syscall(SYS_getdents, unsigned int fd, struct linux_dirent *dirp, unsigned int count);
// asmlinkage long sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
pub const getdents = @compileError("TODO: getdents");

// getcwd
// char *getcwd(char buf[.size], size_t size);
// asmlinkage long sys_getcwd(char __user *buf, unsigned long size);
pub const getcwd = @compileError("TODO: getcwd");

// chdir
// int chdir(const char *path);
// asmlinkage long sys_chdir(const char __user *filename);
pub const chdir = @compileError("TODO: chdir");

// fchdir
// int fchdir(int fd);
// asmlinkage long sys_fchdir(unsigned int fd);
pub const fchdir = @compileError("TODO: fchdir");

// rename
// int rename(const char *oldpath, const char *newpath);
// asmlinkage long sys_rename(const char __user *oldname, const char __user *newname);
pub const rename = @compileError("TODO: rename");

// mkdir
// int mkdir(const char *pathname, mode_t mode);
// asmlinkage long sys_mkdir(const char __user *pathname, umode_t mode);
pub const mkdir = @compileError("TODO: mkdir");

// rmdir
// int rmdir(const char *pathname);
// asmlinkage long sys_rmdir(const char __user *pathname);
pub const rmdir = @compileError("TODO: rmdir");

// creat
// int creat(const char *pathname, mode_t mode);
// asmlinkage long sys_creat(const char __user *pathname, umode_t mode);
pub const creat = @compileError("TODO: creat");

// link
// int link(const char *oldpath, const char *newpath);
// asmlinkage long sys_link(const char __user *oldname, const char __user *newname);
pub const link = @compileError("TODO: link");

// unlink
// int unlink(const char *pathname);
// asmlinkage long sys_unlink(const char __user *pathname);
pub const unlink = @compileError("TODO: unlink");

// symlink
// int symlink(const char *target, const char *linkpath);
// asmlinkage long sys_symlink(const char __user *old, const char __user *new);
pub const symlink = @compileError("TODO: symlink");

// readlink
// ssize_t readlink(const char *restrict pathname, char *restrict buf, size_t bufsiz);
// asmlinkage long sys_readlink(const char __user *path, char __user *buf, int bufsiz);
pub const readlink = @compileError("TODO: readlink");

// chmod
// int chmod(const char *pathname, mode_t mode);
// asmlinkage long sys_chmod(const char __user *filename, umode_t mode);
pub const chmod = @compileError("TODO: chmod");

// fchmod
// int fchmod(int fd, mode_t mode);
// asmlinkage long sys_fchmod(unsigned int fd, umode_t mode);
pub const fchmod = @compileError("TODO: fchmod");

// chown
// int chown(const char *pathname, uid_t owner, gid_t group);
// asmlinkage long sys_chown(const char __user *filename, uid_t user, gid_t group);
pub const chown = @compileError("TODO: chown");

// fchown
// int fchown(int fd, uid_t owner, gid_t group);
// asmlinkage long sys_fchown(unsigned int fd, uid_t user, gid_t group);
pub const fchown = @compileError("TODO: fchown");

// lchown
// int lchown(const char *pathname, uid_t owner, gid_t group);
// asmlinkage long sys_lchown(const char __user *filename, uid_t user, gid_t group);
pub const lchown = @compileError("TODO: lchown");

// umask
// mode_t umask(mode_t mask);
// asmlinkage long sys_umask(int mask);
pub const umask = @compileError("TODO: umask");

// gettimeofday
// int gettimeofday(struct timeval *restrict tv, struct timezone *_Nullable restrict tz);
// asmlinkage long sys_gettimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);
pub const gettimeofday = @compileError("TODO: gettimeofday");

// getrlimit
// int getrlimit(int resource, struct rlimit *rlim);
// asmlinkage long sys_getrlimit(unsigned int resource, struct rlimit __user *rlim);
pub const getrlimit = @compileError("TODO: getrlimit");

// getrusage
// int getrusage(int who, struct rusage *usage);
// asmlinkage long sys_getrusage(int who, struct rusage __user *ru);
pub const getrusage = @compileError("TODO: getrusage");

// sysinfo
// int sysinfo(struct sysinfo *info);
// asmlinkage long sys_sysinfo(struct sysinfo __user *info);
pub const sysinfo = @compileError("TODO: sysinfo");

// times
// clock_t times(struct tms *buf);
// asmlinkage long sys_times(struct tms __user *tbuf);
pub const times = @compileError("TODO: times");

// ptrace
// long ptrace(enum __ptrace_request op, pid_t pid, void *addr, void *data);
// asmlinkage long sys_ptrace(long request, long pid, unsigned long addr, unsigned long data);
pub const ptrace = @compileError("TODO: ptrace");

// getuid
// uid_t getuid(void);
// asmlinkage long sys_getuid(void);
pub fn getuid() errno.Error!uid_t {
    const r = syscall0(.getuid);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// syslog
// int syscall(SYS_syslog, int type, char *bufp, int len);
// asmlinkage long sys_syslog(int type, char __user *buf, int len);
pub const syslog = @compileError("TODO: syslog");

// getgid
// gid_t getgid(void);
// asmlinkage long sys_getgid(void);
pub fn getgid() errno.Error!gid_t {
    const r = syscall0(.getgid);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// setuid
// int setuid(uid_t uid);
// asmlinkage long sys_setuid(uid_t uid);
pub const setuid = @compileError("TODO: setuid");

// setgid
// int setgid(gid_t gid);
// asmlinkage long sys_setgid(gid_t gid);
pub const setgid = @compileError("TODO: setgid");

// geteuid
// uid_t geteuid(void);
// asmlinkage long sys_geteuid(void);
pub fn geteuid() errno.Error!uid_t {
    const r = syscall0(.geteuid);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// getegid
// gid_t getegid(void);
// asmlinkage long sys_getegid(void);
pub fn getegid() errno.Error!gid_t {
    const r = syscall0(.getegid);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// setpgid
// int setpgid(pid_t pid, pid_t pgid);
// asmlinkage long sys_setpgid(pid_t pid, pid_t pgid);
pub const setpgid = @compileError("TODO: setpgid");

// getppid
// pid_t getppid(void);
// asmlinkage long sys_getppid(void);
pub fn getppid() errno.Error!pid_t {
    const r = syscall0(.getppid);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// getpgrp
// pid_t getpgrp(void);
// asmlinkage long sys_getpgrp(void);
pub fn getpgrp() errno.Error!pid_t {
    const r = syscall0(.getpgrp);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// setsid
// pid_t setsid(void);
// asmlinkage long sys_setsid(void);
pub fn setsid() errno.Error!pid_t {
    const r = syscall0(.setsid);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// setreuid
// int setreuid(uid_t ruid, uid_t euid);
// asmlinkage long sys_setreuid(uid_t ruid, uid_t euid);
pub const setreuid = @compileError("TODO: setreuid");

// setregid
// int setregid(gid_t rgid, gid_t egid);
// asmlinkage long sys_setregid(gid_t rgid, gid_t egid);
pub const setregid = @compileError("TODO: setregid");

// getgroups
// int getgroups(int size, gid_t list[]);
// asmlinkage long sys_getgroups(int gidsetsize, gid_t __user *grouplist);
pub const getgroups = @compileError("TODO: getgroups");

// setgroups
// int setgroups(size_t size, const gid_t *_Nullable list);
// asmlinkage long sys_setgroups(int gidsetsize, gid_t __user *grouplist);
pub const setgroups = @compileError("TODO: setgroups");

// setresuid
// int setresuid(uid_t ruid, uid_t euid, uid_t suid);
// asmlinkage long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
pub const setresuid = @compileError("TODO: setresuid");

// getresuid
// int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
// asmlinkage long sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);
pub const getresuid = @compileError("TODO: getresuid");

// setresgid
// int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
// asmlinkage long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
pub const setresgid = @compileError("TODO: setresgid");

// getresgid
// int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
// asmlinkage long sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);
pub const getresgid = @compileError("TODO: getresgid");

// getpgid
// pid_t getpgid(pid_t pid);
// asmlinkage long sys_getpgid(pid_t pid);
pub const getpgid = @compileError("TODO: getpgid");

// setfsuid
// [[deprecated]] int setfsuid(uid_t fsuid);
// asmlinkage long sys_setfsuid(uid_t uid);
pub const setfsuid = @compileError("TODO: setfsuid");

// setfsgid
// [[deprecated]] int setfsgid(gid_t fsgid);
// asmlinkage long sys_setfsgid(gid_t gid);
pub const setfsgid = @compileError("TODO: setfsgid");

// getsid
// pid_t getsid(pid_t pid);
// asmlinkage long sys_getsid(pid_t pid);
pub const getsid = @compileError("TODO: getsid");

// capget
// int syscall(SYS_capget, cap_user_header_t hdrp, cap_user_data_t datap);
// asmlinkage long sys_capget(cap_user_header_t header, cap_user_data_t dataptr);
pub const capget = @compileError("TODO: capget");

// capset
// int syscall(SYS_capset, cap_user_header_t hdrp, const cap_user_data_t datap);
// asmlinkage long sys_capset(cap_user_header_t header, const cap_user_data_t data);
pub const capset = @compileError("TODO: capset");

// rt_sigpending
// int sigpending(sigset_t *set);
// asmlinkage long sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize);
pub const rt_sigpending = @compileError("TODO: rt_sigpending");

// rt_sigtimedwait
// int sigtimedwait(const sigset_t *restrict set, siginfo_t *_Nullable restrict info, const struct timespec *restrict timeout);
// asmlinkage long sys_rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct __kernel_timespec __user *uts, size_t sigsetsize);
pub const rt_sigtimedwait = @compileError("TODO: rt_sigtimedwait");

// rt_sigqueueinfo
// int syscall(SYS_rt_sigqueueinfo, pid_t tgid, int sig, siginfo_t *info);
// asmlinkage long sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);
pub const rt_sigqueueinfo = @compileError("TODO: rt_sigqueueinfo");

// rt_sigsuspend
// int sigsuspend(const sigset_t *mask);
// asmlinkage long sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);
pub const rt_sigsuspend = @compileError("TODO: rt_sigsuspend");

// sigaltstack
// int sigaltstack(const stack_t *_Nullable restrict ss, stack_t *_Nullable restrict old_ss);
// asmlinkage long sys_sigaltstack(const struct sigaltstack __user *uss, struct sigaltstack __user *uoss);
pub const sigaltstack = @compileError("TODO: sigaltstack");

// utime
// int utime(const char *filename, const struct utimbuf *_Nullable times);
// asmlinkage long sys_utime(char __user *filename, struct utimbuf __user *times);
pub const utime = @compileError("TODO: utime");

// mknod
// int mknod(const char *pathname, mode_t mode, dev_t dev);
// asmlinkage long sys_mknod(const char __user *filename, umode_t mode, unsigned dev);
pub const mknod = @compileError("TODO: mknod");

// uselib
// [[deprecated]] int uselib(const char *library);
// asmlinkage long sys_uselib(const char __user *library);
pub const uselib = @compileError("TODO: uselib");

// personality
// int personality(unsigned long persona);
// asmlinkage long sys_personality(unsigned int personality);
pub const personality = @compileError("TODO: personality");

// ustat
// [[deprecated]] int ustat(dev_t dev, struct ustat *ubuf);
// asmlinkage long sys_ustat(unsigned dev, struct ustat __user *ubuf);
pub const ustat = @compileError("TODO: ustat");

// statfs
// int statfs(const char *path, struct statfs *buf);
// asmlinkage long sys_statfs(const char __user * path, struct statfs __user *buf);
pub const statfs = @compileError("TODO: statfs");

// fstatfs
// int fstatfs(int fd, struct statfs *buf);
// asmlinkage long sys_fstatfs(unsigned int fd, struct statfs __user *buf);
pub const fstatfs = @compileError("TODO: fstatfs");

// sysfs
//
// asmlinkage long sys_sysfs(int option, unsigned long arg1, unsigned long arg2);
pub const sysfs = @compileError("TODO: sysfs");

// getpriority
// int getpriority(int which, id_t who);
// asmlinkage long sys_getpriority(int which, int who);
pub const getpriority = @compileError("TODO: getpriority");

// setpriority
// int setpriority(int which, id_t who, int prio);
// asmlinkage long sys_setpriority(int which, int who, int niceval);
pub const setpriority = @compileError("TODO: setpriority");

// sched_setparam
// int sched_setparam(pid_t pid, const struct sched_param *param);
// asmlinkage long sys_sched_setparam(pid_t pid, struct sched_param __user *param);
pub const sched_setparam = @compileError("TODO: sched_setparam");

// sched_getparam
// int sched_getparam(pid_t pid, struct sched_param *param);
// asmlinkage long sys_sched_getparam(pid_t pid, struct sched_param __user *param);
pub const sched_getparam = @compileError("TODO: sched_getparam");

// sched_setscheduler
// int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
// asmlinkage long sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param);
pub const sched_setscheduler = @compileError("TODO: sched_setscheduler");

// sched_getscheduler
// int sched_getscheduler(pid_t pid);
// asmlinkage long sys_sched_getscheduler(pid_t pid);
pub const sched_getscheduler = @compileError("TODO: sched_getscheduler");

// sched_get_priority_max
// int sched_get_priority_max(int policy);
// asmlinkage long sys_sched_get_priority_max(int policy);
pub const sched_get_priority_max = @compileError("TODO: sched_get_priority_max");

// sched_get_priority_min
// int sched_get_priority_min(int policy);
// asmlinkage long sys_sched_get_priority_min(int policy);
pub const sched_get_priority_min = @compileError("TODO: sched_get_priority_min");

// sched_rr_get_interval
// int sched_rr_get_interval(pid_t pid, struct timespec *tp);
// asmlinkage long sys_sched_rr_get_interval(pid_t pid, struct __kernel_timespec __user *interval);
pub const sched_rr_get_interval = @compileError("TODO: sched_rr_get_interval");

// mlock
// int mlock(const void addr[.len], size_t len);
// asmlinkage long sys_mlock(unsigned long start, size_t len);
pub const mlock = @compileError("TODO: mlock");

// munlock
// int munlock(const void addr[.len], size_t len);
// asmlinkage long sys_munlock(unsigned long start, size_t len);
pub const munlock = @compileError("TODO: munlock");

// mlockall
// int mlockall(int flags);
// asmlinkage long sys_mlockall(int flags);
pub const mlockall = @compileError("TODO: mlockall");

// munlockall
// int munlockall(void);
// asmlinkage long sys_munlockall(void);
pub fn munlockall() errno.Error!c_int {
    const r = syscall0(.munlockall);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(@intFromEnum(c)),
    };
}

// vhangup
// int vhangup(void);
// asmlinkage long sys_vhangup(void);
pub const vhangup = @compileError("TODO: vhangup");

// pivot_root
// int syscall(SYS_pivot_root, const char *new_root, const char *put_old);
// asmlinkage long sys_pivot_root(const char __user *new_root, const char __user *put_old);
pub const pivot_root = @compileError("TODO: pivot_root");

// prctl
// int prctl(int op, ... /* unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5 */ );
// asmlinkage long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
pub const prctl = @compileError("TODO: prctl");

// arch_prctl
//
// asmlinkage long sys_arch_prctl(int option, unsigned long arg2)
pub const arch_prctl = @compileError("TODO: arch_prctl");

// adjtimex
// int adjtimex(struct timex *buf);
// asmlinkage long sys_adjtimex(struct __kernel_timex __user *txc_p);
pub const adjtimex = @compileError("TODO: adjtimex");

// setrlimit
// int setrlimit(int resource, const struct rlimit *rlim);
// asmlinkage long sys_setrlimit(unsigned int resource, struct rlimit __user *rlim);
pub const setrlimit = @compileError("TODO: setrlimit");

// chroot
// int chroot(const char *path);
// asmlinkage long sys_chroot(const char __user *filename);
pub const chroot = @compileError("TODO: chroot");

// sync
// void sync(void);
// asmlinkage long sys_sync(void);
pub const sync = @compileError("TODO: sync");

// acct
// int acct(const char *_Nullable filename);
// asmlinkage long sys_acct(const char __user *name);
pub const acct = @compileError("TODO: acct");

// settimeofday
// int settimeofday(const struct timeval *tv, const struct timezone *_Nullable tz);
// asmlinkage long sys_settimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);
pub const settimeofday = @compileError("TODO: settimeofday");

// mount
// int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *_Nullable data);
// asmlinkage long sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);
pub const mount = @compileError("TODO: mount");

// umount2
// int umount2(const char *target, int flags);
// asmlinkage long sys_umount(char __user *name, int flags);
pub const umount = @compileError("TODO: umount");

// swapon
// int swapon(const char *path, int swapflags);
// asmlinkage long sys_swapon(const char __user *specialfile, int swap_flags);
pub const swapon = @compileError("TODO: swapon");

// swapoff
// int swapoff(const char *path);
// asmlinkage long sys_swapoff(const char __user *specialfile);
pub const swapoff = @compileError("TODO: swapoff");

// reboot
// int reboot(int op);
// asmlinkage long sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);
pub const reboot = @compileError("TODO: reboot");

// sethostname
// int sethostname(const char *name, size_t len);
// asmlinkage long sys_sethostname(char __user *name, int len);
pub const sethostname = @compileError("TODO: sethostname");

// setdomainname
// int setdomainname(const char *name, size_t len);
// asmlinkage long sys_setdomainname(char __user *name, int len);
pub const setdomainname = @compileError("TODO: setdomainname");

// ioperm
// int ioperm(unsigned long from, unsigned long num, int turn_on);
// asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int on);
pub const ioperm = @compileError("TODO: ioperm");

// init_module
// int syscall(SYS_init_module, void module_image[.len], unsigned long len, const char *param_values);
// asmlinkage long sys_init_module(void __user *umod, unsigned long len, const char __user *uargs);
pub const init_module = @compileError("TODO: init_module");

// delete_module
// int syscall(SYS_delete_module, const char *name, unsigned int flags);
// asmlinkage long sys_delete_module(const char __user *name_user, unsigned int flags);
pub const delete_module = @compileError("TODO: delete_module");

// quotactl
// int quotactl(int op, const char *_Nullable special, int id, caddr_t addr);
// asmlinkage long sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);
pub const quotactl = @compileError("TODO: quotactl");

// gettid
// pid_t gettid(void);
// asmlinkage long sys_gettid(void);
pub const gettid = @compileError("TODO: gettid");

// readahead
// ssize_t readahead(int fd, off_t offset, size_t count);
// asmlinkage long sys_readahead(int fd, loff_t offset, size_t count);
pub const readahead = @compileError("TODO: readahead");

// setxattr
// int setxattr(const char *path, const char *name, const void value[.size], size_t size, int flags);
// asmlinkage long sys_setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
pub const setxattr = @compileError("TODO: setxattr");

// lsetxattr
// int lsetxattr(const char *path, const char *name, const void value[.size], size_t size, int flags);
// asmlinkage long sys_lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
pub const lsetxattr = @compileError("TODO: lsetxattr");

// fsetxattr
// int fsetxattr(int fd, const char *name, const void value[.size], size_t size, int flags);
// asmlinkage long sys_fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags);
pub const fsetxattr = @compileError("TODO: fsetxattr");

// getxattr
// ssize_t getxattr(const char *path, const char *name, void value[.size], size_t size);
// asmlinkage long sys_getxattr(const char __user *path, const char __user *name, void __user *value, size_t size);
pub const getxattr = @compileError("TODO: getxattr");

// lgetxattr
// ssize_t lgetxattr(const char *path, const char *name, void value[.size], size_t size);
// asmlinkage long sys_lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size);
pub const lgetxattr = @compileError("TODO: lgetxattr");

// fgetxattr
// ssize_t fgetxattr(int fd, const char *name, void value[.size], size_t size);
// asmlinkage long sys_fgetxattr(int fd, const char __user *name, void __user *value, size_t size);
pub const fgetxattr = @compileError("TODO: fgetxattr");

// listxattr
// ssize_t listxattr(const char *path, char *_Nullable list, size_t size);
// asmlinkage long sys_listxattr(const char __user *path, char __user *list, size_t size);
pub const listxattr = @compileError("TODO: listxattr");

// llistxattr
// ssize_t llistxattr(const char *path, char *_Nullable list, size_t size);
// asmlinkage long sys_llistxattr(const char __user *path, char __user *list, size_t size);
pub const llistxattr = @compileError("TODO: llistxattr");

// flistxattr
// ssize_t flistxattr(int fd, char *_Nullable list, size_t size);
// asmlinkage long sys_flistxattr(int fd, char __user *list, size_t size);
pub const flistxattr = @compileError("TODO: flistxattr");

// removexattr
// int removexattr(const char *path, const char *name);
// asmlinkage long sys_removexattr(const char __user *path, const char __user *name);
pub const removexattr = @compileError("TODO: removexattr");

// lremovexattr
// int lremovexattr(const char *path, const char *name);
// asmlinkage long sys_lremovexattr(const char __user *path, const char __user *name);
pub const lremovexattr = @compileError("TODO: lremovexattr");

// fremovexattr
// int fremovexattr(int fd, const char *name);
// asmlinkage long sys_fremovexattr(int fd, const char __user *name);
pub const fremovexattr = @compileError("TODO: fremovexattr");

// tkill
// [[deprecated]] int syscall(SYS_tkill, pid_t tid, int sig);
// asmlinkage long sys_tkill(pid_t pid, int sig);
pub const tkill = @compileError("TODO: tkill");

// time
// time_t time(time_t *_Nullable tloc);
// asmlinkage long sys_time(__kernel_old_time_t __user *tloc);
pub const time = @compileError("TODO: time");

// futex
// long syscall(SYS_futex, uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout,   /* or: uint32_t val2 */ uint32_t *uaddr2, uint32_t val3);
// asmlinkage long sys_futex(u32 __user *uaddr, int op, u32 val, const struct __kernel_timespec __user *utime, u32 __user *uaddr2, u32 val3);
pub const futex = @compileError("TODO: futex");

// sched_setaffinity
// int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
// asmlinkage long sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
pub const sched_setaffinity = @compileError("TODO: sched_setaffinity");

// sched_getaffinity
// int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
// asmlinkage long sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
pub const sched_getaffinity = @compileError("TODO: sched_getaffinity");

// io_setup
// long io_setup(unsigned int nr_events, aio_context_t *ctx_idp);
// asmlinkage long sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx);
pub const io_setup = @compileError("TODO: io_setup");

// io_destroy
// int syscall(SYS_io_destroy, aio_context_t ctx_id);
// asmlinkage long sys_io_destroy(aio_context_t ctx);
pub const io_destroy = @compileError("TODO: io_destroy");

// io_getevents
// int syscall(SYS_io_getevents, aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout);
// asmlinkage long sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout);
pub const io_getevents = @compileError("TODO: io_getevents");

// io_submit
// int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
// asmlinkage long sys_io_submit(aio_context_t, long, struct iocb __user * __user *);
pub const io_submit = @compileError("TODO: io_submit");

// io_cancel
// int syscall(SYS_io_cancel, aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
// asmlinkage long sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result);
pub const io_cancel = @compileError("TODO: io_cancel");

// epoll_create
// int epoll_create(int size);
// asmlinkage long sys_epoll_create(int size);
pub const epoll_create = @compileError("TODO: epoll_create");

// remap_file_pages
// [[deprecated]] int remap_file_pages(void addr[.size], size_t size, int prot, size_t pgoff, int flags);
// asmlinkage long sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
pub const remap_file_pages = @compileError("TODO: remap_file_pages");

// getdents64
// ssize_t getdents64(int fd, void dirp[.count], size_t count);
// asmlinkage long sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
pub const getdents64 = @compileError("TODO: getdents64");

// set_tid_address
// pid_t syscall(SYS_set_tid_address, int *tidptr);
// asmlinkage long sys_set_tid_address(int __user *tidptr);
pub const set_tid_address = @compileError("TODO: set_tid_address");

// semtimedop
// int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *_Nullable timeout);
// asmlinkage long sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct __kernel_timespec __user *timeout);
pub const semtimedop = @compileError("TODO: semtimedop");

// fadvise64
// int posix_fadvise(int fd, off_t offset, off_t size, int advice);
// asmlinkage long sys_fadvise64(int fd, loff_t offset, size_t len, int advice);
pub const fadvise64 = @compileError("TODO: fadvise64");

// timer_create
// int timer_create(clockid_t clockid, struct sigevent *_Nullable restrict sevp, timer_t *restrict timerid);
// asmlinkage long sys_timer_create(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id);
pub const timer_create = @compileError("TODO: timer_create");

// timer_settime
// int timer_settime(timer_t timerid, int flags, const struct itimerspec *restrict new_value, struct itimerspec *_Nullable restrict old_value);
// asmlinkage long sys_timer_settime(timer_t timer_id, int flags, const struct __kernel_itimerspec __user *new_setting, struct __kernel_itimerspec __user *old_setting);
pub const timer_settime = @compileError("TODO: timer_settime");

// timer_gettime
// int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
// asmlinkage long sys_timer_gettime(timer_t timer_id, struct __kernel_itimerspec __user *setting);
pub const timer_gettime = @compileError("TODO: timer_gettime");

// timer_getoverrun
// int timer_getoverrun(timer_t timerid);
// asmlinkage long sys_timer_getoverrun(timer_t timer_id);
pub const timer_getoverrun = @compileError("TODO: timer_getoverrun");

// timer_delete
// int timer_delete(timer_t timerid);
// asmlinkage long sys_timer_delete(timer_t timer_id);
pub const timer_delete = @compileError("TODO: timer_delete");

// clock_settime
// int clock_settime(clockid_t clockid, const struct timespec *tp);
// asmlinkage long sys_clock_settime(clockid_t which_clock, const struct __kernel_timespec __user *tp);
pub const clock_settime = @compileError("TODO: clock_settime");

// clock_gettime
// int clock_gettime(clockid_t clockid, struct timespec *tp);
// asmlinkage long sys_clock_gettime(clockid_t which_clock, struct __kernel_timespec __user *tp);
pub const clock_gettime = @compileError("TODO: clock_gettime");

// clock_getres
// int clock_getres(clockid_t clockid, struct timespec *_Nullable res);
// asmlinkage long sys_clock_getres(clockid_t which_clock, struct __kernel_timespec __user *tp);
pub const clock_getres = @compileError("TODO: clock_getres");

// clock_nanosleep
// int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *t, struct timespec *_Nullable remain);
// asmlinkage long sys_clock_nanosleep(clockid_t which_clock, int flags, const struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);
pub const clock_nanosleep = @compileError("TODO: clock_nanosleep");

// exit_group
// [[noreturn]] void syscall(SYS_exit_group, int status);
// asmlinkage long sys_exit_group(int error_code);
pub const exit_group = @compileError("TODO: exit_group");

// epoll_wait
// int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
// asmlinkage long sys_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout);
pub const epoll_wait = @compileError("TODO: epoll_wait");

// epoll_ctl
// int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
// asmlinkage long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event);
pub const epoll_ctl = @compileError("TODO: epoll_ctl");

// tgkill
// int tgkill(pid_t tgid, pid_t tid, int sig);
// asmlinkage long sys_tgkill(pid_t tgid, pid_t pid, int sig);
pub const tgkill = @compileError("TODO: tgkill");

// utimes
// int utimes(const char *filename, const struct timeval times[_Nullable 2]);
// asmlinkage long sys_utimes(char __user *filename, struct __kernel_old_timeval __user *utimes);
pub const utimes = @compileError("TODO: utimes");

// mbind
// long mbind(void addr[.len], unsigned long len, int mode, const unsigned long nodemask[(.maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH], unsigned long maxnode, unsigned int flags);
// asmlinkage long sys_mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned flags);
pub const mbind = @compileError("TODO: mbind");

// set_mempolicy
// long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
// asmlinkage long sys_set_mempolicy(int mode, const unsigned long __user *nmask, unsigned long maxnode);
pub const set_mempolicy = @compileError("TODO: set_mempolicy");

// get_mempolicy
// long get_mempolicy(int *mode, unsigned long nodemask[(.maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH], unsigned long maxnode, void *addr, unsigned long flags);
// asmlinkage long sys_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
pub const get_mempolicy = @compileError("TODO: get_mempolicy");

// mq_open
// mqd_t mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr);
// asmlinkage long sys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr);
pub const mq_open = @compileError("TODO: mq_open");

// mq_unlink
// int mq_unlink(const char *name);
// asmlinkage long sys_mq_unlink(const char __user *name);
pub const mq_unlink = @compileError("TODO: mq_unlink");

// mq_timedsend
// int mq_timedsend(mqd_t mqdes, const char msg_ptr[.msg_len], size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);
// asmlinkage long sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user *abs_timeout);
pub const mq_timedsend = @compileError("TODO: mq_timedsend");

// mq_timedreceive
// ssize_t mq_timedreceive(mqd_t mqdes, char *restrict msg_ptr[.msg_len], size_t msg_len, unsigned int *restrict msg_prio, const struct timespec *restrict abs_timeout);
// asmlinkage long sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct __kernel_timespec __user *abs_timeout);
pub const mq_timedreceive = @compileError("TODO: mq_timedreceive");

// mq_notify
// int mq_notify(mqd_t mqdes, const struct sigevent *sevp);
// asmlinkage long sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification);
pub const mq_notify = @compileError("TODO: mq_notify");

// mq_getsetattr
// int syscall(SYS_mq_getsetattr, mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr);
// asmlinkage long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);
pub const mq_getsetattr = @compileError("TODO: mq_getsetattr");

// kexec_load
// long syscall(SYS_kexec_load, unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
// asmlinkage long sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags);
pub const kexec_load = @compileError("TODO: kexec_load");

// waitid
// int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
// asmlinkage long sys_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru);
pub const waitid = @compileError("TODO: waitid");

// add_key
// key_serial_t add_key(const char *type, const char *description, const void payload[.plen], size_t plen, key_serial_t keyring);
// asmlinkage long sys_add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid);
pub const add_key = @compileError("TODO: add_key");

// request_key
// key_serial_t request_key(const char *type, const char *description, const char *_Nullable callout_info, key_serial_t dest_keyring);
// asmlinkage long sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid);
pub const request_key = @compileError("TODO: request_key");

// keyctl
// long syscall(SYS_keyctl, int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
// asmlinkage long sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
pub const keyctl = @compileError("TODO: keyctl");

// ioprio_set
// int syscall(SYS_ioprio_set, int which, int who, int ioprio);
// asmlinkage long sys_ioprio_set(int which, int who, int ioprio);
pub const ioprio_set = @compileError("TODO: ioprio_set");

// ioprio_get
// int syscall(SYS_ioprio_set, int which, int who, int ioprio);
// asmlinkage long sys_ioprio_get(int which, int who);
pub const ioprio_get = @compileError("TODO: ioprio_get");

// inotify_init
// int inotify_init(void);
// asmlinkage long sys_inotify_init(void);
pub const inotify_init = @compileError("TODO: inotify_init");

// inotify_add_watch
// int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
// asmlinkage long sys_inotify_add_watch(int fd, const char __user *path, u32 mask);
pub const inotify_add_watch = @compileError("TODO: inotify_add_watch");

// inotify_rm_watch
// int inotify_rm_watch(int fd, int wd);
// asmlinkage long sys_inotify_rm_watch(int fd, __s32 wd);
pub const inotify_rm_watch = @compileError("TODO: inotify_rm_watch");

// migrate_pages
// long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);
// asmlinkage long sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to);
pub const migrate_pages = @compileError("TODO: migrate_pages");

// openat
// int openat(int dirfd, const char *pathname, int flags, ... /* mode_t mode */ );
// asmlinkage long sys_openat(int dfd, const char __user *filename, int flags, umode_t mode);
pub const openat = @compileError("TODO: openat");

// mkdirat
// int mkdirat(int dirfd, const char *pathname, mode_t mode);
// asmlinkage long sys_mkdirat(int dfd, const char __user * pathname, umode_t mode);
pub const mkdirat = @compileError("TODO: mkdirat");

// mknodat
// int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
// asmlinkage long sys_mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev);
pub const mknodat = @compileError("TODO: mknodat");

// fchownat
// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
// asmlinkage long sys_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
pub const fchownat = @compileError("TODO: fchownat");

// futimesat
// [[deprecated]] int futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
// asmlinkage long sys_futimesat(int dfd, const char __user *filename, struct __kernel_old_timeval __user *utimes);
pub const futimesat = @compileError("TODO: futimesat");

// fstatat64
// int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);
// asmlinkage long sys_fstatat64(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag);
pub const fstatat64 = @compileError("TODO: fstatat64");

// unlinkat
// int unlinkat(int dirfd, const char *pathname, int flags);
// asmlinkage long sys_unlinkat(int dfd, const char __user * pathname, int flag);
pub const unlinkat = @compileError("TODO: unlinkat");

// renameat
// int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
// asmlinkage long sys_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname);
pub const renameat = @compileError("TODO: renameat");

// linkat
// int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
// asmlinkage long sys_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
pub const linkat = @compileError("TODO: linkat");

// symlinkat
// int symlinkat(const char *target, int newdirfd, const char *linkpath);
// asmlinkage long sys_symlinkat(const char __user * oldname, int newdfd, const char __user * newname);
pub const symlinkat = @compileError("TODO: symlinkat");

// readlinkat
// ssize_t readlinkat(int dirfd, const char *restrict pathname, char *restrict buf, size_t bufsiz);
// asmlinkage long sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz);
pub const readlinkat = @compileError("TODO: readlinkat");

// fchmodat
// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
// asmlinkage long sys_fchmodat(int dfd, const char __user *filename, umode_t mode);
pub const fchmodat = @compileError("TODO: fchmodat");

// faccessat
// int faccessat(int dirfd, const char *pathname, int mode, int flags);
// asmlinkage long sys_faccessat(int dfd, const char __user *filename, int mode);
pub const faccessat = @compileError("TODO: faccessat");

// pselect6
// int pselect(int nfds, fd_set *_Nullable restrict readfds, fd_set *_Nullable restrict writefds, fd_set *_Nullable restrict exceptfds, const struct timespec *_Nullable restrict timeout, const sigset_t *_Nullable restrict sigmask);
// asmlinkage long sys_pselect6(int, fd_set __user *, fd_set __user *, fd_set __user *, struct __kernel_timespec __user *, void __user *);
pub const pselect6 = @compileError("TODO: pselect6");

// ppoll
// int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *_Nullable tmo_p, const sigset_t *_Nullable sigmask);
// asmlinkage long sys_ppoll(struct pollfd __user *, unsigned int, struct __kernel_timespec __user *, const sigset_t __user *, size_t);
pub const ppoll = @compileError("TODO: ppoll");

// unshare
// int unshare(int flags);
// asmlinkage long sys_unshare(unsigned long unshare_flags);
pub const unshare = @compileError("TODO: unshare");

// set_robust_list
// long syscall(SYS_set_robust_list, struct robust_list_head *head, size_t len);
// asmlinkage long sys_set_robust_list(struct robust_list_head __user *head, size_t len);
pub const set_robust_list = @compileError("TODO: set_robust_list");

// get_robust_list
// long syscall(SYS_get_robust_list, int pid, struct robust_list_head **head_ptr, size_t *len_ptr);
// asmlinkage long sys_get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr);
pub const get_robust_list = @compileError("TODO: get_robust_list");

// splice
// ssize_t splice(int fd_in, off_t *_Nullable off_in, int fd_out, off_t *_Nullable off_out, size_t len, unsigned int flags);
// asmlinkage long sys_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
pub const splice = @compileError("TODO: splice");

// tee
// ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
// asmlinkage long sys_tee(int fdin, int fdout, size_t len, unsigned int flags);
pub const tee = @compileError("TODO: tee");

// sync_file_range
// int sync_file_range(int fd, off_t offset, off_t nbytes, unsigned int flags);
// asmlinkage long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);
pub const sync_file_range = @compileError("TODO: sync_file_range");

// vmsplice
// ssize_t vmsplice(int fd, const struct iovec *iov, size_t nr_segs, unsigned int flags);
// asmlinkage long sys_vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);
pub const vmsplice = @compileError("TODO: vmsplice");

// move_pages
// long move_pages(int pid, unsigned long count, void *pages[.count], const int nodes[.count], int status[.count], int flags);
// asmlinkage long sys_move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags);
pub const move_pages = @compileError("TODO: move_pages");

// utimensat
// int utimensat(int dirfd, const char *pathname, const struct timespec times[_Nullable 2], int flags);
// asmlinkage long sys_utimensat(int dfd, const char __user *filename, struct __kernel_timespec __user *utimes, int flags);
pub const utimensat = @compileError("TODO: utimensat");

// epoll_pwait
// int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *_Nullable sigmask);
// asmlinkage long sys_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize);
pub const epoll_pwait = @compileError("TODO: epoll_pwait");

// signalfd
// int signalfd(int fd, const sigset_t *mask, int flags);
// asmlinkage long sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask);
pub const signalfd = @compileError("TODO: signalfd");

// timerfd_create
// int timerfd_create(int clockid, int flags);
// asmlinkage long sys_timerfd_create(int clockid, int flags);
pub const timerfd_create = @compileError("TODO: timerfd_create");

// eventfd
// int eventfd(unsigned int initval, int flags);
// asmlinkage long sys_eventfd(unsigned int count);
pub const eventfd = @compileError("TODO: eventfd");

// fallocate
// int fallocate(int fd, int mode, off_t offset, off_t len);
// asmlinkage long sys_fallocate(int fd, int mode, loff_t offset, loff_t len);
pub const fallocate = @compileError("TODO: fallocate");

// timerfd_settime
// int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *_Nullable old_value);
// asmlinkage long sys_timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec __user *utmr, struct __kernel_itimerspec __user *otmr);
pub const timerfd_settime = @compileError("TODO: timerfd_settime");

// timerfd_gettime
// int timerfd_gettime(int fd, struct itimerspec *curr_value);
// asmlinkage long sys_timerfd_gettime(int ufd, struct __kernel_itimerspec __user *otmr);
pub const timerfd_gettime = @compileError("TODO: timerfd_gettime");

// accept4
// int accept4(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen, int flags);
// asmlinkage long sys_accept4(int, struct sockaddr __user *, int __user *, int);
pub const accept4 = @compileError("TODO: accept4");

// signalfd4
// int signalfd(int fd, const sigset_t *mask, int flags);
// asmlinkage long sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);
pub const signalfd4 = @compileError("TODO: signalfd4");

// eventfd2
// int eventfd(unsigned int initval, int flags);
// asmlinkage long sys_eventfd2(unsigned int count, int flags);
pub const eventfd2 = @compileError("TODO: eventfd2");

// epoll_create1
// int epoll_create1(int flags);
// asmlinkage long sys_epoll_create1(int flags);
pub const epoll_create1 = @compileError("TODO: epoll_create1");

// dup3
// int dup3(int oldfd, int newfd, int flags);
// asmlinkage long sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);
pub const dup3 = @compileError("TODO: dup3");

// pipe2
// int pipe2(int pipefd[2], int flags);
// asmlinkage long sys_pipe2(int __user *fildes, int flags);
pub const pipe2 = @compileError("TODO: pipe2");

// inotify_init1
// int inotify_init1(int flags);
// asmlinkage long sys_inotify_init1(int flags);
pub const inotify_init1 = @compileError("TODO: inotify_init1");

// preadv
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// asmlinkage long sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
pub const preadv = @compileError("TODO: preadv");

// pwritev
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// asmlinkage long sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
pub const pwritev = @compileError("TODO: pwritev");

// rt_tgsigqueueinfo
// int syscall(SYS_rt_tgsigqueueinfo, pid_t tgid, pid_t tid, int sig, siginfo_t *info);
// asmlinkage long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo);
pub const rt_tgsigqueueinfo = @compileError("TODO: rt_tgsigqueueinfo");

// perf_event_open
// int syscall(SYS_perf_event_open, struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);
// asmlinkage long sys_perf_event_open( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);
pub const perf_event_open = @compileError("TODO: perf_event_open");

// recvmmsg
// int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);
// asmlinkage long sys_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct __kernel_timespec __user *timeout);
pub const recvmmsg = @compileError("TODO: recvmmsg");

// fanotify_init
// int fanotify_init(unsigned int flags, unsigned int event_f_flags);
// asmlinkage long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags);
pub const fanotify_init = @compileError("TODO: fanotify_init");

// fanotify_mark
// int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *_Nullable pathname);
// asmlinkage long sys_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char  __user *pathname);
pub const fanotify_mark = @compileError("TODO: fanotify_mark");

// prlimit64
// int prlimit(pid_t pid, int resource, const struct rlimit *_Nullable new_limit, struct rlimit *_Nullable old_limit);
// asmlinkage long sys_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim);
pub const prlimit64 = @compileError("TODO: prlimit64");

// name_to_handle_at
// int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);
// asmlinkage long sys_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, void __user *mnt_id, int flag);
pub const name_to_handle_at = @compileError("TODO: name_to_handle_at");

// open_by_handle_at
// int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
// asmlinkage long sys_open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags);
pub const open_by_handle_at = @compileError("TODO: open_by_handle_at");

// clock_adjtime
// int clock_adjtime(clockid_t clk_id, struct timex *buf);
// asmlinkage long sys_clock_adjtime(clockid_t which_clock, struct __kernel_timex __user *tx);
pub const clock_adjtime = @compileError("TODO: clock_adjtime");

// syncfs
// int syncfs(int fd);
// asmlinkage long sys_syncfs(int fd);
pub const syncfs = @compileError("TODO: syncfs");

// sendmmsg
// int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
// asmlinkage long sys_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);
pub const sendmmsg = @compileError("TODO: sendmmsg");

// setns
// int setns(int fd, int nstype);
// asmlinkage long sys_setns(int fd, int nstype);
pub const setns = @compileError("TODO: setns");

// getcpu
// int getcpu(unsigned int *_Nullable cpu, unsigned int *_Nullable node);
// asmlinkage long sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
pub const getcpu = @compileError("TODO: getcpu");

// process_vm_readv
// ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// asmlinkage long sys_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
pub const process_vm_readv = @compileError("TODO: process_vm_readv");

// process_vm_writev
// ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// asmlinkage long sys_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
pub const process_vm_writev = @compileError("TODO: process_vm_writev");

// kcmp
// int syscall(SYS_kcmp, pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
// asmlinkage long sys_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
pub const kcmp = @compileError("TODO: kcmp");

// finit_module
// int syscall(SYS_finit_module, int fd, const char *param_values, int flags);
// asmlinkage long sys_finit_module(int fd, const char __user *uargs, int flags);
pub const finit_module = @compileError("TODO: finit_module");

// sched_setattr
// int syscall(SYS_sched_setattr, pid_t pid, struct sched_attr *attr, unsigned int flags);
// asmlinkage long sys_sched_setattr(pid_t pid, struct sched_attr __user *attr, unsigned int flags);
pub const sched_setattr = @compileError("TODO: sched_setattr");

// sched_getattr
// int syscall(SYS_sched_getattr, pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags);
// asmlinkage long sys_sched_getattr(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags);
pub const sched_getattr = @compileError("TODO: sched_getattr");

// renameat2
// int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
// asmlinkage long sys_renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);
pub const renameat2 = @compileError("TODO: renameat2");

// seccomp
// int syscall(SYS_seccomp, unsigned int operation, unsigned int flags, void *args);
// asmlinkage long sys_seccomp(unsigned int op, unsigned int flags, void __user *uargs);
pub const seccomp = @compileError("TODO: seccomp");

// getrandom
// ssize_t getrandom(void buf[.buflen], size_t buflen, unsigned int flags);
// asmlinkage long sys_getrandom(char __user *buf, size_t count, unsigned int flags);
pub const getrandom = @compileError("TODO: getrandom");

// memfd_create
// int memfd_create(const char *name, unsigned int flags);
// asmlinkage long sys_memfd_create(const char __user *uname_ptr, unsigned int flags);
pub const memfd_create = @compileError("TODO: memfd_create");

// kexec_file_load
// long syscall(SYS_kexec_file_load, int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags);
// asmlinkage long sys_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags);
pub const kexec_file_load = @compileError("TODO: kexec_file_load");

// bpf
// int bpf(int cmd, union bpf_attr *attr, unsigned int size);
// asmlinkage long sys_bpf(int cmd, union bpf_attr __user *attr, unsigned int size);
pub const bpf = @compileError("TODO: bpf");

// execveat
// int execveat(int dirfd, const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[], int flags);
// asmlinkage long sys_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
pub const execveat = @compileError("TODO: execveat");

// userfaultfd
// int syscall(SYS_userfaultfd, int flags);
// asmlinkage long sys_userfaultfd(int flags);
pub const userfaultfd = @compileError("TODO: userfaultfd");

// membarrier
// int syscall(SYS_membarrier, int cmd, unsigned int flags, int cpu_id);
// asmlinkage long sys_membarrier(int cmd, unsigned int flags, int cpu_id);
pub const membarrier = @compileError("TODO: membarrier");

// mlock2
// int mlock2(const void addr[.len], size_t len, unsigned int flags);
// asmlinkage long sys_mlock2(unsigned long start, size_t len, int flags);
pub const mlock2 = @compileError("TODO: mlock2");

// copy_file_range
// ssize_t copy_file_range(int fd_in, off_t *_Nullable off_in, int fd_out, off_t *_Nullable off_out, size_t len, unsigned int flags);
// asmlinkage long sys_copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
pub const copy_file_range = @compileError("TODO: copy_file_range");

// preadv2
// ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
// asmlinkage long sys_preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
pub const preadv2 = @compileError("TODO: preadv2");

// pwritev2
// ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
// asmlinkage long sys_pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
pub const pwritev2 = @compileError("TODO: pwritev2");

// pkey_mprotect
// int pkey_mprotect(void addr[.len], size_t len, int prot, int pkey);
// asmlinkage long sys_pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey);
pub const pkey_mprotect = @compileError("TODO: pkey_mprotect");

// pkey_alloc
// int pkey_alloc(unsigned int flags, unsigned int access_rights);
// asmlinkage long sys_pkey_alloc(unsigned long flags, unsigned long init_val);
pub const pkey_alloc = @compileError("TODO: pkey_alloc");

// pkey_free
// int pkey_free(int pkey);
// asmlinkage long sys_pkey_free(int pkey);
pub const pkey_free = @compileError("TODO: pkey_free");

// statx
// int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf);
// asmlinkage long sys_statx(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer);
pub const statx = @compileError("TODO: statx");

// io_pgetevents
//
// asmlinkage long sys_io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout, const struct __aio_sigset __user *sig);
pub const io_pgetevents = @compileError("TODO: io_pgetevents");

// rseq
//
// asmlinkage long sys_rseq(struct rseq __user *rseq, uint32_t rseq_len, int flags, uint32_t sig);
pub const rseq = @compileError("TODO: rseq");

// pidfd_send_signal
// int syscall(SYS_pidfd_send_signal, int pidfd, int sig, siginfo_t *_Nullable info, unsigned int flags);

// io_uring_setup
// int io_uring_setup(u32 entries, struct io_uring_params *p);
// asmlinkage long sys_io_uring_setup(u32 entries, struct io_uring_params __user *p);
pub const io_uring_setup = @compileError("TODO: io_uring_setup");

// io_uring_enter
// int io_uring_enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, sigset_t *sig);
// asmlinkage long sys_io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void __user *argp, size_t argsz);
pub const io_uring_enter = @compileError("TODO: io_uring_enter");

// io_uring_register
// int io_uring_register(unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args);
// asmlinkage long sys_io_uring_register(unsigned int fd, unsigned int op, void __user *arg, unsigned int nr_args);
pub const io_uring_register = @compileError("TODO: io_uring_register");

// open_tree
//
// asmlinkage long sys_open_tree(int dfd, const char __user *path, unsigned flags);
pub const open_tree = @compileError("TODO: open_tree");

// move_mount
//
// asmlinkage long sys_move_mount(int from_dfd, const char __user *from_path, int to_dfd, const char __user *to_path, unsigned int ms_flags);
pub const move_mount = @compileError("TODO: move_mount");

// fsopen
//
// asmlinkage long sys_fsopen(const char __user *fs_name, unsigned int flags);
pub const fsopen = @compileError("TODO: fsopen");

// fsconfig
//
// asmlinkage long sys_fsconfig(int fs_fd, unsigned int cmd, const char __user *key, const void __user *value, int aux);
pub const fsconfig = @compileError("TODO: fsconfig");

// fsmount
//
// asmlinkage long sys_fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags);
pub const fsmount = @compileError("TODO: fsmount");

// fspick
//
// asmlinkage long sys_fspick(int dfd, const char __user *path, unsigned int flags);
pub const fspick = @compileError("TODO: fspick");

// pidfd_open
// int syscall(SYS_pidfd_open, pid_t pid, unsigned int flags);
// asmlinkage long sys_pidfd_open(pid_t pid, unsigned int flags);
pub const pidfd_open = @compileError("TODO: pidfd_open");

// clone3
// long syscall(SYS_clone3, struct clone_args *cl_args, size_t size);
// asmlinkage long sys_clone3(struct clone_args __user *uargs, size_t size);
pub const clone3 = @compileError("TODO: clone3");

// close_range
// int close_range(unsigned int first, unsigned int last, int flags);
// asmlinkage long sys_close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);
pub const close_range = @compileError("TODO: close_range");

// openat2
// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size);
// asmlinkage long sys_openat2(int dfd, const char __user *filename, struct open_how __user *how, size_t size);
pub const openat2 = @compileError("TODO: openat2");

// pidfd_getfd
// int syscall(SYS_pidfd_getfd, int pidfd, int targetfd, unsigned int flags);
// asmlinkage long sys_pidfd_getfd(int pidfd, int fd, unsigned int flags);
pub const pidfd_getfd = @compileError("TODO: pidfd_getfd");

// faccessat2
// int syscall(SYS_faccessat2, int dirfd, const char *pathname, int mode, int flags);
// asmlinkage long sys_faccessat2(int dfd, const char __user *filename, int mode, int flags);
pub const faccessat2 = @compileError("TODO: faccessat2");

// process_madvise
// ssize_t process_madvise(int pidfd, const struct iovec iovec[.n], size_t n, int advice, unsigned int flags);
// asmlinkage long sys_process_madvise(int pidfd, const struct iovec __user *vec, size_t vlen, int behavior, unsigned int flags);
pub const process_madvise = @compileError("TODO: process_madvise");

// epoll_pwait2
// int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct timespec *_Nullable timeout, const sigset_t *_Nullable sigmask);
// asmlinkage long sys_epoll_pwait2(int epfd, struct epoll_event __user *events, int maxevents, const struct __kernel_timespec __user *timeout, const sigset_t __user *sigmask, size_t sigsetsize);
pub const epoll_pwait2 = @compileError("TODO: epoll_pwait2");

// mount_setattr
// int syscall(SYS_mount_setattr, int dirfd, const char *pathname, unsigned int flags, struct mount_attr *attr, size_t size);
// asmlinkage long sys_mount_setattr(int dfd, const char __user *path, unsigned int flags, struct mount_attr __user *uattr, size_t usize);
pub const mount_setattr = @compileError("TODO: mount_setattr");

// quotactl_fd
// int quotactl(int op, const char *_Nullable special, int id, caddr_t addr);
// asmlinkage long sys_quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void __user *addr);
pub const quotactl_fd = @compileError("TODO: quotactl_fd");

// landlock_create_ruleset
// int syscall(SYS_landlock_create_ruleset, const struct landlock_ruleset_attr *attr, size_t size , uint32_t flags);
// asmlinkage long sys_landlock_create_ruleset(const struct landlock_ruleset_attr __user *attr, size_t size, __u32 flags);
pub const landlock_create_ruleset = @compileError("TODO: landlock_create_ruleset");

// landlock_add_rule
// int syscall(SYS_landlock_add_rule, int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags);
// asmlinkage long sys_landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void __user *rule_attr, __u32 flags);
pub const landlock_add_rule = @compileError("TODO: landlock_add_rule");

// landlock_restrict_self
// int syscall(SYS_landlock_restrict_self, int ruleset_fd, uint32_t flags);
// asmlinkage long sys_landlock_restrict_self(int ruleset_fd, __u32 flags);
pub const landlock_restrict_self = @compileError("TODO: landlock_restrict_self");

// memfd_secret
// int syscall(SYS_memfd_secret, unsigned int flags);
// asmlinkage long sys_memfd_secret(unsigned int flags);
pub const memfd_secret = @compileError("TODO: memfd_secret");

// process_mrelease
//
// asmlinkage long sys_process_mrelease(int pidfd, unsigned int flags);
pub const process_mrelease = @compileError("TODO: process_mrelease");

// futex_waitv
//
// asmlinkage long sys_futex_waitv(struct futex_waitv __user *waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec __user *timeout, clockid_t clockid);
pub const futex_waitv = @compileError("TODO: futex_waitv");

// set_mempolicy_home_node
//
// asmlinkage long sys_set_mempolicy_home_node(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);
pub const set_mempolicy_home_node = @compileError("TODO: set_mempolicy_home_node");

// cachestat
//
// asmlinkage long sys_cachestat(unsigned int fd, struct cachestat_range __user *cstat_range, struct cachestat __user *cstat, unsigned int flags);
pub const cachestat = @compileError("TODO: cachestat");

// fchmodat2
//
// asmlinkage long sys_fchmodat2(int dfd, const char __user *filename, umode_t mode, unsigned int flags);
pub const fchmodat2 = @compileError("TODO: fchmodat2");

// map_shadow_stack
//
// asmlinkage long sys_map_shadow_stack(unsigned long addr, unsigned long size, unsigned int flags);
pub const map_shadow_stack = @compileError("TODO: map_shadow_stack");

// futex_wake
//
// asmlinkage long sys_futex_wake(void __user *uaddr, unsigned long mask, int nr, unsigned int flags);
pub const futex_wake = @compileError("TODO: futex_wake");

// futex_wait
//
// asmlinkage long sys_futex_wait(void __user *uaddr, unsigned long val, unsigned long mask, unsigned int flags, struct __kernel_timespec __user *timespec, clockid_t clockid);
pub const futex_wait = @compileError("TODO: futex_wait");

// futex_requeue
//
// asmlinkage long sys_futex_requeue(struct futex_waitv __user *waiters, unsigned int flags, int nr_wake, int nr_requeue);
pub const futex_requeue = @compileError("TODO: futex_requeue");
