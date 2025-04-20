const std = @import("std");
const sys = std.os.linux;
const syscall0 = sys.syscall0;
const syscall1 = sys.syscall1;
const syscall2 = sys.syscall2;
const syscall3 = sys.syscall3;
const syscall4 = sys.syscall4;
const syscall5 = sys.syscall5;
const syscall6 = sys.syscall6;
const errno = @import("errno");

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

// close
// int close(int fd);
// asmlinkage long sys_close(unsigned int fd);

// stat
// int stat(const char *restrict pathname, struct stat *restrict statbuf);
// asmlinkage long sys_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);

// fstat
// int fstat(int fd, struct stat *statbuf);
// asmlinkage long sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf);

// lstat
// int lstat(const char *restrict pathname, struct stat *restrict statbuf);
// asmlinkage long sys_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);

// poll
// int poll(struct pollfd *fds, nfds_t nfds, int timeout);
// asmlinkage long sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);

// lseek
// off_t lseek(int fd, off_t offset, int whence);
// asmlinkage long sys_lseek(unsigned int fd, off_t offset, unsigned int whence);

// mmap
// void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
// asmlinkage long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);

// mprotect
// int mprotect(void addr[.len], size_t len, int prot);
// asmlinkage long sys_mprotect(unsigned long start, size_t len, unsigned long prot);

// munmap
// int munmap(void addr[.length], size_t length);
// asmlinkage long sys_munmap(unsigned long addr, size_t len);

// brk
// int brk(void *addr);
// asmlinkage long sys_brk(unsigned long brk);

// rt_sigaction
// int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
// asmlinkage long sys_rt_sigaction(int, const struct sigaction __user *, struct sigaction __user *, size_t);

// rt_sigprocmask
// int sigprocmask(int how, const sigset_t *_Nullable restrict set, sigset_t *_Nullable restrict oldset);
// asmlinkage long sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize);

// rt_sigreturn
// int sigreturn(...);
// asmlinkage long sys_rt_sigreturn(struct pt_regs *regs);

// ioctl
// int ioctl(int fd, unsigned long op, ...);
// asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);

// pread64
// ssize_t pread(int fd, void buf[.count], size_t count, off_t offset);
// asmlinkage long sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);

// pwrite64
// ssize_t pwrite(int fd, const void buf[.count], size_t count, off_t offset);
// asmlinkage long sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);

// readv
// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
// asmlinkage long sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);

// writev
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
// asmlinkage long sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);

// access
// int access(const char *pathname, int mode);
// asmlinkage long sys_access(const char __user *filename, int mode);

// pipe
// int pipe(int pipefd[2]);
// asmlinkage long sys_pipe(int __user *fildes);

// select
// int select(int nfds, fd_set *_Nullable restrict readfds, fd_set *_Nullable restrict writefds, fd_set *_Nullable restrict exceptfds, struct timeval *_Nullable restrict timeout);
// asmlinkage long sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct __kernel_old_timeval __user *tvp);

// sched_yield
// int sched_yield(void);
// asmlinkage long sys_sched_yield(void);

// mremap
// void *mremap(void old_address[.old_size], size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
// asmlinkage long sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);

// msync
// int msync(void addr[.length], size_t length, int flags);
// asmlinkage long sys_msync(unsigned long start, size_t len, int flags);

// mincore
// int mincore(void addr[.length], size_t length, unsigned char *vec);
// asmlinkage long sys_mincore(unsigned long start, size_t len, unsigned char __user * vec);

// madvise
// int madvise(void addr[.length], size_t length, int advice);
// asmlinkage long sys_madvise(unsigned long start, size_t len, int behavior);

// shmget
// int shmget(key_t key, size_t size, int shmflg);
// asmlinkage long sys_shmget(key_t key, size_t size, int flag);

// shmat
// void *shmat(int shmid, const void *_Nullable shmaddr, int shmflg);
// asmlinkage long sys_shmat(int shmid, char __user *shmaddr, int shmflg);

// shmctl
// int shmctl(int shmid, int op, struct shmid_ds *buf);
// asmlinkage long sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf);

// dup
// int dup(int oldfd);
// asmlinkage long sys_dup(unsigned int fildes);

// dup2
// int dup2(int oldfd, int newfd);
// asmlinkage long sys_dup2(unsigned int oldfd, unsigned int newfd);

// pause
// int pause(void);
// asmlinkage long sys_pause(void);

// nanosleep
// int nanosleep(const struct timespec *duration, struct timespec *_Nullable rem);
// asmlinkage long sys_nanosleep(struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);

// getitimer
// int getitimer(int which, struct itimerval *curr_value);
// asmlinkage long sys_getitimer(int which, struct __kernel_old_itimerval __user *value);

// alarm
// unsigned int alarm(unsigned int seconds);
// asmlinkage long sys_alarm(unsigned int seconds);

// setitimer
// int setitimer(int which, const struct itimerval *restrict new_value, struct itimerval *_Nullable restrict old_value);
// asmlinkage long sys_setitimer(int which, struct __kernel_old_itimerval __user *value, struct __kernel_old_itimerval __user *ovalue);

// getpid
// pid_t getpid(void);
// asmlinkage long sys_getpid(void);

// sendfile
// ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset, size_t count);
// asmlinkage long sys_sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count);

// socket
// int socket(int domain, int type, int protocol);
// asmlinkage long sys_socket(int, int, int);

// connect
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
// asmlinkage long sys_connect(int, struct sockaddr __user *, int);

// accept
// int accept(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen);
// asmlinkage long sys_accept(int, struct sockaddr __user *, int __user *);

// sendto
// ssize_t sendto(int sockfd, const void buf[.len], size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
// asmlinkage long sys_sendto(int, void __user *, size_t, unsigned, struct sockaddr __user *, int);

// recvfrom
// ssize_t recvfrom(int sockfd, void buf[restrict .len], size_t len, int flags, struct sockaddr *_Nullable restrict src_addr, socklen_t *_Nullable restrict addrlen);
// asmlinkage long sys_recvfrom(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *);

// sendmsg
// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
// asmlinkage long sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags);

// recvmsg
// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
// asmlinkage long sys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags);

// shutdown
// int shutdown(int sockfd, int how);
// asmlinkage long sys_shutdown(int, int);

// bind
// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
// asmlinkage long sys_bind(int, struct sockaddr __user *, int);

// listen
// int listen(int sockfd, int backlog);
// asmlinkage long sys_listen(int, int);

// getsockname
// int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
// asmlinkage long sys_getsockname(int, struct sockaddr __user *, int __user *);

// getpeername
// int getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
// asmlinkage long sys_getpeername(int, struct sockaddr __user *, int __user *);

// socketpair
// int socketpair(int domain, int type, int protocol, int sv[2]);
// asmlinkage long sys_socketpair(int, int, int, int __user *);

// setsockopt
// int setsockopt(int sockfd, int level, int optname, const void optval[.optlen], socklen_t optlen);
// asmlinkage long sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen);

// getsockopt
// int getsockopt(int sockfd, int level, int optname, void optval[restrict *.optlen], socklen_t *restrict optlen);
// asmlinkage long sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen);

// clone
// int clone(int (*fn)(void *_Nullable), void *stack, int flags, void *_Nullable arg, ...  /* pid_t *_Nullable parent_tid, void *_Nullable tls, pid_t *_Nullable child_tid */ );
// asmlinkage long sys_clone(unsigned long, unsigned long, int __user *, int __user *, unsigned long);

// fork
// pid_t fork(void);
// asmlinkage long sys_fork(void);

// vfork
// pid_t vfork(void);
// asmlinkage long sys_vfork(void);

// execve
// int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[]);
// asmlinkage long sys_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);

// exit
// [[noreturn]] void _exit(int status);
// asmlinkage long sys_exit(int error_code);

// wait4
// pid_t wait4(pid_t pid, int *_Nullable wstatus, int options, struct rusage *_Nullable rusage);
// asmlinkage long sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru);

// kill
// int kill(pid_t pid, int sig);
// asmlinkage long sys_kill(pid_t pid, int sig);

// uname
// int uname(struct utsname *buf);
// asmlinkage long sys_uname(struct old_utsname __user *);

// semget
// int semget(key_t key, int nsems, int semflg);
// asmlinkage long sys_semget(key_t key, int nsems, int semflg);

// semop
// int semop(int semid, struct sembuf *sops, size_t nsops);
// asmlinkage long sys_semop(int semid, struct sembuf __user *sops, unsigned nsops);

// semctl
// int semctl(int semid, int semnum, int op, ...);
// asmlinkage long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);

// shmdt
// int shmdt(const void *shmaddr);
// asmlinkage long sys_shmdt(char __user *shmaddr);

// msgget
// int msgget(key_t key, int msgflg);
// asmlinkage long sys_msgget(key_t key, int msgflg);

// msgsnd
// int msgsnd(int msqid, const void msgp[.msgsz], size_t msgsz, int msgflg);
// asmlinkage long sys_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg);

// msgrcv
// ssize_t msgrcv(int msqid, void msgp[.msgsz], size_t msgsz, long msgtyp, int msgflg);
// asmlinkage long sys_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg);

// msgctl
// int msgctl(int msqid, int op, struct msqid_ds *buf);
// asmlinkage long sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf);

// fcntl
// int fcntl(int fd, int op, ... /* arg */ );
// asmlinkage long sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);

// flock
// int flock(int fd, int op);
// asmlinkage long sys_flock(unsigned int fd, unsigned int cmd);

// fsync
// int fsync(int fd);
// asmlinkage long sys_fsync(unsigned int fd);

// fdatasync
// int fdatasync(int fd);
// asmlinkage long sys_fdatasync(unsigned int fd);

// truncate
// int truncate(const char *path, off_t length);
// asmlinkage long sys_truncate(const char __user *path, long length);

// ftruncate
// int ftruncate(int fd, off_t length);
// asmlinkage long sys_ftruncate(unsigned int fd, off_t length);

// getdents
// long syscall(SYS_getdents, unsigned int fd, struct linux_dirent *dirp, unsigned int count);
// asmlinkage long sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);

// getcwd
// char *getcwd(char buf[.size], size_t size);
// asmlinkage long sys_getcwd(char __user *buf, unsigned long size);

// chdir
// int chdir(const char *path);
// asmlinkage long sys_chdir(const char __user *filename);

// fchdir
// int fchdir(int fd);
// asmlinkage long sys_fchdir(unsigned int fd);

// rename
// int rename(const char *oldpath, const char *newpath);
// asmlinkage long sys_rename(const char __user *oldname, const char __user *newname);

// mkdir
// int mkdir(const char *pathname, mode_t mode);
// asmlinkage long sys_mkdir(const char __user *pathname, umode_t mode);

// rmdir
// int rmdir(const char *pathname);
// asmlinkage long sys_rmdir(const char __user *pathname);

// creat
// int creat(const char *pathname, mode_t mode);
// asmlinkage long sys_creat(const char __user *pathname, umode_t mode);

// link
// int link(const char *oldpath, const char *newpath);
// asmlinkage long sys_link(const char __user *oldname, const char __user *newname);

// unlink
// int unlink(const char *pathname);
// asmlinkage long sys_unlink(const char __user *pathname);

// symlink
// int symlink(const char *target, const char *linkpath);
// asmlinkage long sys_symlink(const char __user *old, const char __user *new);

// readlink
// ssize_t readlink(const char *restrict pathname, char *restrict buf, size_t bufsiz);
// asmlinkage long sys_readlink(const char __user *path, char __user *buf, int bufsiz);

// chmod
// int chmod(const char *pathname, mode_t mode);
// asmlinkage long sys_chmod(const char __user *filename, umode_t mode);

// fchmod
// int fchmod(int fd, mode_t mode);
// asmlinkage long sys_fchmod(unsigned int fd, umode_t mode);

// chown
// int chown(const char *pathname, uid_t owner, gid_t group);
// asmlinkage long sys_chown(const char __user *filename, uid_t user, gid_t group);

// fchown
// int fchown(int fd, uid_t owner, gid_t group);
// asmlinkage long sys_fchown(unsigned int fd, uid_t user, gid_t group);

// lchown
// int lchown(const char *pathname, uid_t owner, gid_t group);
// asmlinkage long sys_lchown(const char __user *filename, uid_t user, gid_t group);

// umask
// mode_t umask(mode_t mask);
// asmlinkage long sys_umask(int mask);

// gettimeofday
// int gettimeofday(struct timeval *restrict tv, struct timezone *_Nullable restrict tz);
// asmlinkage long sys_gettimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);

// getrlimit
// int getrlimit(int resource, struct rlimit *rlim);
// asmlinkage long sys_getrlimit(unsigned int resource, struct rlimit __user *rlim);

// getrusage
// int getrusage(int who, struct rusage *usage);
// asmlinkage long sys_getrusage(int who, struct rusage __user *ru);

// sysinfo
// int sysinfo(struct sysinfo *info);
// asmlinkage long sys_sysinfo(struct sysinfo __user *info);

// times
// clock_t times(struct tms *buf);
// asmlinkage long sys_times(struct tms __user *tbuf);

// ptrace
// long ptrace(enum __ptrace_request op, pid_t pid, void *addr, void *data);
// asmlinkage long sys_ptrace(long request, long pid, unsigned long addr, unsigned long data);

// getuid
// uid_t getuid(void);
// asmlinkage long sys_getuid(void);

// syslog
// int syscall(SYS_syslog, int type, char *bufp, int len);
// asmlinkage long sys_syslog(int type, char __user *buf, int len);

// getgid
// gid_t getgid(void);
// asmlinkage long sys_getgid(void);

// setuid
// int setuid(uid_t uid);
// asmlinkage long sys_setuid(uid_t uid);

// setgid
// int setgid(gid_t gid);
// asmlinkage long sys_setgid(gid_t gid);

// geteuid
// uid_t geteuid(void);
// asmlinkage long sys_geteuid(void);

// getegid
// gid_t getegid(void);
// asmlinkage long sys_getegid(void);

// setpgid
// int setpgid(pid_t pid, pid_t pgid);
// asmlinkage long sys_setpgid(pid_t pid, pid_t pgid);

// getppid
// pid_t getppid(void);
// asmlinkage long sys_getppid(void);

// getpgrp
// pid_t getpgrp(void);
// asmlinkage long sys_getpgrp(void);

// setsid
// pid_t setsid(void);
// asmlinkage long sys_setsid(void);

// setreuid
// int setreuid(uid_t ruid, uid_t euid);
// asmlinkage long sys_setreuid(uid_t ruid, uid_t euid);

// setregid
// int setregid(gid_t rgid, gid_t egid);
// asmlinkage long sys_setregid(gid_t rgid, gid_t egid);

// getgroups
// int getgroups(int size, gid_t list[]);
// asmlinkage long sys_getgroups(int gidsetsize, gid_t __user *grouplist);

// setgroups
// int setgroups(size_t size, const gid_t *_Nullable list);
// asmlinkage long sys_setgroups(int gidsetsize, gid_t __user *grouplist);

// setresuid
// int setresuid(uid_t ruid, uid_t euid, uid_t suid);
// asmlinkage long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);

// getresuid
// int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
// asmlinkage long sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);

// setresgid
// int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
// asmlinkage long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);

// getresgid
// int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
// asmlinkage long sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);

// getpgid
// pid_t getpgid(pid_t pid);
// asmlinkage long sys_getpgid(pid_t pid);

// setfsuid
// [[deprecated]] int setfsuid(uid_t fsuid);
// asmlinkage long sys_setfsuid(uid_t uid);

// setfsgid
// [[deprecated]] int setfsgid(gid_t fsgid);
// asmlinkage long sys_setfsgid(gid_t gid);

// getsid
// pid_t getsid(pid_t pid);
// asmlinkage long sys_getsid(pid_t pid);

// capget
// int syscall(SYS_capget, cap_user_header_t hdrp, cap_user_data_t datap);
// asmlinkage long sys_capget(cap_user_header_t header, cap_user_data_t dataptr);

// capset
// int syscall(SYS_capset, cap_user_header_t hdrp, const cap_user_data_t datap);
// asmlinkage long sys_capset(cap_user_header_t header, const cap_user_data_t data);

// rt_sigpending
// int sigpending(sigset_t *set);
// asmlinkage long sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize);

// rt_sigtimedwait
// int sigtimedwait(const sigset_t *restrict set, siginfo_t *_Nullable restrict info, const struct timespec *restrict timeout);
// asmlinkage long sys_rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct __kernel_timespec __user *uts, size_t sigsetsize);

// rt_sigqueueinfo
// int syscall(SYS_rt_sigqueueinfo, pid_t tgid, int sig, siginfo_t *info);
// asmlinkage long sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);

// rt_sigsuspend
// int sigsuspend(const sigset_t *mask);
// asmlinkage long sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);

// sigaltstack
// int sigaltstack(const stack_t *_Nullable restrict ss, stack_t *_Nullable restrict old_ss);
// asmlinkage long sys_sigaltstack(const struct sigaltstack __user *uss, struct sigaltstack __user *uoss);

// utime
// int utime(const char *filename, const struct utimbuf *_Nullable times);
// asmlinkage long sys_utime(char __user *filename, struct utimbuf __user *times);

// mknod
// int mknod(const char *pathname, mode_t mode, dev_t dev);
// asmlinkage long sys_mknod(const char __user *filename, umode_t mode, unsigned dev);

// uselib
// [[deprecated]] int uselib(const char *library);
// asmlinkage long sys_uselib(const char __user *library);

// personality
// int personality(unsigned long persona);
// asmlinkage long sys_personality(unsigned int personality);

// ustat
// [[deprecated]] int ustat(dev_t dev, struct ustat *ubuf);
// asmlinkage long sys_ustat(unsigned dev, struct ustat __user *ubuf);

// statfs
// int statfs(const char *path, struct statfs *buf);
// asmlinkage long sys_statfs(const char __user * path, struct statfs __user *buf);

// fstatfs
// int fstatfs(int fd, struct statfs *buf);
// asmlinkage long sys_fstatfs(unsigned int fd, struct statfs __user *buf);

// sysfs
//
// asmlinkage long sys_sysfs(int option, unsigned long arg1, unsigned long arg2);

// getpriority
// int getpriority(int which, id_t who);
// asmlinkage long sys_getpriority(int which, int who);

// setpriority
// int setpriority(int which, id_t who, int prio);
// asmlinkage long sys_setpriority(int which, int who, int niceval);

// sched_setparam
// int sched_setparam(pid_t pid, const struct sched_param *param);
// asmlinkage long sys_sched_setparam(pid_t pid, struct sched_param __user *param);

// sched_getparam
// int sched_getparam(pid_t pid, struct sched_param *param);
// asmlinkage long sys_sched_getparam(pid_t pid, struct sched_param __user *param);

// sched_setscheduler
// int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
// asmlinkage long sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param);

// sched_getscheduler
// int sched_getscheduler(pid_t pid);
// asmlinkage long sys_sched_getscheduler(pid_t pid);

// sched_get_priority_max
// int sched_get_priority_max(int policy);
// asmlinkage long sys_sched_get_priority_max(int policy);

// sched_get_priority_min
// int sched_get_priority_min(int policy);
// asmlinkage long sys_sched_get_priority_min(int policy);

// sched_rr_get_interval
// int sched_rr_get_interval(pid_t pid, struct timespec *tp);
// asmlinkage long sys_sched_rr_get_interval(pid_t pid, struct __kernel_timespec __user *interval);

// mlock
// int mlock(const void addr[.len], size_t len);
// asmlinkage long sys_mlock(unsigned long start, size_t len);

// munlock
// int munlock(const void addr[.len], size_t len);
// asmlinkage long sys_munlock(unsigned long start, size_t len);

// mlockall
// int mlockall(int flags);
// asmlinkage long sys_mlockall(int flags);

// munlockall
// int munlockall(void);
// asmlinkage long sys_munlockall(void);

// vhangup
// int vhangup(void);
// asmlinkage long sys_vhangup(void);

// pivot_root
// int syscall(SYS_pivot_root, const char *new_root, const char *put_old);
// asmlinkage long sys_pivot_root(const char __user *new_root, const char __user *put_old);

// prctl
// int prctl(int op, ... /* unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5 */ );
// asmlinkage long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

// arch_prctl
//
// asmlinkage long sys_arch_prctl(int option, unsigned long arg2)

// adjtimex
// int adjtimex(struct timex *buf);
// asmlinkage long sys_adjtimex(struct __kernel_timex __user *txc_p);

// setrlimit
// int setrlimit(int resource, const struct rlimit *rlim);
// asmlinkage long sys_setrlimit(unsigned int resource, struct rlimit __user *rlim);

// chroot
// int chroot(const char *path);
// asmlinkage long sys_chroot(const char __user *filename);

// sync
// void sync(void);
// asmlinkage long sys_sync(void);

// acct
// int acct(const char *_Nullable filename);
// asmlinkage long sys_acct(const char __user *name);

// settimeofday
// int settimeofday(const struct timeval *tv, const struct timezone *_Nullable tz);
// asmlinkage long sys_settimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);

// mount
// int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *_Nullable data);
// asmlinkage long sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);

// umount2
// int umount2(const char *target, int flags);
// asmlinkage long sys_umount(char __user *name, int flags);

// swapon
// int swapon(const char *path, int swapflags);
// asmlinkage long sys_swapon(const char __user *specialfile, int swap_flags);

// swapoff
// int swapoff(const char *path);
// asmlinkage long sys_swapoff(const char __user *specialfile);

// reboot
// int reboot(int op);
// asmlinkage long sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);

// sethostname
// int sethostname(const char *name, size_t len);
// asmlinkage long sys_sethostname(char __user *name, int len);

// setdomainname
// int setdomainname(const char *name, size_t len);
// asmlinkage long sys_setdomainname(char __user *name, int len);

// ioperm
// int ioperm(unsigned long from, unsigned long num, int turn_on);
// asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int on);

// init_module
// int syscall(SYS_init_module, void module_image[.len], unsigned long len, const char *param_values);
// asmlinkage long sys_init_module(void __user *umod, unsigned long len, const char __user *uargs);

// delete_module
// int syscall(SYS_delete_module, const char *name, unsigned int flags);
// asmlinkage long sys_delete_module(const char __user *name_user, unsigned int flags);

// quotactl
// int quotactl(int op, const char *_Nullable special, int id, caddr_t addr);
// asmlinkage long sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);

// gettid
// pid_t gettid(void);
// asmlinkage long sys_gettid(void);

// readahead
// ssize_t readahead(int fd, off_t offset, size_t count);
// asmlinkage long sys_readahead(int fd, loff_t offset, size_t count);

// setxattr
// int setxattr(const char *path, const char *name, const void value[.size], size_t size, int flags);
// asmlinkage long sys_setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);

// lsetxattr
// int lsetxattr(const char *path, const char *name, const void value[.size], size_t size, int flags);
// asmlinkage long sys_lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);

// fsetxattr
// int fsetxattr(int fd, const char *name, const void value[.size], size_t size, int flags);
// asmlinkage long sys_fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags);

// getxattr
// ssize_t getxattr(const char *path, const char *name, void value[.size], size_t size);
// asmlinkage long sys_getxattr(const char __user *path, const char __user *name, void __user *value, size_t size);

// lgetxattr
// ssize_t lgetxattr(const char *path, const char *name, void value[.size], size_t size);
// asmlinkage long sys_lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size);

// fgetxattr
// ssize_t fgetxattr(int fd, const char *name, void value[.size], size_t size);
// asmlinkage long sys_fgetxattr(int fd, const char __user *name, void __user *value, size_t size);

// listxattr
// ssize_t listxattr(const char *path, char *_Nullable list, size_t size);
// asmlinkage long sys_listxattr(const char __user *path, char __user *list, size_t size);

// llistxattr
// ssize_t llistxattr(const char *path, char *_Nullable list, size_t size);
// asmlinkage long sys_llistxattr(const char __user *path, char __user *list, size_t size);

// flistxattr
// ssize_t flistxattr(int fd, char *_Nullable list, size_t size);
// asmlinkage long sys_flistxattr(int fd, char __user *list, size_t size);

// removexattr
// int removexattr(const char *path, const char *name);
// asmlinkage long sys_removexattr(const char __user *path, const char __user *name);

// lremovexattr
// int lremovexattr(const char *path, const char *name);
// asmlinkage long sys_lremovexattr(const char __user *path, const char __user *name);

// fremovexattr
// int fremovexattr(int fd, const char *name);
// asmlinkage long sys_fremovexattr(int fd, const char __user *name);

// tkill
// [[deprecated]] int syscall(SYS_tkill, pid_t tid, int sig);
// asmlinkage long sys_tkill(pid_t pid, int sig);

// time
// time_t time(time_t *_Nullable tloc);
// asmlinkage long sys_time(__kernel_old_time_t __user *tloc);

// futex
// long syscall(SYS_futex, uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout,   /* or: uint32_t val2 */ uint32_t *uaddr2, uint32_t val3);
// asmlinkage long sys_futex(u32 __user *uaddr, int op, u32 val, const struct __kernel_timespec __user *utime, u32 __user *uaddr2, u32 val3);

// sched_setaffinity
// int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
// asmlinkage long sys_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);

// sched_getaffinity
// int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
// asmlinkage long sys_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);

// io_setup
// long io_setup(unsigned int nr_events, aio_context_t *ctx_idp);
// asmlinkage long sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx);

// io_destroy
// int syscall(SYS_io_destroy, aio_context_t ctx_id);
// asmlinkage long sys_io_destroy(aio_context_t ctx);

// io_getevents
// int syscall(SYS_io_getevents, aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout);
// asmlinkage long sys_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout);

// io_submit
// int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
// asmlinkage long sys_io_submit(aio_context_t, long, struct iocb __user * __user *);

// io_cancel
// int syscall(SYS_io_cancel, aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
// asmlinkage long sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result);

// epoll_create
// int epoll_create(int size);
// asmlinkage long sys_epoll_create(int size);

// remap_file_pages
// [[deprecated]] int remap_file_pages(void addr[.size], size_t size, int prot, size_t pgoff, int flags);
// asmlinkage long sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);

// getdents64
// ssize_t getdents64(int fd, void dirp[.count], size_t count);
// asmlinkage long sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);

// set_tid_address
// pid_t syscall(SYS_set_tid_address, int *tidptr);
// asmlinkage long sys_set_tid_address(int __user *tidptr);

// semtimedop
// int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *_Nullable timeout);
// asmlinkage long sys_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct __kernel_timespec __user *timeout);

// fadvise64
// int posix_fadvise(int fd, off_t offset, off_t size, int advice);
// asmlinkage long sys_fadvise64(int fd, loff_t offset, size_t len, int advice);

// timer_create
// int timer_create(clockid_t clockid, struct sigevent *_Nullable restrict sevp, timer_t *restrict timerid);
// asmlinkage long sys_timer_create(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id);

// timer_settime
// int timer_settime(timer_t timerid, int flags, const struct itimerspec *restrict new_value, struct itimerspec *_Nullable restrict old_value);
// asmlinkage long sys_timer_settime(timer_t timer_id, int flags, const struct __kernel_itimerspec __user *new_setting, struct __kernel_itimerspec __user *old_setting);

// timer_gettime
// int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
// asmlinkage long sys_timer_gettime(timer_t timer_id, struct __kernel_itimerspec __user *setting);

// timer_getoverrun
// int timer_getoverrun(timer_t timerid);
// asmlinkage long sys_timer_getoverrun(timer_t timer_id);

// timer_delete
// int timer_delete(timer_t timerid);
// asmlinkage long sys_timer_delete(timer_t timer_id);

// clock_settime
// int clock_settime(clockid_t clockid, const struct timespec *tp);
// asmlinkage long sys_clock_settime(clockid_t which_clock, const struct __kernel_timespec __user *tp);

// clock_gettime
// int clock_gettime(clockid_t clockid, struct timespec *tp);
// asmlinkage long sys_clock_gettime(clockid_t which_clock, struct __kernel_timespec __user *tp);

// clock_getres
// int clock_getres(clockid_t clockid, struct timespec *_Nullable res);
// asmlinkage long sys_clock_getres(clockid_t which_clock, struct __kernel_timespec __user *tp);

// clock_nanosleep
// int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *t, struct timespec *_Nullable remain);
// asmlinkage long sys_clock_nanosleep(clockid_t which_clock, int flags, const struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);

// exit_group
// [[noreturn]] void syscall(SYS_exit_group, int status);
// asmlinkage long sys_exit_group(int error_code);

// epoll_wait
// int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
// asmlinkage long sys_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout);

// epoll_ctl
// int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);
// asmlinkage long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event);

// tgkill
// int tgkill(pid_t tgid, pid_t tid, int sig);
// asmlinkage long sys_tgkill(pid_t tgid, pid_t pid, int sig);

// utimes
// int utimes(const char *filename, const struct timeval times[_Nullable 2]);
// asmlinkage long sys_utimes(char __user *filename, struct __kernel_old_timeval __user *utimes);

// mbind
// long mbind(void addr[.len], unsigned long len, int mode, const unsigned long nodemask[(.maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH], unsigned long maxnode, unsigned int flags);
// asmlinkage long sys_mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned flags);

// set_mempolicy
// long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
// asmlinkage long sys_set_mempolicy(int mode, const unsigned long __user *nmask, unsigned long maxnode);

// get_mempolicy
// long get_mempolicy(int *mode, unsigned long nodemask[(.maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH], unsigned long maxnode, void *addr, unsigned long flags);
// asmlinkage long sys_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);

// mq_open
// mqd_t mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr);
// asmlinkage long sys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr);

// mq_unlink
// int mq_unlink(const char *name);
// asmlinkage long sys_mq_unlink(const char __user *name);

// mq_timedsend
// int mq_timedsend(mqd_t mqdes, const char msg_ptr[.msg_len], size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);
// asmlinkage long sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user *abs_timeout);

// mq_timedreceive
// ssize_t mq_timedreceive(mqd_t mqdes, char *restrict msg_ptr[.msg_len], size_t msg_len, unsigned int *restrict msg_prio, const struct timespec *restrict abs_timeout);
// asmlinkage long sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct __kernel_timespec __user *abs_timeout);

// mq_notify
// int mq_notify(mqd_t mqdes, const struct sigevent *sevp);
// asmlinkage long sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification);

// mq_getsetattr
// int syscall(SYS_mq_getsetattr, mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr);
// asmlinkage long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);

// kexec_load
// long syscall(SYS_kexec_load, unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
// asmlinkage long sys_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags);

// waitid
// int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
// asmlinkage long sys_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru);

// add_key
// key_serial_t add_key(const char *type, const char *description, const void payload[.plen], size_t plen, key_serial_t keyring);
// asmlinkage long sys_add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid);

// request_key
// key_serial_t request_key(const char *type, const char *description, const char *_Nullable callout_info, key_serial_t dest_keyring);
// asmlinkage long sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid);

// keyctl
// long syscall(SYS_keyctl, int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
// asmlinkage long sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

// ioprio_set
// int syscall(SYS_ioprio_set, int which, int who, int ioprio);
// asmlinkage long sys_ioprio_set(int which, int who, int ioprio);

// ioprio_get
// int syscall(SYS_ioprio_set, int which, int who, int ioprio);
// asmlinkage long sys_ioprio_get(int which, int who);

// inotify_init
// int inotify_init(void);
// asmlinkage long sys_inotify_init(void);

// inotify_add_watch
// int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
// asmlinkage long sys_inotify_add_watch(int fd, const char __user *path, u32 mask);

// inotify_rm_watch
// int inotify_rm_watch(int fd, int wd);
// asmlinkage long sys_inotify_rm_watch(int fd, __s32 wd);

// migrate_pages
// long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);
// asmlinkage long sys_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to);

// openat
// int openat(int dirfd, const char *pathname, int flags, ... /* mode_t mode */ );
// asmlinkage long sys_openat(int dfd, const char __user *filename, int flags, umode_t mode);

// mkdirat
// int mkdirat(int dirfd, const char *pathname, mode_t mode);
// asmlinkage long sys_mkdirat(int dfd, const char __user * pathname, umode_t mode);

// mknodat
// int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
// asmlinkage long sys_mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev);

// fchownat
// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
// asmlinkage long sys_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);

// futimesat
// [[deprecated]] int futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
// asmlinkage long sys_futimesat(int dfd, const char __user *filename, struct __kernel_old_timeval __user *utimes);

// fstatat64
// int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);
// asmlinkage long sys_fstatat64(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag);

// unlinkat
// int unlinkat(int dirfd, const char *pathname, int flags);
// asmlinkage long sys_unlinkat(int dfd, const char __user * pathname, int flag);

// renameat
// int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
// asmlinkage long sys_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname);

// linkat
// int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
// asmlinkage long sys_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);

// symlinkat
// int symlinkat(const char *target, int newdirfd, const char *linkpath);
// asmlinkage long sys_symlinkat(const char __user * oldname, int newdfd, const char __user * newname);

// readlinkat
// ssize_t readlinkat(int dirfd, const char *restrict pathname, char *restrict buf, size_t bufsiz);
// asmlinkage long sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz);

// fchmodat
// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
// asmlinkage long sys_fchmodat(int dfd, const char __user *filename, umode_t mode);

// faccessat
// int faccessat(int dirfd, const char *pathname, int mode, int flags);
// asmlinkage long sys_faccessat(int dfd, const char __user *filename, int mode);

// pselect6
// int pselect(int nfds, fd_set *_Nullable restrict readfds, fd_set *_Nullable restrict writefds, fd_set *_Nullable restrict exceptfds, const struct timespec *_Nullable restrict timeout, const sigset_t *_Nullable restrict sigmask);
// asmlinkage long sys_pselect6(int, fd_set __user *, fd_set __user *, fd_set __user *, struct __kernel_timespec __user *, void __user *);

// ppoll
// int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *_Nullable tmo_p, const sigset_t *_Nullable sigmask);
// asmlinkage long sys_ppoll(struct pollfd __user *, unsigned int, struct __kernel_timespec __user *, const sigset_t __user *, size_t);

// unshare
// int unshare(int flags);
// asmlinkage long sys_unshare(unsigned long unshare_flags);

// set_robust_list
// long syscall(SYS_set_robust_list, struct robust_list_head *head, size_t len);
// asmlinkage long sys_set_robust_list(struct robust_list_head __user *head, size_t len);

// get_robust_list
// long syscall(SYS_get_robust_list, int pid, struct robust_list_head **head_ptr, size_t *len_ptr);
// asmlinkage long sys_get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr);

// splice
// ssize_t splice(int fd_in, off_t *_Nullable off_in, int fd_out, off_t *_Nullable off_out, size_t len, unsigned int flags);
// asmlinkage long sys_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);

// tee
// ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
// asmlinkage long sys_tee(int fdin, int fdout, size_t len, unsigned int flags);

// sync_file_range
// int sync_file_range(int fd, off_t offset, off_t nbytes, unsigned int flags);
// asmlinkage long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);

// vmsplice
// ssize_t vmsplice(int fd, const struct iovec *iov, size_t nr_segs, unsigned int flags);
// asmlinkage long sys_vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);

// move_pages
// long move_pages(int pid, unsigned long count, void *pages[.count], const int nodes[.count], int status[.count], int flags);
// asmlinkage long sys_move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags);

// utimensat
// int utimensat(int dirfd, const char *pathname, const struct timespec times[_Nullable 2], int flags);
// asmlinkage long sys_utimensat(int dfd, const char __user *filename, struct __kernel_timespec __user *utimes, int flags);

// epoll_pwait
// int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *_Nullable sigmask);
// asmlinkage long sys_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize);

// signalfd
// int signalfd(int fd, const sigset_t *mask, int flags);
// asmlinkage long sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask);

// timerfd_create
// int timerfd_create(int clockid, int flags);
// asmlinkage long sys_timerfd_create(int clockid, int flags);

// eventfd
// int eventfd(unsigned int initval, int flags);
// asmlinkage long sys_eventfd(unsigned int count);

// fallocate
// int fallocate(int fd, int mode, off_t offset, off_t len);
// asmlinkage long sys_fallocate(int fd, int mode, loff_t offset, loff_t len);

// timerfd_settime
// int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *_Nullable old_value);
// asmlinkage long sys_timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec __user *utmr, struct __kernel_itimerspec __user *otmr);

// timerfd_gettime
// int timerfd_gettime(int fd, struct itimerspec *curr_value);
// asmlinkage long sys_timerfd_gettime(int ufd, struct __kernel_itimerspec __user *otmr);

// accept4
// int accept4(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen, int flags);
// asmlinkage long sys_accept4(int, struct sockaddr __user *, int __user *, int);

// signalfd4
// int signalfd(int fd, const sigset_t *mask, int flags);
// asmlinkage long sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);

// eventfd2
// int eventfd(unsigned int initval, int flags);
// asmlinkage long sys_eventfd2(unsigned int count, int flags);

// epoll_create1
// int epoll_create1(int flags);
// asmlinkage long sys_epoll_create1(int flags);

// dup3
// int dup3(int oldfd, int newfd, int flags);
// asmlinkage long sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);

// pipe2
// int pipe2(int pipefd[2], int flags);
// asmlinkage long sys_pipe2(int __user *fildes, int flags);

// inotify_init1
// int inotify_init1(int flags);
// asmlinkage long sys_inotify_init1(int flags);

// preadv
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// asmlinkage long sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);

// pwritev
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// asmlinkage long sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);

// rt_tgsigqueueinfo
// int syscall(SYS_rt_tgsigqueueinfo, pid_t tgid, pid_t tid, int sig, siginfo_t *info);
// asmlinkage long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo);

// perf_event_open
// int syscall(SYS_perf_event_open, struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);
// asmlinkage long sys_perf_event_open( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);

// recvmmsg
// int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);
// asmlinkage long sys_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct __kernel_timespec __user *timeout);

// fanotify_init
// int fanotify_init(unsigned int flags, unsigned int event_f_flags);
// asmlinkage long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags);

// fanotify_mark
// int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *_Nullable pathname);
// asmlinkage long sys_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char  __user *pathname);

// prlimit64
// int prlimit(pid_t pid, int resource, const struct rlimit *_Nullable new_limit, struct rlimit *_Nullable old_limit);
// asmlinkage long sys_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim);

// name_to_handle_at
// int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);
// asmlinkage long sys_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, void __user *mnt_id, int flag);

// open_by_handle_at
// int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
// asmlinkage long sys_open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags);

// clock_adjtime
// int clock_adjtime(clockid_t clk_id, struct timex *buf);
// asmlinkage long sys_clock_adjtime(clockid_t which_clock, struct __kernel_timex __user *tx);

// syncfs
// int syncfs(int fd);
// asmlinkage long sys_syncfs(int fd);

// sendmmsg
// int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
// asmlinkage long sys_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);

// setns
// int setns(int fd, int nstype);
// asmlinkage long sys_setns(int fd, int nstype);

// getcpu
// int getcpu(unsigned int *_Nullable cpu, unsigned int *_Nullable node);
// asmlinkage long sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);

// process_vm_readv
// ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// asmlinkage long sys_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);

// process_vm_writev
// ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// asmlinkage long sys_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);

// kcmp
// int syscall(SYS_kcmp, pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
// asmlinkage long sys_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);

// finit_module
// int syscall(SYS_finit_module, int fd, const char *param_values, int flags);
// asmlinkage long sys_finit_module(int fd, const char __user *uargs, int flags);

// sched_setattr
// int syscall(SYS_sched_setattr, pid_t pid, struct sched_attr *attr, unsigned int flags);
// asmlinkage long sys_sched_setattr(pid_t pid, struct sched_attr __user *attr, unsigned int flags);

// sched_getattr
// int syscall(SYS_sched_getattr, pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags);
// asmlinkage long sys_sched_getattr(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags);

// renameat2
// int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
// asmlinkage long sys_renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);

// seccomp
// int syscall(SYS_seccomp, unsigned int operation, unsigned int flags, void *args);
// asmlinkage long sys_seccomp(unsigned int op, unsigned int flags, void __user *uargs);

// getrandom
// ssize_t getrandom(void buf[.buflen], size_t buflen, unsigned int flags);
// asmlinkage long sys_getrandom(char __user *buf, size_t count, unsigned int flags);

// memfd_create
// int memfd_create(const char *name, unsigned int flags);
// asmlinkage long sys_memfd_create(const char __user *uname_ptr, unsigned int flags);

// kexec_file_load
// long syscall(SYS_kexec_file_load, int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags);
// asmlinkage long sys_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags);

// bpf
// int bpf(int cmd, union bpf_attr *attr, unsigned int size);
// asmlinkage long sys_bpf(int cmd, union bpf_attr __user *attr, unsigned int size);

// execveat
// int execveat(int dirfd, const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[], int flags);
// asmlinkage long sys_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);

// userfaultfd
// int syscall(SYS_userfaultfd, int flags);
// asmlinkage long sys_userfaultfd(int flags);

// membarrier
// int syscall(SYS_membarrier, int cmd, unsigned int flags, int cpu_id);
// asmlinkage long sys_membarrier(int cmd, unsigned int flags, int cpu_id);

// mlock2
// int mlock2(const void addr[.len], size_t len, unsigned int flags);
// asmlinkage long sys_mlock2(unsigned long start, size_t len, int flags);

// copy_file_range
// ssize_t copy_file_range(int fd_in, off_t *_Nullable off_in, int fd_out, off_t *_Nullable off_out, size_t len, unsigned int flags);
// asmlinkage long sys_copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);

// preadv2
// ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
// asmlinkage long sys_preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);

// pwritev2
// ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
// asmlinkage long sys_pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);

// pkey_mprotect
// int pkey_mprotect(void addr[.len], size_t len, int prot, int pkey);
// asmlinkage long sys_pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey);

// pkey_alloc
// int pkey_alloc(unsigned int flags, unsigned int access_rights);
// asmlinkage long sys_pkey_alloc(unsigned long flags, unsigned long init_val);

// pkey_free
// int pkey_free(int pkey);
// asmlinkage long sys_pkey_free(int pkey);

// statx
// int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf);
// asmlinkage long sys_statx(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer);

// io_pgetevents
//
// asmlinkage long sys_io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout, const struct __aio_sigset __user *sig);

// rseq
//
// asmlinkage long sys_rseq(struct rseq __user *rseq, uint32_t rseq_len, int flags, uint32_t sig);

// pidfd_send_signal
// int syscall(SYS_pidfd_send_signal, int pidfd, int sig, siginfo_t *_Nullable info, unsigned int flags);

// io_uring_setup
// int io_uring_setup(u32 entries, struct io_uring_params *p);
// asmlinkage long sys_io_uring_setup(u32 entries, struct io_uring_params __user *p);

// io_uring_enter
// int io_uring_enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, sigset_t *sig);
// asmlinkage long sys_io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void __user *argp, size_t argsz);

// io_uring_register
// int io_uring_register(unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args);
// asmlinkage long sys_io_uring_register(unsigned int fd, unsigned int op, void __user *arg, unsigned int nr_args);

// open_tree
//
// asmlinkage long sys_open_tree(int dfd, const char __user *path, unsigned flags);

// move_mount
//
// asmlinkage long sys_move_mount(int from_dfd, const char __user *from_path, int to_dfd, const char __user *to_path, unsigned int ms_flags);

// fsopen
//
// asmlinkage long sys_fsopen(const char __user *fs_name, unsigned int flags);

// fsconfig
//
// asmlinkage long sys_fsconfig(int fs_fd, unsigned int cmd, const char __user *key, const void __user *value, int aux);

// fsmount
//
// asmlinkage long sys_fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags);

// fspick
//
// asmlinkage long sys_fspick(int dfd, const char __user *path, unsigned int flags);

// pidfd_open
// int syscall(SYS_pidfd_open, pid_t pid, unsigned int flags);
// asmlinkage long sys_pidfd_open(pid_t pid, unsigned int flags);

// clone3
// long syscall(SYS_clone3, struct clone_args *cl_args, size_t size);
// asmlinkage long sys_clone3(struct clone_args __user *uargs, size_t size);

// close_range
// int close_range(unsigned int first, unsigned int last, int flags);
// asmlinkage long sys_close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);

// openat2
// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size);
// asmlinkage long sys_openat2(int dfd, const char __user *filename, struct open_how __user *how, size_t size);

// pidfd_getfd
// int syscall(SYS_pidfd_getfd, int pidfd, int targetfd, unsigned int flags);
// asmlinkage long sys_pidfd_getfd(int pidfd, int fd, unsigned int flags);

// faccessat2
// int syscall(SYS_faccessat2, int dirfd, const char *pathname, int mode, int flags);
// asmlinkage long sys_faccessat2(int dfd, const char __user *filename, int mode, int flags);

// process_madvise
// ssize_t process_madvise(int pidfd, const struct iovec iovec[.n], size_t n, int advice, unsigned int flags);
// asmlinkage long sys_process_madvise(int pidfd, const struct iovec __user *vec, size_t vlen, int behavior, unsigned int flags);

// epoll_pwait2
// int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct timespec *_Nullable timeout, const sigset_t *_Nullable sigmask);
// asmlinkage long sys_epoll_pwait2(int epfd, struct epoll_event __user *events, int maxevents, const struct __kernel_timespec __user *timeout, const sigset_t __user *sigmask, size_t sigsetsize);

// mount_setattr
// int syscall(SYS_mount_setattr, int dirfd, const char *pathname, unsigned int flags, struct mount_attr *attr, size_t size);
// asmlinkage long sys_mount_setattr(int dfd, const char __user *path, unsigned int flags, struct mount_attr __user *uattr, size_t usize);

// quotactl_fd
// int quotactl(int op, const char *_Nullable special, int id, caddr_t addr);
// asmlinkage long sys_quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void __user *addr);

// landlock_create_ruleset
// int syscall(SYS_landlock_create_ruleset, const struct landlock_ruleset_attr *attr, size_t size , uint32_t flags);
// asmlinkage long sys_landlock_create_ruleset(const struct landlock_ruleset_attr __user *attr, size_t size, __u32 flags);

// landlock_add_rule
// int syscall(SYS_landlock_add_rule, int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags);
// asmlinkage long sys_landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void __user *rule_attr, __u32 flags);

// landlock_restrict_self
// int syscall(SYS_landlock_restrict_self, int ruleset_fd, uint32_t flags);
// asmlinkage long sys_landlock_restrict_self(int ruleset_fd, __u32 flags);

// memfd_secret
// int syscall(SYS_memfd_secret, unsigned int flags);
// asmlinkage long sys_memfd_secret(unsigned int flags);

// process_mrelease
//
// asmlinkage long sys_process_mrelease(int pidfd, unsigned int flags);

// futex_waitv
//
// asmlinkage long sys_futex_waitv(struct futex_waitv __user *waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec __user *timeout, clockid_t clockid);

// set_mempolicy_home_node
//
// asmlinkage long sys_set_mempolicy_home_node(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);

// cachestat
//
// asmlinkage long sys_cachestat(unsigned int fd, struct cachestat_range __user *cstat_range, struct cachestat __user *cstat, unsigned int flags);

// fchmodat2
//
// asmlinkage long sys_fchmodat2(int dfd, const char __user *filename, umode_t mode, unsigned int flags);

// map_shadow_stack
//
// asmlinkage long sys_map_shadow_stack(unsigned long addr, unsigned long size, unsigned int flags);

// futex_wake
//
// asmlinkage long sys_futex_wake(void __user *uaddr, unsigned long mask, int nr, unsigned int flags);

// futex_wait
//
// asmlinkage long sys_futex_wait(void __user *uaddr, unsigned long val, unsigned long mask, unsigned int flags, struct __kernel_timespec __user *timespec, clockid_t clockid);

// futex_requeue
//
// asmlinkage long sys_futex_requeue(struct futex_waitv __user *waiters, unsigned int flags, int nr_wake, int nr_requeue);
