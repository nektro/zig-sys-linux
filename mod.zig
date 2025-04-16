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
    const r = syscall3(.read, fd, buf.ptr, buf.len);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(c),
    };
}

// write
// ssize_t write(int fd, const void buf[.count], size_t count);
// asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);
pub fn write(fd: c_int, buf: []const u8) errno.Error!usize {
    const r = syscall3(.write, fd, buf.ptr, buf.len);
    return switch (_errno(r)) {
        .ok => @intCast(r),
        _ => |c| errno.errorFromInt(c),
    };
}

// open
// int open(const char *pathname, int flags, ... /* mode_t mode */ );

// close
// int close(int fd);

// stat
// int stat(const char *restrict pathname, struct stat *restrict statbuf);

// fstat
// int fstat(int fd, struct stat *statbuf);

// lstat
// int lstat(const char *restrict pathname, struct stat *restrict statbuf);

// poll
// int poll(struct pollfd *fds, nfds_t nfds, int timeout);

// lseek
// off_t lseek(int fd, off_t offset, int whence);

// mmap
// void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);

// mprotect
// int mprotect(void addr[.len], size_t len, int prot);

// munmap
// int munmap(void addr[.length], size_t length);

// brk
// int brk(void *addr);

// rt_sigaction

// rt_sigprocmask

// rt_sigreturn

// ioctl

// pread64
// ssize_t pread(int fd, void buf[.count], size_t count, off_t offset);

// pwrite64
// ssize_t pwrite(int fd, const void buf[.count], size_t count, off_t offset);

// readv
// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);

// writev
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

// access
// int access(const char *pathname, int mode);

// pipe
// int pipe(int pipefd[2]);

// select
// int select(int nfds, fd_set *_Nullable restrict readfds, fd_set *_Nullable restrict writefds, fd_set *_Nullable restrict exceptfds, struct timeval *_Nullable restrict timeout);

// sched_yield
// int sched_yield(void);

// mremap
// void *mremap(void old_address[.old_size], size_t old_size, size_t new_size, int flags, ... /* void *new_address */);

// msync
// int msync(void addr[.length], size_t length, int flags);

// mincore
// int mincore(void addr[.length], size_t length, unsigned char *vec);

// madvise
// int madvise(void addr[.length], size_t length, int advice);

// shmget
// int shmget(key_t key, size_t size, int shmflg);

// shmat
// void *shmat(int shmid, const void *_Nullable shmaddr, int shmflg);

// shmctl
// int shmctl(int shmid, int op, struct shmid_ds *buf);

// dup
// int dup(int oldfd);

// dup2
// int dup2(int oldfd, int newfd);

// pause
// int pause(void);

// nanosleep
// int nanosleep(const struct timespec *duration, struct timespec *_Nullable rem);

// getitimer
// int getitimer(int which, struct itimerval *curr_value);

// alarm
// unsigned int alarm(unsigned int seconds);

// setitimer
// int setitimer(int which, const struct itimerval *restrict new_value, struct itimerval *_Nullable restrict old_value);

// getpid
// pid_t getpid(void);

// sendfile
// ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset, size_t count);

// socket
// int socket(int domain, int type, int protocol);

// connect
// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// accept
// int accept(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen);

// sendto
// ssize_t sendto(int sockfd, const void buf[.len], size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

// recvfrom
// ssize_t recvfrom(int sockfd, void buf[restrict .len], size_t len, int flags, struct sockaddr *_Nullable restrict src_addr, socklen_t *_Nullable restrict addrlen);

// sendmsg
// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

// recvmsg
// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

// shutdown
// int shutdown(int sockfd, int how);

// bind
// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// listen
// int listen(int sockfd, int backlog);

// getsockname
// int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);

// getpeername
// int getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);

// socketpair
// int socketpair(int domain, int type, int protocol, int sv[2]);

// setsockopt
// int setsockopt(int sockfd, int level, int optname, const void optval[.optlen], socklen_t optlen);

// getsockopt
// int getsockopt(int sockfd, int level, int optname, void optval[restrict *.optlen], socklen_t *restrict optlen);

// clone
// int clone(int (*fn)(void *_Nullable), void *stack, int flags, void *_Nullable arg, ...  /* pid_t *_Nullable parent_tid, void *_Nullable tls, pid_t *_Nullable child_tid */ );

// fork
// pid_t fork(void);

// vfork
// pid_t vfork(void);

// execve
// int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[]);

// exit
// [[noreturn]] void _exit(int status);

// wait4
// pid_t wait4(pid_t pid, int *_Nullable wstatus, int options, struct rusage *_Nullable rusage);

// kill
// int kill(pid_t pid, int sig);

// uname
// int uname(struct utsname *buf);

// semget
// int semget(key_t key, int nsems, int semflg);

// semop
// int semop(int semid, struct sembuf *sops, size_t nsops);

// semctl
// int semctl(int semid, int semnum, int op, ...);

// shmdt
// int shmdt(const void *shmaddr);

// msgget
// int msgget(key_t key, int msgflg);

// msgsnd
// int msgsnd(int msqid, const void msgp[.msgsz], size_t msgsz, int msgflg);

// msgrcv
// ssize_t msgrcv(int msqid, void msgp[.msgsz], size_t msgsz, long msgtyp, int msgflg);

// msgctl
// int msgctl(int msqid, int op, struct msqid_ds *buf);

// fcntl
// int fcntl(int fd, int op, ... /* arg */ );

// flock
// int flock(int fd, int op);

// fsync
// int fsync(int fd);

// fdatasync
// int fdatasync(int fd);

// truncate
// int truncate(const char *path, off_t length);

// ftruncate
// int ftruncate(int fd, off_t length);

// getdents
// ssize_t getdents64(int fd, void dirp[.count], size_t count);

// getcwd
// char *getcwd(char buf[.size], size_t size);

// chdir
// int chdir(const char *path);

// fchdir
// int fchdir(int fd);

// rename
// int rename(const char *oldpath, const char *newpath);

// mkdir
// int mkdir(const char *pathname, mode_t mode);

// rmdir
// int rmdir(const char *pathname);

// creat
// int creat(const char *pathname, mode_t mode);

// link
// int link(const char *oldpath, const char *newpath);

// unlink
// int unlink(const char *pathname);

// symlink
// int symlink(const char *target, const char *linkpath);

// readlink
// ssize_t readlink(const char *restrict pathname, char *restrict buf, size_t bufsiz);

// chmod
// int chmod(const char *pathname, mode_t mode);

// fchmod
// int fchmod(int fd, mode_t mode);

// chown
// int chown(const char *pathname, uid_t owner, gid_t group);

// fchown
// int fchown(int fd, uid_t owner, gid_t group);

// lchown
// int lchown(const char *pathname, uid_t owner, gid_t group);

// umask
// mode_t umask(mode_t mask);

// gettimeofday
// int gettimeofday(struct timeval *restrict tv, struct timezone *_Nullable restrict tz);

// getrlimit
// int getrlimit(int resource, struct rlimit *rlim);

// getrusage
// int getrusage(int who, struct rusage *usage);

// sysinfo
// int sysinfo(struct sysinfo *info);

// times
// clock_t times(struct tms *buf);

// ptrace
// long ptrace(enum __ptrace_request op, pid_t pid, void *addr, void *data);

// getuid
// uid_t getuid(void);

// syslog
// int syscall(SYS_syslog, int type, char *bufp, int len);

// getgid
// gid_t getgid(void);

// setuid
// int setuid(uid_t uid);

// setgid
// int setgid(gid_t gid);

// geteuid
// uid_t geteuid(void);

// getegid
// gid_t getegid(void);

// setpgid
// int setpgid(pid_t pid, pid_t pgid);

// getppid
// pid_t getppid(void);

// getpgrp
// pid_t getpgrp(void);

// setsid
// pid_t setsid(void);

// setreuid
// int setreuid(uid_t ruid, uid_t euid);

// setregid
// int setregid(gid_t rgid, gid_t egid);

// getgroups
// int getgroups(int size, gid_t list[]);

// setgroups
// int setgroups(size_t size, const gid_t *_Nullable list);

// setresuid
// int setresuid(uid_t ruid, uid_t euid, uid_t suid);

// getresuid
// int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);

// setresgid
// int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

// getresgid
// int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);

// getpgid
// pid_t getpgid(pid_t pid);

// setfsuid
// [[deprecated]] int setfsuid(uid_t fsuid);

// setfsgid
// [[deprecated]] int setfsgid(gid_t fsgid);

// getsid
// pid_t getsid(pid_t pid);

// capget
// int syscall(SYS_capget, cap_user_header_t hdrp, cap_user_data_t datap);

// capset
// int syscall(SYS_capset, cap_user_header_t hdrp, const cap_user_data_t datap);

// rt_sigpending

// rt_sigtimedwait

// rt_sigqueueinfo

// rt_sigsuspend

// sigaltstack
// int sigaltstack(const stack_t *_Nullable restrict ss, stack_t *_Nullable restrict old_ss);

// utime
// int utime(const char *filename, const struct utimbuf *_Nullable times);

// mknod
// int mknod(const char *pathname, mode_t mode, dev_t dev);

// uselib
// [[deprecated]] int uselib(const char *library);

// personality
// int personality(unsigned long persona);

// ustat
// [[deprecated]] int ustat(dev_t dev, struct ustat *ubuf);

// statfs
// int statfs(const char *path, struct statfs *buf);

// fstatfs
// int fstatfs(int fd, struct statfs *buf);

// sysfs

// getpriority
// int getpriority(int which, id_t who);

// setpriority
// int setpriority(int which, id_t who, int prio);

// sched_setparam
// int sched_setparam(pid_t pid, const struct sched_param *param);

// sched_getparam
// int sched_getparam(pid_t pid, struct sched_param *param);

// sched_setscheduler
// int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);

// sched_getscheduler
// int sched_getscheduler(pid_t pid);

// sched_get_priority_max
// int sched_get_priority_max(int policy);

// sched_get_priority_min
// int sched_get_priority_min(int policy);

// sched_rr_get_interval
// int sched_rr_get_interval(pid_t pid, struct timespec *tp);

// mlock

// munlock

// mlockall

// munlockall

// vhangup

// modify_ldt

// pivot_root

// _sysctl

// prctl

// arch_prctl

// adjtimex

// setrlimit
// int setrlimit(int resource, const struct rlimit *rlim);

// chroot

// sync

// acct

// settimeofday
// int settimeofday(const struct timeval *tv, const struct timezone *_Nullable tz);

// mount

// umount2

// swapon

// swapoff

// reboot

// sethostname

// setdomainname

// iopl

// ioperm

// create_module

// init_module

// delete_module

// get_kernel_syms

// query_module

// quotactl

// nfsservctl

// getpmsg

// putpmsg

// afs_syscall

// tuxcall

// security

// gettid

// readahead

// setxattr

// lsetxattr

// fsetxattr

// getxattr

// lgetxattr

// fgetxattr

// listxattr

// llistxattr

// flistxattr

// removexattr

// lremovexattr

// fremovexattr

// tkill

// time

// futex

// sched_setaffinity

// sched_getaffinity

// set_thread_area

// io_setup

// io_destroy

// io_getevents

// io_submit

// io_cancel

// get_thread_area

// lookup_dcookie

// epoll_create

// epoll_ctl_old

// epoll_wait_old

// remap_file_pages

// getdents64

// set_tid_address

// restart_syscall

// semtimedop

// fadvise64

// timer_create

// timer_settime

// timer_gettime

// timer_getoverrun

// timer_delete

// clock_settime

// clock_gettime

// clock_getres

// clock_nanosleep

// exit_group

// epoll_wait

// epoll_ctl

// tgkill

// utimes
// int utimes(const char *filename, const struct timeval times[_Nullable 2]);

// vserver

// mbind

// set_mempolicy

// get_mempolicy

// mq_open

// mq_unlink

// mq_timedsend

// mq_timedreceive

// mq_notify

// mq_getsetattr

// kexec_load

// waitid

// add_key

// request_key

// keyctl

// ioprio_set

// ioprio_get

// inotify_init

// inotify_add_watch

// inotify_rm_watch

// migrate_pages

// openat
// int openat(int dirfd, const char *pathname, int flags, ... /* mode_t mode */ );

// mkdirat
// int mkdirat(int dirfd, const char *pathname, mode_t mode);

// mknodat
// int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);

// fchownat

// futimesat

// fstatat64
// int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);

// unlinkat
// int unlinkat(int dirfd, const char *pathname, int flags);

// renameat
// int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

// linkat
// int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);

// symlinkat
// int symlinkat(const char *target, int newdirfd, const char *linkpath);

// readlinkat
// ssize_t readlinkat(int dirfd, const char *restrict pathname, char *restrict buf, size_t bufsiz);

// fchmodat
// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);

// faccessat
// int faccessat(int dirfd, const char *pathname, int mode, int flags);

// pselect6
// int pselect(int nfds, fd_set *_Nullable restrict readfds, fd_set *_Nullable restrict writefds, fd_set *_Nullable restrict exceptfds, const struct timespec *_Nullable restrict timeout, const sigset_t *_Nullable restrict sigmask);

// ppoll
// int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *_Nullable tmo_p, const sigset_t *_Nullable sigmask);

// unshare
// int unshare(int flags);

// set_robust_list

// get_robust_list

// splice

// tee

// sync_file_range

// vmsplice

// move_pages

// utimensat

// epoll_pwait

// signalfd

// timerfd_create

// eventfd

// fallocate

// timerfd_settime

// timerfd_gettime

// accept4
// int accept4(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen, int flags);

// signalfd4

// eventfd2

// epoll_create1

// dup3
// int dup3(int oldfd, int newfd, int flags);

// pipe2
// int pipe2(int pipefd[2], int flags);

// inotify_init1

// preadv
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);

// pwritev
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);

// rt_tgsigqueueinfo

// perf_event_open

// recvmmsg

// fanotify_init

// fanotify_mark

// prlimit64
// int prlimit(pid_t pid, int resource, const struct rlimit *_Nullable new_limit, struct rlimit *_Nullable old_limit);

// name_to_handle_at

// open_by_handle_at

// clock_adjtime

// syncfs

// sendmmsg

// setns

// getcpu

// process_vm_readv

// process_vm_writev

// kcmp

// finit_module

// sched_setattr

// sched_getattr

// renameat2
// int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);

// seccomp

// getrandom

// memfd_create

// kexec_file_load

// bpf

// execveat

// userfaultfd

// membarrier

// mlock2

// copy_file_range

// preadv2
// ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);

// pwritev2
// ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);

// pkey_mprotect
// int pkey_mprotect(void addr[.len], size_t len, int prot, int pkey);

// pkey_alloc

// pkey_free

// statx

// io_pgetevents

// rseq

// pidfd_send_signal

// io_uring_setup

// io_uring_enter

// io_uring_register

// open_tree

// move_mount

// fsopen

// fsconfig

// fsmount

// fspick

// pidfd_open

// clone3

// close_range

// openat2
// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size);

// pidfd_getfd

// faccessat2

// process_madvise

// epoll_pwait2

// mount_setattr

// quotactl_fd

// landlock_create_ruleset

// landlock_add_rule

// landlock_restrict_self

// memfd_secret

// process_mrelease

// futex_waitv

// set_mempolicy_home_node

// cachestat

// fchmodat2

// map_shadow_stack

// futex_wake

// futex_wait

// futex_requeue
