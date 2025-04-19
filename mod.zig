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
// int sigprocmask(int how, const sigset_t *_Nullable restrict set, sigset_t *_Nullable restrict oldset);

// rt_sigreturn
// int sigreturn(...);

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
// int sigpending(sigset_t *set);

// rt_sigtimedwait
// int sigtimedwait(const sigset_t *restrict set, siginfo_t *_Nullable restrict info, const struct timespec *restrict timeout);

// rt_sigqueueinfo
// int syscall(SYS_rt_sigqueueinfo, pid_t tgid, int sig, siginfo_t *info);

// rt_sigsuspend
// int sigsuspend(const sigset_t *mask);

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
// int mlock(const void addr[.len], size_t len);

// munlock
// int munlock(const void addr[.len], size_t len);

// mlockall
// int mlockall(int flags);

// munlockall
// int munlockall(void);

// vhangup
// int vhangup(void);

// modify_ldt
// int syscall(SYS_modify_ldt, int func, void ptr[.bytecount], unsigned long bytecount);

// pivot_root
// int syscall(SYS_pivot_root, const char *new_root, const char *put_old);

// _sysctl
// [[deprecated]] int _sysctl(struct __sysctl_args *args);

// prctl
// int prctl(int op, ... /* unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5 */ );

// arch_prctl

// adjtimex
// int adjtimex(struct timex *buf);

// setrlimit
// int setrlimit(int resource, const struct rlimit *rlim);

// chroot
// int chroot(const char *path);

// sync
// void sync(void);

// acct
// int acct(const char *_Nullable filename);

// settimeofday
// int settimeofday(const struct timeval *tv, const struct timezone *_Nullable tz);

// mount
// int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *_Nullable data);

// umount2
// int umount2(const char *target, int flags);

// swapon
// int swapon(const char *path, int swapflags);

// swapoff
// int swapoff(const char *path);

// reboot
// int reboot(int op);

// sethostname
// int sethostname(const char *name, size_t len);

// setdomainname
// int setdomainname(const char *name, size_t len);

// iopl
// [[deprecated]] int iopl(int level);

// ioperm
// int ioperm(unsigned long from, unsigned long num, int turn_on);

// create_module
// [[deprecated]] caddr_t create_module(const char *name, size_t size);

// init_module
// int syscall(SYS_init_module, void module_image[.len], unsigned long len, const char *param_values);

// delete_module
// int syscall(SYS_delete_module, const char *name, unsigned int flags);

// get_kernel_syms
// [[deprecated]] int get_kernel_syms(struct kernel_sym *table);

// query_module
// [[deprecated]] int query_module(const char *name, int which, void buf[.bufsize], size_t bufsize, size_t *ret);

// quotactl
// int quotactl(int op, const char *_Nullable special, int id, caddr_t addr);

// nfsservctl
// long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp);

// getpmsg

// putpmsg

// afs_syscall

// tuxcall

// security

// gettid
// pid_t gettid(void);

// readahead
// ssize_t readahead(int fd, off_t offset, size_t count);

// setxattr
// int setxattr(const char *path, const char *name, const void value[.size], size_t size, int flags);

// lsetxattr
// int lsetxattr(const char *path, const char *name, const void value[.size], size_t size, int flags);

// fsetxattr
// int fsetxattr(int fd, const char *name, const void value[.size], size_t size, int flags);

// getxattr
// ssize_t getxattr(const char *path, const char *name, void value[.size], size_t size);

// lgetxattr
// ssize_t lgetxattr(const char *path, const char *name, void value[.size], size_t size);

// fgetxattr
// ssize_t fgetxattr(int fd, const char *name, void value[.size], size_t size);

// listxattr
// ssize_t listxattr(const char *path, char *_Nullable list, size_t size);

// llistxattr
// ssize_t llistxattr(const char *path, char *_Nullable list, size_t size);

// flistxattr
// ssize_t flistxattr(int fd, char *_Nullable list, size_t size);

// removexattr
// int removexattr(const char *path, const char *name);

// lremovexattr
// int lremovexattr(const char *path, const char *name);

// fremovexattr
// int fremovexattr(int fd, const char *name);

// tkill
// [[deprecated]] int syscall(SYS_tkill, pid_t tid, int sig);

// time
// time_t time(time_t *_Nullable tloc);

// futex
// long syscall(SYS_futex, uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout,   /* or: uint32_t val2 */ uint32_t *uaddr2, uint32_t val3);

// sched_setaffinity
// int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);

// sched_getaffinity
// int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);

// set_thread_area

// io_setup
// long io_setup(unsigned int nr_events, aio_context_t *ctx_idp);

// io_destroy
// int syscall(SYS_io_destroy, aio_context_t ctx_id);

// io_getevents
// int syscall(SYS_io_getevents, aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout);

// io_submit
// int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);

// io_cancel
// int syscall(SYS_io_cancel, aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);

// get_thread_area

// lookup_dcookie
// int syscall(SYS_lookup_dcookie, uint64_t cookie, char *buffer, size_t len);

// epoll_create
// int epoll_create(int size);

// epoll_ctl_old
// int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);

// epoll_wait_old
// int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

// remap_file_pages
// [[deprecated]] int remap_file_pages(void addr[.size], size_t size, int prot, size_t pgoff, int flags);

// getdents64
// ssize_t getdents64(int fd, void dirp[.count], size_t count);

// set_tid_address
// pid_t syscall(SYS_set_tid_address, int *tidptr);

// restart_syscall

// semtimedop
// int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *_Nullable timeout);

// fadvise64

// timer_create
// int timer_create(clockid_t clockid, struct sigevent *_Nullable restrict sevp, timer_t *restrict timerid);

// timer_settime
// int timer_settime(timer_t timerid, int flags, const struct itimerspec *restrict new_value, struct itimerspec *_Nullable restrict old_value);

// timer_gettime
// int timer_gettime(timer_t timerid, struct itimerspec *curr_value);

// timer_getoverrun
// int timer_getoverrun(timer_t timerid);

// timer_delete
// int timer_delete(timer_t timerid);

// clock_settime
// int clock_settime(clockid_t clockid, const struct timespec *tp);

// clock_gettime
// int clock_gettime(clockid_t clockid, struct timespec *tp);

// clock_getres
// int clock_getres(clockid_t clockid, struct timespec *_Nullable res);

// clock_nanosleep
// int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *t, struct timespec *_Nullable remain);

// exit_group
// [[noreturn]] void syscall(SYS_exit_group, int status);

// epoll_wait
// int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

// epoll_ctl
// int epoll_ctl(int epfd, int op, int fd, struct epoll_event *_Nullable event);

// tgkill
// int tgkill(pid_t tgid, pid_t tid, int sig);

// utimes
// int utimes(const char *filename, const struct timeval times[_Nullable 2]);

// vserver

// mbind
// long mbind(void addr[.len], unsigned long len, int mode, const unsigned long nodemask[(.maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH], unsigned long maxnode, unsigned int flags);

// set_mempolicy
// long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);

// get_mempolicy
// long get_mempolicy(int *mode, unsigned long nodemask[(.maxnode + ULONG_WIDTH - 1) / ULONG_WIDTH], unsigned long maxnode, void *addr, unsigned long flags);

// mq_open
// mqd_t mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr);

// mq_unlink
// int mq_unlink(const char *name);

// mq_timedsend
// int mq_timedsend(mqd_t mqdes, const char msg_ptr[.msg_len], size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);

// mq_timedreceive
// ssize_t mq_timedreceive(mqd_t mqdes, char *restrict msg_ptr[.msg_len], size_t msg_len, unsigned int *restrict msg_prio, const struct timespec *restrict abs_timeout);

// mq_notify
// int mq_notify(mqd_t mqdes, const struct sigevent *sevp);

// mq_getsetattr
// int syscall(SYS_mq_getsetattr, mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr);

// kexec_load
// long syscall(SYS_kexec_load, unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);

// waitid
// int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);

// add_key
// key_serial_t add_key(const char *type, const char *description, const void payload[.plen], size_t plen, key_serial_t keyring);

// request_key
// key_serial_t request_key(const char *type, const char *description, const char *_Nullable callout_info, key_serial_t dest_keyring);

// keyctl
// long syscall(SYS_keyctl, int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

// ioprio_set
// int syscall(SYS_ioprio_set, int which, int who, int ioprio);

// ioprio_get
// int syscall(SYS_ioprio_set, int which, int who, int ioprio);

// inotify_init
// int inotify_init(void);

// inotify_add_watch
// int inotify_add_watch(int fd, const char *pathname, uint32_t mask);

// inotify_rm_watch
// int inotify_rm_watch(int fd, int wd);

// migrate_pages
// long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);

// openat
// int openat(int dirfd, const char *pathname, int flags, ... /* mode_t mode */ );

// mkdirat
// int mkdirat(int dirfd, const char *pathname, mode_t mode);

// mknodat
// int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);

// fchownat
// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);

// futimesat
// [[deprecated]] int futimesat(int dirfd, const char *pathname, const struct timeval times[2]);

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
// long syscall(SYS_set_robust_list, struct robust_list_head *head, size_t len);

// get_robust_list
// long syscall(SYS_get_robust_list, int pid, struct robust_list_head **head_ptr, size_t *len_ptr);

// splice
// ssize_t splice(int fd_in, off_t *_Nullable off_in, int fd_out, off_t *_Nullable off_out, size_t len, unsigned int flags);

// tee
// ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);

// sync_file_range
// int sync_file_range(int fd, off_t offset, off_t nbytes, unsigned int flags);

// vmsplice
// ssize_t vmsplice(int fd, const struct iovec *iov, size_t nr_segs, unsigned int flags);

// move_pages
// long move_pages(int pid, unsigned long count, void *pages[.count], const int nodes[.count], int status[.count], int flags);

// utimensat
// int utimensat(int dirfd, const char *pathname, const struct timespec times[_Nullable 2], int flags);

// epoll_pwait
// int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *_Nullable sigmask);

// signalfd
// int signalfd(int fd, const sigset_t *mask, int flags);

// timerfd_create
// int timerfd_create(int clockid, int flags);

// eventfd
// int eventfd(unsigned int initval, int flags);

// fallocate
// int fallocate(int fd, int mode, off_t offset, off_t len);

// timerfd_settime
// int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *_Nullable old_value);

// timerfd_gettime
// int timerfd_gettime(int fd, struct itimerspec *curr_value);

// accept4
// int accept4(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen, int flags);

// signalfd4
// int signalfd(int fd, const sigset_t *mask, int flags);

// eventfd2
// int eventfd(unsigned int initval, int flags);

// epoll_create1
// int epoll_create1(int flags);

// dup3
// int dup3(int oldfd, int newfd, int flags);

// pipe2
// int pipe2(int pipefd[2], int flags);

// inotify_init1
// int inotify_init1(int flags);

// preadv
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);

// pwritev
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);

// rt_tgsigqueueinfo
// int syscall(SYS_rt_tgsigqueueinfo, pid_t tgid, pid_t tid, int sig, siginfo_t *info);

// perf_event_open
// int syscall(SYS_perf_event_open, struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);

// recvmmsg
// int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);

// fanotify_init
// int fanotify_init(unsigned int flags, unsigned int event_f_flags);

// fanotify_mark
// int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *_Nullable pathname);

// prlimit64
// int prlimit(pid_t pid, int resource, const struct rlimit *_Nullable new_limit, struct rlimit *_Nullable old_limit);

// name_to_handle_at
// int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);

// open_by_handle_at
// int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);

// clock_adjtime
// int clock_adjtime(clockid_t clk_id, struct timex *buf);

// syncfs
// int syncfs(int fd);

// sendmmsg
// int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);

// setns
// int setns(int fd, int nstype);

// getcpu
// int getcpu(unsigned int *_Nullable cpu, unsigned int *_Nullable node);

// process_vm_readv
// ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);

// process_vm_writev
// ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);

// kcmp
// int syscall(SYS_kcmp, pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);

// finit_module
// int syscall(SYS_finit_module, int fd, const char *param_values, int flags);

// sched_setattr
// int syscall(SYS_sched_setattr, pid_t pid, struct sched_attr *attr, unsigned int flags);

// sched_getattr
// int syscall(SYS_sched_getattr, pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags);

// renameat2
// int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);

// seccomp
// int syscall(SYS_seccomp, unsigned int operation, unsigned int flags, void *args);

// getrandom
// ssize_t getrandom(void buf[.buflen], size_t buflen, unsigned int flags);

// memfd_create
// int memfd_create(const char *name, unsigned int flags);

// kexec_file_load
// long syscall(SYS_kexec_file_load, int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags);

// bpf
// int bpf(int cmd, union bpf_attr *attr, unsigned int size);

// execveat
// int execveat(int dirfd, const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[], int flags);

// userfaultfd
// int syscall(SYS_userfaultfd, int flags);

// membarrier
// int syscall(SYS_membarrier, int cmd, unsigned int flags, int cpu_id);

// mlock2
// int mlock2(const void addr[.len], size_t len, unsigned int flags);

// copy_file_range
// ssize_t copy_file_range(int fd_in, off_t *_Nullable off_in, int fd_out, off_t *_Nullable off_out, size_t len, unsigned int flags);

// preadv2
// ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);

// pwritev2
// ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);

// pkey_mprotect
// int pkey_mprotect(void addr[.len], size_t len, int prot, int pkey);

// pkey_alloc
// int pkey_alloc(unsigned int flags, unsigned int access_rights);

// pkey_free
// int pkey_free(int pkey);

// statx
// int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf);

// io_pgetevents

// rseq

// pidfd_send_signal
// int syscall(SYS_pidfd_send_signal, int pidfd, int sig, siginfo_t *_Nullable info, unsigned int flags);

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
// int syscall(SYS_pidfd_open, pid_t pid, unsigned int flags);

// clone3
// long syscall(SYS_clone3, struct clone_args *cl_args, size_t size);

// close_range
// int close_range(unsigned int first, unsigned int last, int flags);

// openat2
// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size);

// pidfd_getfd
// int syscall(SYS_pidfd_getfd, int pidfd, int targetfd, unsigned int flags);

// faccessat2
// int syscall(SYS_faccessat2, int dirfd, const char *pathname, int mode, int flags);

// process_madvise
// ssize_t process_madvise(int pidfd, const struct iovec iovec[.n], size_t n, int advice, unsigned int flags);

// epoll_pwait2
// int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct timespec *_Nullable timeout, const sigset_t *_Nullable sigmask);

// mount_setattr
// int syscall(SYS_mount_setattr, int dirfd, const char *pathname, unsigned int flags, struct mount_attr *attr, size_t size);

// quotactl_fd

// landlock_create_ruleset
// int syscall(SYS_landlock_create_ruleset, const struct landlock_ruleset_attr *attr, size_t size , uint32_t flags);

// landlock_add_rule
// int syscall(SYS_landlock_add_rule, int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags);

// landlock_restrict_self
// int syscall(SYS_landlock_restrict_self, int ruleset_fd, uint32_t flags);

// memfd_secret
// int syscall(SYS_memfd_secret, unsigned int flags);

// process_mrelease

// futex_waitv

// set_mempolicy_home_node

// cachestat

// fchmodat2

// map_shadow_stack

// futex_wake

// futex_wait

// futex_requeue
