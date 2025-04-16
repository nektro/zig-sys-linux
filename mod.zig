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
// int creat(const char *pathname, mode_t mode);

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

// mremap

// msync

// mincore

// madvise

// shmget

// shmat

// shmctl

// dup

// dup2

// pause

// nanosleep

// getitimer

// alarm

// setitimer

// getpid

// sendfile

// socket

// connect

// accept

// sendto

// recvfrom

// sendmsg

// recvmsg

// shutdown

// bind

// listen

// getsockname

// getpeername

// socketpair

// setsockopt

// getsockopt

// clone

// fork

// vfork

// execve

// exit

// wait4

// kill

// uname

// semget

// semop

// semctl

// shmdt

// msgget

// msgsnd

// msgrcv

// msgctl

// fcntl

// flock

// fsync

// fdatasync

// truncate

// ftruncate

// getdents

// getcwd

// chdir

// fchdir

// rename

// mkdir

// rmdir

// creat

// link

// unlink

// symlink

// readlink

// chmod

// fchmod

// chown

// fchown

// lchown

// umask

// gettimeofday

// getrlimit

// getrusage

// sysinfo

// times

// ptrace

// getuid

// syslog

// getgid

// setuid

// setgid

// geteuid

// getegid

// setpgid

// getppid

// getpgrp

// setsid

// setreuid

// setregid

// getgroups

// setgroups

// setresuid

// getresuid

// setresgid

// getresgid

// getpgid

// setfsuid

// setfsgid

// getsid

// capget

// capset

// rt_sigpending

// rt_sigtimedwait

// rt_sigqueueinfo

// rt_sigsuspend

// sigaltstack

// utime

// mknod

// uselib

// personality

// ustat

// statfs

// fstatfs

// sysfs

// getpriority

// setpriority

// sched_setparam

// sched_getparam

// sched_setscheduler

// sched_getscheduler

// sched_get_priority_max

// sched_get_priority_min

// sched_rr_get_interval

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

// chroot

// sync

// acct

// settimeofday

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

// mknodat

// fchownat

// futimesat

// fstatat64
// int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);

// unlinkat

// renameat

// linkat

// symlinkat

// readlinkat

// fchmodat

// faccessat
// int faccessat(int dirfd, const char *pathname, int mode, int flags);

// pselect6
// int pselect(int nfds, fd_set *_Nullable restrict readfds, fd_set *_Nullable restrict writefds, fd_set *_Nullable restrict exceptfds, const struct timespec *_Nullable restrict timeout, const sigset_t *_Nullable restrict sigmask);

// ppoll
// int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *_Nullable tmo_p, const sigset_t *_Nullable sigmask);

// unshare

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

// signalfd4

// eventfd2

// epoll_create1

// dup3

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
