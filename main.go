package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"syscall"

	"github.com/genuinetools/amicontained/version"
	"github.com/genuinetools/pkg/cli"
	"github.com/jessfraz/bpfd/proc"
	"github.com/sirupsen/logrus"
)

var (
	debug       bool
	seccomplist bool
)

func main() {
	// Create a new cli program.
	p := cli.NewProgram()
	p.Name = "amicontained"
	p.Description = "A container introspection tool"

	// Set the GitCommit and Version.
	p.GitCommit = version.GITCOMMIT
	p.Version = version.VERSION

	// Setup the global flags.
	p.FlagSet = flag.NewFlagSet("ship", flag.ExitOnError)
	p.FlagSet.BoolVar(&debug, "d", false, "enable debug logging")

	// Set the before function.
	p.Before = func(ctx context.Context) error {
		// Set the log level.
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		return nil
	}

	// Set the main program action.
	p.Action = func(ctx context.Context, args []string) error {
		// Container Runtime
		runtime := proc.GetContainerRuntime(0, 0)
		fmt.Printf("Container Runtime: %s\n", runtime)

		// Namespaces
		namespaces := []string{"pid"}
		fmt.Println("Has Namespaces:")
		for _, namespace := range namespaces {
			ns, err := proc.HasNamespace(namespace)
			if err != nil {
				fmt.Printf("\t%s: error -> %v\n", namespace, err)
				continue
			}
			fmt.Printf("\t%s: %t\n", namespace, ns)
		}

		// User Namespaces
		userNS, userMappings := proc.GetUserNamespaceInfo(0)
		fmt.Printf("\tuser: %t\n", userNS)
		if len(userMappings) > 0 {
			fmt.Println("User Namespace Mappings:")
			for _, userMapping := range userMappings {
				fmt.Printf("\tContainer -> %d\tHost -> %d\tRange -> %d\n", userMapping.ContainerID, userMapping.HostID, userMapping.Range)
			}
		}

		// AppArmor Profile
		aaprof := proc.GetAppArmorProfile(0)
		fmt.Printf("AppArmor Profile: %s\n", aaprof)

		// Capabilities
		caps, err := proc.GetCapabilities(0)
		if err != nil {
			logrus.Warnf("getting capabilities failed: %v", err)
		}
		if len(caps) > 0 {
			fmt.Println("Capabilities:")
			for k, v := range caps {
				if len(v) > 0 {
					fmt.Printf("\t%s -> %s\n", k, strings.Join(v, " "))
				}
			}
		}

		// Seccomp
		seccompMode := proc.GetSeccompEnforcingMode(0)
		fmt.Printf("Seccomp: %s\n", seccompMode)

		seccompIter()

		return nil
	}

	// Run our program.
	p.Run()
}

func seccompIter() {
	allowed := []string{}
	blocked := []string{}

	//fmt.Println("Checking available syscalls...")

	for id := 0; id < 314; id++ {
		// these cause a hang, so just skip
		// rt_sigreturn, select, pause, pselect6, ppoll
		if id == syscall.SYS_RT_SIGRETURN || id == syscall.SYS_SELECT || id == syscall.SYS_PAUSE || id == syscall.SYS_PSELECT6 || id == syscall.SYS_PPOLL {
			continue
		}
		// exit_group and exit -- causes us to exit.. doh!
		if id == syscall.SYS_EXIT || id == syscall.SYS_EXIT_GROUP {
			continue
		}

		// things currently break horribly if  CLONE, FORK or VFORK are called and the call succeeds
		// guess it should be straight forward to kill the forks
		if id == syscall.SYS_CLONE || id == syscall.SYS_FORK || id == syscall.SYS_VFORK {
			continue
		}

		_, _, err := syscall.Syscall(uintptr(id), 0, 0, 0)

		// check both EPERM and EACCES - LXC returns EACCES and Docker EPERM
		if err == syscall.EPERM || err == syscall.EACCES {
			blocked = append(blocked, syscallName(id))
		} else {
			allowed = append(allowed, syscallName(id))
		}

	}

	if debug && len(allowed) > 0 {
		fmt.Printf("Allowed Syscalls (%d):\n", len(allowed))
		fmt.Printf("\t%s\n", strings.Join(allowed, " "))
	}

	if len(blocked) > 0 {
		fmt.Printf("Blocked Syscalls (%d):\n", len(blocked))
		fmt.Printf("\t%s\n", strings.Join(blocked, " "))
	}
}

func syscallName(e int) string {
	switch e {
	case syscall.SYS_READ:
		return "READ"
	case syscall.SYS_WRITE:
		return "WRITE"
	case syscall.SYS_OPEN:
		return "OPEN"
	case syscall.SYS_CLOSE:
		return "CLOSE"
	case syscall.SYS_STAT:
		return "STAT"
	case syscall.SYS_FSTAT:
		return "FSTAT"
	case syscall.SYS_LSTAT:
		return "LSTAT"
	case syscall.SYS_POLL:
		return "POLL"
	case syscall.SYS_LSEEK:
		return "LSEEK"
	case syscall.SYS_MMAP:
		return "MMAP"
	case syscall.SYS_MPROTECT:
		return "MPROTECT"
	case syscall.SYS_MUNMAP:
		return "MUNMAP"
	case syscall.SYS_BRK:
		return "BRK"
	case syscall.SYS_RT_SIGACTION:
		return "RT_SIGACTION"
	case syscall.SYS_RT_SIGPROCMASK:
		return "RT_SIGPROCMASK"
	case syscall.SYS_RT_SIGRETURN:
		return "RT_SIGRETURN"
	case syscall.SYS_IOCTL:
		return "IOCTL"
	case syscall.SYS_PREAD64:
		return "PREAD64"
	case syscall.SYS_PWRITE64:
		return "PWRITE64"
	case syscall.SYS_READV:
		return "READV"
	case syscall.SYS_WRITEV:
		return "WRITEV"
	case syscall.SYS_ACCESS:
		return "ACCESS"
	case syscall.SYS_PIPE:
		return "PIPE"
	case syscall.SYS_SELECT:
		return "SELECT"
	case syscall.SYS_SCHED_YIELD:
		return "SCHED_YIELD"
	case syscall.SYS_MREMAP:
		return "MREMAP"
	case syscall.SYS_MSYNC:
		return "MSYNC"
	case syscall.SYS_MINCORE:
		return "MINCORE"
	case syscall.SYS_MADVISE:
		return "MADVISE"
	case syscall.SYS_SHMGET:
		return "SHMGET"
	case syscall.SYS_SHMAT:
		return "SHMAT"
	case syscall.SYS_SHMCTL:
		return "SHMCTL"
	case syscall.SYS_DUP:
		return "DUP"
	case syscall.SYS_DUP2:
		return "DUP2"
	case syscall.SYS_PAUSE:
		return "PAUSE"
	case syscall.SYS_NANOSLEEP:
		return "NANOSLEEP"
	case syscall.SYS_GETITIMER:
		return "GETITIMER"
	case syscall.SYS_ALARM:
		return "ALARM"
	case syscall.SYS_SETITIMER:
		return "SETITIMER"
	case syscall.SYS_GETPID:
		return "GETPID"
	case syscall.SYS_SENDFILE:
		return "SENDFILE"
	case syscall.SYS_SOCKET:
		return "SOCKET"
	case syscall.SYS_CONNECT:
		return "CONNECT"
	case syscall.SYS_ACCEPT:
		return "ACCEPT"
	case syscall.SYS_SENDTO:
		return "SENDTO"
	case syscall.SYS_RECVFROM:
		return "RECVFROM"
	case syscall.SYS_SENDMSG:
		return "SENDMSG"
	case syscall.SYS_RECVMSG:
		return "RECVMSG"
	case syscall.SYS_SHUTDOWN:
		return "SHUTDOWN"
	case syscall.SYS_BIND:
		return "BIND"
	case syscall.SYS_LISTEN:
		return "LISTEN"
	case syscall.SYS_GETSOCKNAME:
		return "GETSOCKNAME"
	case syscall.SYS_GETPEERNAME:
		return "GETPEERNAME"
	case syscall.SYS_SOCKETPAIR:
		return "SOCKETPAIR"
	case syscall.SYS_SETSOCKOPT:
		return "SETSOCKOPT"
	case syscall.SYS_GETSOCKOPT:
		return "GETSOCKOPT"
	case syscall.SYS_CLONE:
		return "CLONE"
	case syscall.SYS_FORK:
		return "FORK"
	case syscall.SYS_VFORK:
		return "VFORK"
	case syscall.SYS_EXECVE:
		return "EXECVE"
	case syscall.SYS_EXIT:
		return "EXIT"
	case syscall.SYS_WAIT4:
		return "WAIT4"
	case syscall.SYS_KILL:
		return "KILL"
	case syscall.SYS_UNAME:
		return "UNAME"
	case syscall.SYS_SEMGET:
		return "SEMGET"
	case syscall.SYS_SEMOP:
		return "SEMOP"
	case syscall.SYS_SEMCTL:
		return "SEMCTL"
	case syscall.SYS_SHMDT:
		return "SHMDT"
	case syscall.SYS_MSGGET:
		return "MSGGET"
	case syscall.SYS_MSGSND:
		return "MSGSND"
	case syscall.SYS_MSGRCV:
		return "MSGRCV"
	case syscall.SYS_MSGCTL:
		return "MSGCTL"
	case syscall.SYS_FCNTL:
		return "FCNTL"
	case syscall.SYS_FLOCK:
		return "FLOCK"
	case syscall.SYS_FSYNC:
		return "FSYNC"
	case syscall.SYS_FDATASYNC:
		return "FDATASYNC"
	case syscall.SYS_TRUNCATE:
		return "TRUNCATE"
	case syscall.SYS_FTRUNCATE:
		return "FTRUNCATE"
	case syscall.SYS_GETDENTS:
		return "GETDENTS"
	case syscall.SYS_GETCWD:
		return "GETCWD"
	case syscall.SYS_CHDIR:
		return "CHDIR"
	case syscall.SYS_FCHDIR:
		return "FCHDIR"
	case syscall.SYS_RENAME:
		return "RENAME"
	case syscall.SYS_MKDIR:
		return "MKDIR"
	case syscall.SYS_RMDIR:
		return "RMDIR"
	case syscall.SYS_CREAT:
		return "CREAT"
	case syscall.SYS_LINK:
		return "LINK"
	case syscall.SYS_UNLINK:
		return "UNLINK"
	case syscall.SYS_SYMLINK:
		return "SYMLINK"
	case syscall.SYS_READLINK:
		return "READLINK"
	case syscall.SYS_CHMOD:
		return "CHMOD"
	case syscall.SYS_FCHMOD:
		return "FCHMOD"
	case syscall.SYS_CHOWN:
		return "CHOWN"
	case syscall.SYS_FCHOWN:
		return "FCHOWN"
	case syscall.SYS_LCHOWN:
		return "LCHOWN"
	case syscall.SYS_UMASK:
		return "UMASK"
	case syscall.SYS_GETTIMEOFDAY:
		return "GETTIMEOFDAY"
	case syscall.SYS_GETRLIMIT:
		return "GETRLIMIT"
	case syscall.SYS_GETRUSAGE:
		return "GETRUSAGE"
	case syscall.SYS_SYSINFO:
		return "SYSINFO"
	case syscall.SYS_TIMES:
		return "TIMES"
	case syscall.SYS_PTRACE:
		return "PTRACE"
	case syscall.SYS_GETUID:
		return "GETUID"
	case syscall.SYS_SYSLOG:
		return "SYSLOG"
	case syscall.SYS_GETGID:
		return "GETGID"
	case syscall.SYS_SETUID:
		return "SETUID"
	case syscall.SYS_SETGID:
		return "SETGID"
	case syscall.SYS_GETEUID:
		return "GETEUID"
	case syscall.SYS_GETEGID:
		return "GETEGID"
	case syscall.SYS_SETPGID:
		return "SETPGID"
	case syscall.SYS_GETPPID:
		return "GETPPID"
	case syscall.SYS_GETPGRP:
		return "GETPGRP"
	case syscall.SYS_SETSID:
		return "SETSID"
	case syscall.SYS_SETREUID:
		return "SETREUID"
	case syscall.SYS_SETREGID:
		return "SETREGID"
	case syscall.SYS_GETGROUPS:
		return "GETGROUPS"
	case syscall.SYS_SETGROUPS:
		return "SETGROUPS"
	case syscall.SYS_SETRESUID:
		return "SETRESUID"
	case syscall.SYS_GETRESUID:
		return "GETRESUID"
	case syscall.SYS_SETRESGID:
		return "SETRESGID"
	case syscall.SYS_GETRESGID:
		return "GETRESGID"
	case syscall.SYS_GETPGID:
		return "GETPGID"
	case syscall.SYS_SETFSUID:
		return "SETFSUID"
	case syscall.SYS_SETFSGID:
		return "SETFSGID"
	case syscall.SYS_GETSID:
		return "GETSID"
	case syscall.SYS_CAPGET:
		return "CAPGET"
	case syscall.SYS_CAPSET:
		return "CAPSET"
	case syscall.SYS_RT_SIGPENDING:
		return "RT_SIGPENDING"
	case syscall.SYS_RT_SIGTIMEDWAIT:
		return "RT_SIGTIMEDWAIT"
	case syscall.SYS_RT_SIGQUEUEINFO:
		return "RT_SIGQUEUEINFO"
	case syscall.SYS_RT_SIGSUSPEND:
		return "RT_SIGSUSPEND"
	case syscall.SYS_SIGALTSTACK:
		return "SIGALTSTACK"
	case syscall.SYS_UTIME:
		return "UTIME"
	case syscall.SYS_MKNOD:
		return "MKNOD"
	case syscall.SYS_USELIB:
		return "USELIB"
	case syscall.SYS_PERSONALITY:
		return "PERSONALITY"
	case syscall.SYS_USTAT:
		return "USTAT"
	case syscall.SYS_STATFS:
		return "STATFS"
	case syscall.SYS_FSTATFS:
		return "FSTATFS"
	case syscall.SYS_SYSFS:
		return "SYSFS"
	case syscall.SYS_GETPRIORITY:
		return "GETPRIORITY"
	case syscall.SYS_SETPRIORITY:
		return "SETPRIORITY"
	case syscall.SYS_SCHED_SETPARAM:
		return "SCHED_SETPARAM"
	case syscall.SYS_SCHED_GETPARAM:
		return "SCHED_GETPARAM"
	case syscall.SYS_SCHED_SETSCHEDULER:
		return "SCHED_SETSCHEDULER"
	case syscall.SYS_SCHED_GETSCHEDULER:
		return "SCHED_GETSCHEDULER"
	case syscall.SYS_SCHED_GET_PRIORITY_MAX:
		return "SCHED_GET_PRIORITY_MAX"
	case syscall.SYS_SCHED_GET_PRIORITY_MIN:
		return "SCHED_GET_PRIORITY_MIN"
	case syscall.SYS_SCHED_RR_GET_INTERVAL:
		return "SCHED_RR_GET_INTERVAL"
	case syscall.SYS_MLOCK:
		return "MLOCK"
	case syscall.SYS_MUNLOCK:
		return "MUNLOCK"
	case syscall.SYS_MLOCKALL:
		return "MLOCKALL"
	case syscall.SYS_MUNLOCKALL:
		return "MUNLOCKALL"
	case syscall.SYS_VHANGUP:
		return "VHANGUP"
	case syscall.SYS_MODIFY_LDT:
		return "MODIFY_LDT"
	case syscall.SYS_PIVOT_ROOT:
		return "PIVOT_ROOT"
	case syscall.SYS__SYSCTL:
		return "_SYSCTL"
	case syscall.SYS_PRCTL:
		return "PRCTL"
	case syscall.SYS_ARCH_PRCTL:
		return "ARCH_PRCTL"
	case syscall.SYS_ADJTIMEX:
		return "ADJTIMEX"
	case syscall.SYS_SETRLIMIT:
		return "SETRLIMIT"
	case syscall.SYS_CHROOT:
		return "CHROOT"
	case syscall.SYS_SYNC:
		return "SYNC"
	case syscall.SYS_ACCT:
		return "ACCT"
	case syscall.SYS_SETTIMEOFDAY:
		return "SETTIMEOFDAY"
	case syscall.SYS_MOUNT:
		return "MOUNT"
	case syscall.SYS_UMOUNT2:
		return "UMOUNT2"
	case syscall.SYS_SWAPON:
		return "SWAPON"
	case syscall.SYS_SWAPOFF:
		return "SWAPOFF"
	case syscall.SYS_REBOOT:
		return "REBOOT"
	case syscall.SYS_SETHOSTNAME:
		return "SETHOSTNAME"
	case syscall.SYS_SETDOMAINNAME:
		return "SETDOMAINNAME"
	case syscall.SYS_IOPL:
		return "IOPL"
	case syscall.SYS_IOPERM:
		return "IOPERM"
	case syscall.SYS_CREATE_MODULE:
		return "CREATE_MODULE"
	case syscall.SYS_INIT_MODULE:
		return "INIT_MODULE"
	case syscall.SYS_DELETE_MODULE:
		return "DELETE_MODULE"
	case syscall.SYS_GET_KERNEL_SYMS:
		return "GET_KERNEL_SYMS"
	case syscall.SYS_QUERY_MODULE:
		return "QUERY_MODULE"
	case syscall.SYS_QUOTACTL:
		return "QUOTACTL"
	case syscall.SYS_NFSSERVCTL:
		return "NFSSERVCTL"
	case syscall.SYS_GETPMSG:
		return "GETPMSG"
	case syscall.SYS_PUTPMSG:
		return "PUTPMSG"
	case syscall.SYS_AFS_SYSCALL:
		return "AFS_SYSCALL"
	case syscall.SYS_TUXCALL:
		return "TUXCALL"
	case syscall.SYS_SECURITY:
		return "SECURITY"
	case syscall.SYS_GETTID:
		return "GETTID"
	case syscall.SYS_READAHEAD:
		return "READAHEAD"
	case syscall.SYS_SETXATTR:
		return "SETXATTR"
	case syscall.SYS_LSETXATTR:
		return "LSETXATTR"
	case syscall.SYS_FSETXATTR:
		return "FSETXATTR"
	case syscall.SYS_GETXATTR:
		return "GETXATTR"
	case syscall.SYS_LGETXATTR:
		return "LGETXATTR"
	case syscall.SYS_FGETXATTR:
		return "FGETXATTR"
	case syscall.SYS_LISTXATTR:
		return "LISTXATTR"
	case syscall.SYS_LLISTXATTR:
		return "LLISTXATTR"
	case syscall.SYS_FLISTXATTR:
		return "FLISTXATTR"
	case syscall.SYS_REMOVEXATTR:
		return "REMOVEXATTR"
	case syscall.SYS_LREMOVEXATTR:
		return "LREMOVEXATTR"
	case syscall.SYS_FREMOVEXATTR:
		return "FREMOVEXATTR"
	case syscall.SYS_TKILL:
		return "TKILL"
	case syscall.SYS_TIME:
		return "TIME"
	case syscall.SYS_FUTEX:
		return "FUTEX"
	case syscall.SYS_SCHED_SETAFFINITY:
		return "SCHED_SETAFFINITY"
	case syscall.SYS_SCHED_GETAFFINITY:
		return "SCHED_GETAFFINITY"
	case syscall.SYS_SET_THREAD_AREA:
		return "SET_THREAD_AREA"
	case syscall.SYS_IO_SETUP:
		return "IO_SETUP"
	case syscall.SYS_IO_DESTROY:
		return "IO_DESTROY"
	case syscall.SYS_IO_GETEVENTS:
		return "IO_GETEVENTS"
	case syscall.SYS_IO_SUBMIT:
		return "IO_SUBMIT"
	case syscall.SYS_IO_CANCEL:
		return "IO_CANCEL"
	case syscall.SYS_GET_THREAD_AREA:
		return "GET_THREAD_AREA"
	case syscall.SYS_LOOKUP_DCOOKIE:
		return "LOOKUP_DCOOKIE"
	case syscall.SYS_EPOLL_CREATE:
		return "EPOLL_CREATE"
	case syscall.SYS_EPOLL_CTL_OLD:
		return "EPOLL_CTL_OLD"
	case syscall.SYS_EPOLL_WAIT_OLD:
		return "EPOLL_WAIT_OLD"
	case syscall.SYS_REMAP_FILE_PAGES:
		return "REMAP_FILE_PAGES"
	case syscall.SYS_GETDENTS64:
		return "GETDENTS64"
	case syscall.SYS_SET_TID_ADDRESS:
		return "SET_TID_ADDRESS"
	case syscall.SYS_RESTART_SYSCALL:
		return "RESTART_SYSCALL"
	case syscall.SYS_SEMTIMEDOP:
		return "SEMTIMEDOP"
	case syscall.SYS_FADVISE64:
		return "FADVISE64"
	case syscall.SYS_TIMER_CREATE:
		return "TIMER_CREATE"
	case syscall.SYS_TIMER_SETTIME:
		return "TIMER_SETTIME"
	case syscall.SYS_TIMER_GETTIME:
		return "TIMER_GETTIME"
	case syscall.SYS_TIMER_GETOVERRUN:
		return "TIMER_GETOVERRUN"
	case syscall.SYS_TIMER_DELETE:
		return "TIMER_DELETE"
	case syscall.SYS_CLOCK_SETTIME:
		return "CLOCK_SETTIME"
	case syscall.SYS_CLOCK_GETTIME:
		return "CLOCK_GETTIME"
	case syscall.SYS_CLOCK_GETRES:
		return "CLOCK_GETRES"
	case syscall.SYS_CLOCK_NANOSLEEP:
		return "CLOCK_NANOSLEEP"
	case syscall.SYS_EXIT_GROUP:
		return "EXIT_GROUP"
	case syscall.SYS_EPOLL_WAIT:
		return "EPOLL_WAIT"
	case syscall.SYS_EPOLL_CTL:
		return "EPOLL_CTL"
	case syscall.SYS_TGKILL:
		return "TGKILL"
	case syscall.SYS_UTIMES:
		return "UTIMES"
	case syscall.SYS_VSERVER:
		return "VSERVER"
	case syscall.SYS_MBIND:
		return "MBIND"
	case syscall.SYS_SET_MEMPOLICY:
		return "SET_MEMPOLICY"
	case syscall.SYS_GET_MEMPOLICY:
		return "GET_MEMPOLICY"
	case syscall.SYS_MQ_OPEN:
		return "MQ_OPEN"
	case syscall.SYS_MQ_UNLINK:
		return "MQ_UNLINK"
	case syscall.SYS_MQ_TIMEDSEND:
		return "MQ_TIMEDSEND"
	case syscall.SYS_MQ_TIMEDRECEIVE:
		return "MQ_TIMEDRECEIVE"
	case syscall.SYS_MQ_NOTIFY:
		return "MQ_NOTIFY"
	case syscall.SYS_MQ_GETSETATTR:
		return "MQ_GETSETATTR"
	case syscall.SYS_KEXEC_LOAD:
		return "KEXEC_LOAD"
	case syscall.SYS_WAITID:
		return "WAITID"
	case syscall.SYS_ADD_KEY:
		return "ADD_KEY"
	case syscall.SYS_REQUEST_KEY:
		return "REQUEST_KEY"
	case syscall.SYS_KEYCTL:
		return "KEYCTL"
	case syscall.SYS_IOPRIO_SET:
		return "IOPRIO_SET"
	case syscall.SYS_IOPRIO_GET:
		return "IOPRIO_GET"
	case syscall.SYS_INOTIFY_INIT:
		return "INOTIFY_INIT"
	case syscall.SYS_INOTIFY_ADD_WATCH:
		return "INOTIFY_ADD_WATCH"
	case syscall.SYS_INOTIFY_RM_WATCH:
		return "INOTIFY_RM_WATCH"
	case syscall.SYS_MIGRATE_PAGES:
		return "MIGRATE_PAGES"
	case syscall.SYS_OPENAT:
		return "OPENAT"
	case syscall.SYS_MKDIRAT:
		return "MKDIRAT"
	case syscall.SYS_MKNODAT:
		return "MKNODAT"
	case syscall.SYS_FCHOWNAT:
		return "FCHOWNAT"
	case syscall.SYS_FUTIMESAT:
		return "FUTIMESAT"
	case syscall.SYS_NEWFSTATAT:
		return "NEWFSTATAT"
	case syscall.SYS_UNLINKAT:
		return "UNLINKAT"
	case syscall.SYS_RENAMEAT:
		return "RENAMEAT"
	case syscall.SYS_LINKAT:
		return "LINKAT"
	case syscall.SYS_SYMLINKAT:
		return "SYMLINKAT"
	case syscall.SYS_READLINKAT:
		return "READLINKAT"
	case syscall.SYS_FCHMODAT:
		return "FCHMODAT"
	case syscall.SYS_FACCESSAT:
		return "FACCESSAT"
	case syscall.SYS_PSELECT6:
		return "PSELECT6"
	case syscall.SYS_PPOLL:
		return "PPOLL"
	case syscall.SYS_UNSHARE:
		return "UNSHARE"
	case syscall.SYS_SET_ROBUST_LIST:
		return "SET_ROBUST_LIST"
	case syscall.SYS_GET_ROBUST_LIST:
		return "GET_ROBUST_LIST"
	case syscall.SYS_SPLICE:
		return "SPLICE"
	case syscall.SYS_TEE:
		return "TEE"
	case syscall.SYS_SYNC_FILE_RANGE:
		return "SYNC_FILE_RANGE"
	case syscall.SYS_VMSPLICE:
		return "VMSPLICE"
	case syscall.SYS_MOVE_PAGES:
		return "MOVE_PAGES"
	case syscall.SYS_UTIMENSAT:
		return "UTIMENSAT"
	case syscall.SYS_EPOLL_PWAIT:
		return "EPOLL_PWAIT"
	case syscall.SYS_SIGNALFD:
		return "SIGNALFD"
	case syscall.SYS_TIMERFD_CREATE:
		return "TIMERFD_CREATE"
	case syscall.SYS_EVENTFD:
		return "EVENTFD"
	case syscall.SYS_FALLOCATE:
		return "FALLOCATE"
	case syscall.SYS_TIMERFD_SETTIME:
		return "TIMERFD_SETTIME"
	case syscall.SYS_TIMERFD_GETTIME:
		return "TIMERFD_GETTIME"
	case syscall.SYS_ACCEPT4:
		return "ACCEPT4"
	case syscall.SYS_SIGNALFD4:
		return "SIGNALFD4"
	case syscall.SYS_EVENTFD2:
		return "EVENTFD2"
	case syscall.SYS_EPOLL_CREATE1:
		return "EPOLL_CREATE1"
	case syscall.SYS_DUP3:
		return "DUP3"
	case syscall.SYS_PIPE2:
		return "PIPE2"
	case syscall.SYS_INOTIFY_INIT1:
		return "INOTIFY_INIT1"
	case syscall.SYS_PREADV:
		return "PREADV"
	case syscall.SYS_PWRITEV:
		return "PWRITEV"
	case syscall.SYS_RT_TGSIGQUEUEINFO:
		return "RT_TGSIGQUEUEINFO"
	case syscall.SYS_PERF_EVENT_OPEN:
		return "PERF_EVENT_OPEN"
	case syscall.SYS_RECVMMSG:
		return "RECVMMSG"
	case syscall.SYS_FANOTIFY_INIT:
		return "FANOTIFY_INIT"
	case syscall.SYS_FANOTIFY_MARK:
		return "FANOTIFY_MARK"
	case syscall.SYS_PRLIMIT64:
		return "PRLIMIT64"
	case 303:
		return "NAME_TO_HANDLE_AT"
	case 304:
		return "OPEN_BY_HANDLE_AT"
	case 305:
		return "CLOCK_ADJTIME"
	case 306:
		return "SYNCFS"
	case 307:
		return "SENDMMSG"
	case 308:
		return "SETNS"
	case 309:
		return "GETCPU"
	case 310:
		return "PROCESS_VM_READV"
	case 311:
		return "PROCESS_VM_WRITEV"
	case 312:
		return "KCMP"
	case 313:
		return "FINIT_MODULE"
	}
	return fmt.Sprintf("%d - ERR_UNKNOWN_SYSCALL", e)
}
