# Linux security and filtering mechanisms

## Sessions and process groups

Each process starts with a Process ID (PID) different from that of all other processes currently running.

Each process is associated with a *process group* (or "job"), which itself belongs to a *session*. Both these characteristics are inherited from parent processes.

Processes in the same session can send each other `SIGCONT` signals (interfering with normal control flow), and can join each others' process group. Moreover, each session is associated with zero or one *controlling terminal* (a terminal which can be read from, and may send signals in response to these operations). Various operations can be performed on the terminal via `ioctl()`, including spying on keystrokes (by reading from `/dev/tty`, even if you made sure to close the standard input file descriptor), and injecting fake keystrokes to potentially execute shell commands (using `ioctl(TIOCSTI)`). To prevent this, processes should detach from any controlling terminal permanently, by creating a new session for themselves (via `setsid()`).

From that state, attaching to a new controlling terminal requires (see `ioctl(TIOCSCTTY)`):
- either a file descriptor leak, or being able to open a `/dev/tty*` character device, which requires passing access checks on it;
- and, if another process already uses that terminal, `CAP_SYS_ADMIN`.

## User and group identifiers

Users are identified by a unique numeric identifier (User ID or UID) stored in /etc/passwd, or other identity providers managed by the Name Service Switch (e.g. a LDAP server).
Each user has a primary group identified by Group ID (GID) in that same location. Each user may also have supplemental group(s), if they are listed as member of one or more group in /etc/group (or in other identity providers, e.g. LDAP groups).

User and group ID are used in various access checks, with UID 0 having different semantics: it bypasses all access checks. GID 0, however, does not have this specificity, but may grant read or write access to sensitive files depending on programs installed.

Credentials are stored on a per-task (think "per-thread") basis:

- *Real UID* (RUID/RGID): the ones of the user who started a process
- *Effective UID* (EUID/EGID): the ones used by the kernel when performing access checks, except for the filesystem
- *FileSystem UID* (FSUID/FSGID): the ones used by the kernel when accessing files. This used to be useful to allow services to open files as users but not allowing them to send signals to the service (e.g. kill it). Filesystem IDs are now transparently updated to the effective IDs whenever they change, because since kernel 1.3.78 a signal can only be sent if the sender's RUID or EUID is equal to the target's RUID or SUID. Filesystem IDs do not need to be set manually.
- *Saved UID* (SUID/SGID): the ones which can be restored if needed (e.g. for a service to open a file as a client user, then become root again)
- *Supplemental groups*: all GIDs of groups which list the user as a member, used just like the primary GID, for filesystem access checks. Users can switch their GID to the ID of any of their supplemental groups, but this is a privileged operation done via the `newgrp` set-UID-0 executable.

If an executable with the SUID bit set is executed, it starts with the RUID of the executing user, but with the EUID and SUID of the file owner.

## Discretionary Access Control (DAC)

DAC on Linux is entirely based on UIDs and GIDs. Its only goals are to protect users from each others, and let them share what they want.

File access, on modern filesystems (e.g. ext4, zfs, btrfs, etc.), is governed by 9 permission bits on each file and directory:
- read, write, and execute bits, used if the accessor's EUID is the file owner ID
- read, write, and execute bits, used if the accessor's EGID is the file group ID
- read, write, and execute bits, used otherwise (this allows to create special cases where everyone can read a file except a restricted group, more on that later).

The read, write, and execute permission on files respectively allows reading them, replacing their contents, and using them in an `execve()` call. On directories, they respectively allow listing child files, adding and removing child files and directories, and traversing the directory to perform operations on child files and directories themselves. Note that, by definition, adding child files and directories requires traversing the directory.

When accessing a file path, the caller must be allowed to traverse all directoires, and must have at least the requested access rights on the final component.

## Mandatory Access Control (MAC)

Various MAC solutions exist and may be enforced by the kernel: SELinux, Smack, Tomoyo, AppArmor, etc.[2]
These solutions require administrator privileges on the host to be configured, and thus are considered out of scope for this project.

## Capabilities

Each thread holds five sets (or bitfields) of *capabilities*, progressively added since Linux 2.6.23 (2008-10), which grant an exemption of some discretionary authorization checks, in a more granular way than EUID 0. These sets are inherited by child processes, and are only changed by the kernel when calling `execve()`.

- the *effective set* contains all the capabilities held by the process which will influence the results of access checks;
- the *permitted set* contains capabilities which the task can decide to add to its effective set: it is a way to keep a capability but not use it at a given moment. Capabilities can only be removed from that set;
- the *bounding set* contains an upper bound on capabilities that process will ever be able to have in its effective set. Capabilities can only be removed from that set;
- the *inheritable set* is used during `execve()` as a bit mask of capabilities to use in the executable's inheritable set, if any;
- the *ambient set* (since Linux 4.3) contains capabilities which will be transmitted in the permitted and effective set after a call to `execve()` (if the executable does not have Set-UID nor Set-GID bits nor file capabilities, to prevent tampering with the behaviour of privileged executables).

Files can also have three capability sets since Linux 2.6.24, stored in their `security.capability` extended attribute (if their filesystem supports it):

- capabilities in the *permitted set* (or "forced set") are automatically added to the permitted set of the process: they are needed by the executable to run and it expects to hold them;
- capabilities in the *inheritable set* (or "allowed set") are added to the permitted set of the process if the thread calling `execve()` holds them in its inheritable set: it is a way for the file to say that it can hold them without problem, but does not require them;
- the *effective set* is "all or nothing": if it is enabled, the effective set after `execve()` is automatically set to the permitted set of the process instead of ambient capabilities, and if any permitted file capability is not acquired in the process permitted set (e.g. because of a bounding set), execution is aborted (this is used for legacy SUID binaries not aware of what a capability is, to protect them from being executed with fewer capabilities than they expect).

Since capabilities which allow controlling the entire system may be introduced in the future, implementations must be careful to strip any capability not known at compile time (e.g. by removing capabilities up to the highest supported one, which can be queried at runtime via `/proc/sys/kernel/cap_last_cap` since Linux 3.2).
Some capabilities allow escaping any sandbox, by design, and cannot be delegated:

        CAP_SYS_ADMIN         All sysadmin ops: mount/swapon/pivot_root/sethostname/override RLIMIT_NPROC/set trusted and security extended attributes/keyctl()/etc.

        CAP_AUDIT_CONTROL     Disable system-wide kernel auditing
	CAP_AUDIT_READ        Read system-wide auditing log entries
        CAP_AUDIT_WRITE       Append system-wide auditing log entries
	CAP_BLOCK_SUSPEND     Keep the entire system powered on
	CAP_WAKE_ALARM        Keep the entire system powered on
	CAP_BPF
        CAP_IPC_LOCK          Override memory locking restrictions (mlock/mlockall/SHM_LOCK/etc.)
        CAP_IPC_OWNER         Bypass System V IPC objects permission checks
        CAP_MAC_ADMIN         Configure MAC (not supported by all MACs)
        CAP_MAC_OVERRIDE      Override MAC (not supported by all MACs)
        CAP_NET_ADMIN         Configure network interfaces/routing/firewalling, privileged sockets, etc.
		An unprivileged process cannot modify netfilter rules in its original network namespace. Even if it creates a new network namespace, that network namespace will not be able to communicate with the original one, and injecting a veth interface pair between the two would require `CAP_NET_ADMIN` in the original namespace. Creating a user namespace can only grant `CAP_NET_ADMIN` on a new network namespace within that user namespace, but not on the original network namespace within the original user namespace.
		=> Network can only be filtered by creating a new network namespace, and intercepting socket functions to serialize them to a broker. As a defense in depth, or as a degraded restriction if network namespaces cannot be used (e.g. if the kernel was compiled without support, or if user namespaces cannot be used to gain `CAP_NET_ADMIN`), network system calls can be restricted using seccomp.

        CAP_NET_BIND_SERVICE  Bind to privileged ports
        CAP_NET_RAW           Open raw/packet sockets

        CAP_DAC_READ_SEARCH   Grants directory read and search, and file read
        CAP_DAC_OVERRIDE      Bypasses file permission checks
        CAP_FOWNER            Act as owner of all files
        CAP_CHOWN             Change arbitrarily ownership/groups (possibly not your uid/gids)
        CAP_FSETID            Enable SUID/SGID on a file not owned by you, modify files w/o removing SUID/SGID
        CAP_SETUID            Arbitrary changes to any process's user IDs (setuid/euid/reuid/resuid/fsuid), forge UID when passing SCM_CREDENTIALS in unix sockets
        CAP_SETGID            Arbitrary changes to any process's group IDs (setgid/egid/regid/resgid/fsgid/setgroups/initgroups)
        CAP_SETFCAP           Set arbitrary file capabilities
        CAP_SETPCAP           Add any cap from bounding set to inheritable set (give to children, even if it's not in permitted set), drop bounding set, change securebits. Before commit 72c2d5823fc7, would allow process to give arbitrary caps to any process (was a hack waiting for file capabilities to be ready)
        CAP_LINUX_IMMUTABLE   Set/unset append/immutable inode flags
        CAP_LEASE             fcntl(F_SETLEASE) on arbitrary files

        CAP_SYS_PACCT         Use acct() to enable/disable process accounting

        CAP_SYS_CHROOT        chroot()
        CAP_SYS_BOOT          reboot(), kexec_load() (rootkit)
        CAP_SYS_MODULE        Load/unload kernel modules {init,delete,create}_module() (rootkit)


        CAP_SYS_NICE          nice()/setpriority()/sched_setscheduler()/sched_setaffinity(), etc.

        CAP_SYS_PTRACE        ptrace() arbitrary processes, read /proc/*/environ (leak credentials)
        CAP_MKNOD             mknod() arbitrary devices, this should be blocked and only device files on an allow list should be populated in a restricted process' `/proc`: even if mounting block devices can only be done from the initial user namespace, they can still be read from and written to
        CAP_SYS_RAWIO         Access /proc/kcore, /dev/mem, /dev/kmem to write kern mem, and use IO ports (iopl/iopem) (leak credentials)

        CAP_SYS_RESOURCE      Override disk quotas, use system reserved space increase hard rlimits, override RLIMIT_NPROC (DoS)
        CAP_KILL              Send arbitrary signals (kill, sigqueue)

        CAP_SYS_TIME          settimeofday/stime/adjtime/adjtimex, set hardware clock (crypto rollback attacks?)

        CAP_SYS_TTY_CONFIG    would allow killing (vhangup) any terminal ?
        CAP_SYSLOG            empty system-wide kernel logs, read system-wide log entries including kernel addresses (breaks KASLR)
        CAP_NET_BROADCAST     unused

## Chroot

A system call named `chroot` allows changing which directory is seen by a thread as the "root" of the file hierarchy. This can only be done by processes running with `CAP_SYS_CHROOT` in their user namespace, due to the potential of abuse (e.g. chroot in /tmp/a/ after forgeing /tmp/a/etc/shadow to then authenticate as root).

Care should be taken to drop `CAP_SYS_CHROOT` after use, since chroots are trivial to escape when holding that capability: just chroot further into a subdirectory while holding a file descriptor to the previous root, then that file descriptor (outside of the new chroot) has no restriction and can be used to access files anywhere in the actual root.

## User Namespaces

Since Linux 3.5, starting a new process using `clone(CLONE_NEWUSER)` creates a new *user namespace* which adds a translation layer for user and group IDs, allowing processes to see their IDs being X whilst they are actually mapped to Y in the parent user namespace. User namespaces are attached to the one which created them, forming a tree which always allows (with a varying number of translations) to end up with translated IDs in the namespace where the resource resides (e.g. the initial user namespace for block device filesystems, or another namespace with which communication has been established using a Unix socket).

Creating a user namespace required `CAP_SYS_ADMIN`, `CAP_SETUID`, and `CAP_SETGID` up to Linux 3.7, but nothing in 3.8 and later. Moving a process to an existing user namespace is possible with the `setns()` system call, but requires `CAP_SYS_ADMIN` in the destination namespace. Due to the new attack surface from unprivileged code to code guarded by EUID 0 checks (and therefore previously less audited), many vulnerabilities emerged, and many popular distributions patched their kernel to only expose this feature if a privileged sysctl was set:

- Ubuntu [introduced a patch in 2013](https://sources.debian.org/patches/linux/3.16.56-1+deb8u1/debian/add-sysctl-to-disallow-unprivileged-CLONE_NEWUSER-by-default.patch/), and rolled it back in 14.04 (based on Debian 8)
- Debian used the same patch as Ubuntu until [version 11 in 2021](https://www.debian.org/releases/stable/amd64/release-notes/ch-information.html)
- Arch Linux still applies the original Ubuntu patch to its stable kernel to this day (Linux 5.18), but with a default value of `unprivileged_userns_clone=1` since [version 5.3](https://github.com/archlinux/linux/commit/4548790064d9d658127c85c8e318f0f397c63889)

Due to the potential vulnerabilities mentionned above, if user namespaces are accessible by unprivileged processes, it is important to prevent creating any more user namespace in a sandboxed process. This can be achieved with sysctl `user.max_user_namespaces` set to 0 in the namespace.

Until a UID and GID mapping are set, IDs returned by interfaces (owner and group in `stat()`, process credentials in `getresuid()`, information from /proc, etc.) are all replaced with the `sys.kernel.overflowuid` and `sys.kernel.overflowgid` sysctl values (65534 by default), and the process IDs are transparently mapped to the effective UID of the creator in the parent user namespace. A mapping can be set, once, by writing to `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`. This requires `CAP_SETUID` and `CAP_SETGID` in the user namespace being set up, and requires `CAP_SETGID` in the parent namespace (except if `deny` has been written to `/proc/<pid>/setgroups`, in which case there is no risk for a user namespace to strip its identity of a restrictive group by unmapping its GID).

ID ranges cannot overlap, and must map to valid IDs in the parent user namespace. They are written in the following syntax:

        <id in [pid]'s usernamespace>   <id in the file opener user namespace, or in parent namespace if opened from within>        <range length (1 <= N <= 4294967295)>

Note that IDs 4294967295 are unusable on purpose, they are equal to `(uid_t)(-1)` which means "any value" for some syscalls.

The first process in a namespace, and any process joining it via `setns`, has all capabilities in it. Holding a capability grants it in the current user namespace and all child namespaces, but not in parent ones. Additionally, having an EUID equal to that of the creator of a user namespace grants all capabilities in that namespace.

Capabilities held by processes only have effect on resources exposed in the user namespace, and operations which have global effects not restricted to one user namespace (e.g. loading a kernel module, mounting a block device) can only be performed from the initial user namespace. Capabilities set on files, along with set-UID and set-GID bits, only change IDs within the namespace: translation is still performed when operating on resources in a parent namespace.

Other types of namespaces below are all associated to one user namespace. Changing user namespace alone does not revoke access to resources already held in other namespaces (e.g. if file descriptors remain open, or if mount namespace is not   A pitfall is to only change user namespaces, and keep an existing process namespace (it is then possible to inject into another process), or keep an existing mount namespace (it is then possible to e.g. use that namespace's `/proc` to access other processes)

## Mount Namespaces

- Requires `CAP_SYS_ADMIN` to create
- Some mount types require `CAP_SYS_ADMIN`:
        - bind-mounts
        - procfs (since Linux 3.8)
        - sysfs (since Linux 3.8)
        - devpts (since Linux 3.9)
        - tmpfs (since Linux 3.9)
        - ramfs (since Linux 3.9)
        - mqueue (since Linux 3.9)
        - bpf (since Linux 4.4)

## Other Namespaces




## No New Privs

Since Linux 3.5, a special per-thread bit named `no_new_privs` disables all special semantics of `execve` which could grant more privileges[1]. In particular, it blocks all file Set-UID bit, Set-GID bit, and file capabilities semantics.

This bit should be set using `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.

## Cgroups

Introduced in Linux 2.6.24 (2008-01)

## Seccomp

## References

    [1] https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt
    [2] https://www.kernel.org/doc/html/v4.16/admin-guide/LSM/index.html

