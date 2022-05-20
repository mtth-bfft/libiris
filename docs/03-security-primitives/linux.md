# Linux security and filtering mechanisms

## User and group identifiers

Users are identified by a unique numeric identifier (User ID or UID) stored in /etc/passwd, or other identity providers managed by the Name Service Switch (e.g. a LDAP server).
Each user has a primary group identified by Group ID (GID) in that same location. Each user may also have supplemental group(s), if they are listed as member of one or more group in /etc/group (or in other identity providers).

User and group ID are used in various access checks, with UID 0 being reserved for root and bypassing all capability checks. GID 0, however, does not bypass capability checks, but may grant read or write access to sensitive files depending on programs installed.

Credentials are stored on a per-thread basis:

- *Real UID* (RUID/RGID): the ones of the user who started a process
- *Saved UID* (SUID/SGID): the ones which can be restored if needed (e.g. for a service to open a file as a user, then become root again)
- *Effective UID* (EUID/EGID): the ones used by the kernel when performing access checks, except for the filesystem
- *FileSystem UID* (FSUID/FSGID): the ones used by the kernel when accessing files. This used to be useful to allow services to open files as users but not allowing them to send the service signals (e.g. kill it). They are now transparently updated to the effective IDs whenever they change, because since kernel 1.3.78 a signal can only be sent if sender's RUID/EUID in target's RUID/SUID
- *Supplemental groups*: GIDs user is also a member of, used just like the primary GID, for filesystem access checks

If an executable with the SUID bit set is executed, it starts with the RUID of the executing user, but with the EUID and SUID of the file owner.

## Process group ID and session ID

Each thread has a *Session ID*, the PID of the session leader for that task. A task becomes a session leader by calling `setsid()`. When a session leader opens a terminal for the first time, it becomes the *controlling terminal* for the entire session.

TODO: need to move to a separate session to separate controlling terminals?

## Discretionary Access Control (DAC)

DAC on Linux is entirely based on UIDs and GIDs. Its only goals are to protect users from each others, and let them share what they want.
On modern filesystems (e.g. ext4, zfs, btrfs, etc.), each file or directory has 9 permission bits:
- read, write, and execute bits, used if the accessor's EUID is the file owner UID
- read, write, and execute bits, used if the accessor's EGID is the file group GID
- read, write, and execute bits, used otherwise (this allows to create special cases where everyone can read a file except a restricted group, more on that later)

## Mandatory Access Control (MAC)

Various MAC solutions exist and may be enforced by the kernel: SELinux, Smack, Tomoyo, AppArmor, etc.[2]
These solutions require administrator privileges on the host to be configured, and thus are considered out of scope for this project.

## Capabilities

Each thread holds three sets of capability bits since Linux 2.6.23 (2008-10). These bits grant an exemption of some discretionary authorization checks, or grant access to a shared resource which cannot be controlled by DAC.

- the *effective set* contains all the capabilities which can be used when requesting a privileged action;
- the *bounding set* contains the maximum set of capabilities that task will ever be able to have in its effective set. Adding a capability to it is impossible. The first process starts with a full set. It is inherited by all children, so stripping it from a capability makes it unusable for all children, forever. It is a privileged operation, since it could be used to trick a child process designed to work with certain capabilities into performing only part of an action (e.g. writing to a file but then being unable to delete it);
- the *permitted set* contains capabilities which the task can decide to add to its effective set (thus it can be a strict superset of the effective set if some capabilities are not required/desired at the moment). Capabilities cannot be added to that set, but can be removed without any privilege.

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

        CAP_DAC_READ_SEARCH   Bypass file+dir read+execute permission checks
        CAP_DAC_OVERRIDE      Bypass file permission checks, read /proc/*/{cwd,exe,root}
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

        CAP_SYS_ADMIN         All sysadmin ops: mount/swapon/pivot_root/sethostname/override RLIMIT_NPROC/set trusted and security extended attributes/keyctl()/etc.

        CAP_SYS_NICE          nice()/setpriority()/sched_setscheduler()/sched_setaffinity(), etc.

        CAP_SYS_PTRACE        ptrace() arbitrary processes, read /proc/*/environ (leak credentials)
        CAP_MKNOD             mknod() arbitrary devices
        CAP_SYS_RAWIO         Access /proc/kcore, /dev/mem, /dev/kmem to write kern mem, and use IO ports (iopl/iopem) (leak credentials)

        CAP_SYS_RESOURCE      Override disk quotas, use system reserved space increase hard rlimits, override RLIMIT_NPROC (DoS)
        CAP_KILL              Send arbitrary signals (kill, sigqueue)

        CAP_SYS_TIME          settimeofday/stime/adjtime/adjtimex, set hardware clock (crypto rollback attacks?)

        CAP_SYS_TTY_CONFIG    would allow killing (vhangup) any terminal ?
        CAP_SYSLOG            empty system-wide kernel logs, read system-wide log entries including kernel addresses (breaks KASLR)
        CAP_NET_BROADCAST     unused

Since Linux 2.6.24, files can have capability bits set, which grants anyone executing that file the capability.

## User Namespaces

- Segments:
        - UIDs / GIDs
        - keyrings
        - capabilities:
                - only are usable against objects in the namespace
                        - if global effect (e.g. mounting a block device, setting time, loading a kernel module), only have an effect in the root user namespace
                - capability is owned if (cap in effective capability set && process in that usernamespace or a parent) || (process is the creator/"owner" of the user namespace)
                - full set of capabilities is given when entering the namespace
                - `CAP_SYS_ADMIN` in the namespace to enter, and makes you lose any capability you had in the parent)

- Nesting can be prevented with sysctl `user.max_user_namespaces` = 0 in the namespace

- Set (once and once only) through `/proc/[pid]/uid_map` and `/proc/[pid]/gid_map` (requires `CAP_SETUID` or `CAP_SETGID`)
        <id in [pid]'s usernamespace>   <id in the reader namespace, or in parent namespace if read from within>        <range length (1 <= N <= 4294967295)>
        (UID/GID=4294967295 are unusable on purpose, they are == (-1) which has the semantic of "any value" for some syscalls)

        - limited to 5 ranges in 4.14 and less, 340 ranges in 4.15+
        - ranges cannot overlap
        - ranges must map to IDs which are, in turn, mapped in the parent namespace

- Requires CAP_SYS_ADMIN up to 3.7, nothing in 3.8+
	- TODO: distributions patch to still restrict to CAP_SYS_ADMIN

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


## Chroot

A system call named `chroot` allows changing which directory is seen by a thread as the "root" of the file hierarchy. This can only be done by processes running with `CAP_SYS_CHROOT` in their user namespace, due to the potential of abuse (e.g. chroot in /tmp/a/ after forgeing /tmp/a/etc/shadow to trick a SUID binary to give us root access).

Care should be taken to drop `CAP_SYS_CHROOT` after use, since chroots are trivial to escape when holding that capability: just chroot further into a subdirectory while holding a file descriptor to the previous root, then that file descriptor (outside of the new chroot) has no restriction and can be used to access files anywhere in the actual root.

## No New Privs

Since Linux 3.5, a special per-thread bit named `no_new_privs` disables all special semantics of `execve` which could grant more privileges[1]. In particular, it blocks all file Set-UID bit, Set-GID bit, and file capabilities semantics.

This bit should be set using `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.

## Cgroups

Introduced in Linux 2.6.24 (2008-01)

## Seccomp

## References

    [1] https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt
    [2] https://www.kernel.org/doc/html/v4.16/admin-guide/LSM/index.html

