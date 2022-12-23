# NetBSD security model and sandboxing primitives

Like other BSDs, ambient authority entirely depends mostly on your numeric IDs for user and group(s). These come from `/etc/passwd` during your login. UID 0 (root) is given the highest privileges, while others are given basic ones. The first group in the list is the effective GID, and is set to the user's GID from `/etc/passwd`, and additional groups are added according to `/etc/group`.

Changing credentials of a process can be done in two cases:
- when running as `root`, arbitrary values can be set with `setuid()`, `seteuid()`, `setgid()`, `setegid()`, and `setgroups()`;
- when running a `setuid` (or `setgid`) file, which has bit 0o4000 (or 0o2000) set in their mode bitfield, EUID (or EGID) can be set to the saved UID (or GID) or real UID (or GID).

Processes can always write to their attached terminal, if they inherited one from their parent process, or if they attached to one manually. They have credentials which determine whether they can attach and read from terminals:
- a session ID (the PID of the first process in each session): being the first process in a session grants the right to open and attach a controlling terminal;
- a process group ID, within the session of the process: being in the foreground process group of a session allows the process to read from the controlling terminal, if any;

## Ptrace

One option could be to debug worker processes, and control their execution by inspecting their CPU registers at system call time (using the `PT_SYSCALL` option). However, since only one process can be attached as debugger at a time, this would prevent developpers from debugging their own bugs.

## Chroot

A `chroot()` system call is supported, but it can be used by `root` only.

`chroot` on NetBSD implements a few more security checks than other OSes to prevent escapes, like automatically changing the current working directory if needed.

## Conclusion

There is no way to prevent access to local nor remote network services.
To prevent snooping on user input in the controlling terminal (if any), changing session is required.
A chroot alone would still allow worker processes to control the execution flow of non-chrooted processes (by using `ptrace`) and escaping, so lowering credentials is required.
Lowering credentials alone would still allow worker processes to access any file, device, pipe, or UNIX socket with a weak ACL.

The only option matching our requirements is to develop a set-UID executable, install it (as root), and proxy worker creation requests to it so that it drops ambient authority before running workers:
- by forking, switching to a new session with `setsid`, then forking again to not be a session leader;
- by setting UID and GIDs to unused ones;
- by cleaning any inherited file descriptor;
- by calling `chroot()` to an empty directory.
