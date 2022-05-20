The smallest security boundary supported by operating systems is between processes: even if on UNIX operating systems threads can have different access rights and mitigations, they could still tamper with each others by writing to their address space, and Windows does not support this.
=> Each sandboxing policy must be implemented by a separate process.

On Windows, creating a restricted process requires setting almost all parameters of `CreateProcess`, and modifying the process memory before it runs its very basic initialization.
=> The sandboxing library must offer an API which encapsulates primitives offered by the OS to create processes.

On Linux, in some cases, modifications must be applied to the seccomp filter of sandboxed processes after they began running.
=> The sandboxed process must be aware of its sandboxing and cooperate to e.g. load a library.

On Linux, using `ptrace` or seccomp with `SECCOMP_RET_TRACE` to filter system calls prevents anyone from attaching to the sandboxed process to debug it, which greatly impedes usability of the sandbox by developers.
=> Linux sandboxing must not rely on `ptrace` or `SECCOMP_RET_TRACE`

