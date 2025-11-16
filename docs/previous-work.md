## Sandboxing by emulation

- Recompiling in another language, e.g. transpile to WASM

## Run-time system call origin restriction

Various research projects have studied how to restrict which system calls can be performed from where[5][6].
To do so, system call locations and types must first be inventoried. This prerequisite is usually handled focusing on statically-linked binaries, whilst all popular OSes use and package dynamically-linked binaries. 

Some ideas include embedding all allowed system call locations in the executable file, then filter at kernel level to only allow these call addresses and syscalls[5]. This idea could nowadays be implemented using a seccomp BPF filter (which can perform comparisons on call address and system call type) to avoid using custom kernel patches. However, this requires an inventory of system calls not known in advance (e.g. when dynamically linking to a library provided by the system's package manager), and scanning memory to find system call instructions would require handling cases of . - it requires a patched kernel and dynamic linker, and there are no such patches available to the public for popular OSes like GNU/Linux or Windows;
- in the Windows ecosystem, system calls are seldom performed directly in assembly: instead, programs (and malicious shellcodes) call into ntdll.dll, and thus filtering based on call address is not enough (stack analysis would be required, and even then, it can be spoofed since it is stored in userland memory ranges);

## Capsicum

This project was designed by researchers from the University of Cambridge in 2010[3]. Its goal is to add extensions to system calls and libraries exposed to unprivileged processes, more suitable if they want to sandbox themselves. These extensions were merged into FreeBSD 9.0, but unfortunately the Linux integration project has been discontinued (the last patchset[2] for Linux 4.11 has not been updated for four years, and the original website[2] is no longer online).

With these extensions, processes can permanently cut their own access to global namespaces by entering a new *capability mode* : this removes their ability to open files by their absolute path, to debug processes by their PID, etc. Instead, access needs to be requested through *capabilities* (unforgeable tokens of authority[4]), already held by the process : a file can be opened if you hold a capability pointing to its parent directory with sufficient rights. Such capabilities (in the Capsicum sense of the word, unlike POSIX.1e or Linux capabilities) are based on file descriptors, so they can be passed through UNIX sockets. However, they differ from standard file descriptors in the granularity of access rights they grant: `fchmod()` still works on a read-only file descriptor, but on a capability around that file descriptor it requires `CAP_FCHMOD`. `fcntl()` can clear the the `O_APPEND` flag of a file descriptor, but writing anywhere into a capability around that file descriptor requires `CAP_SEEK`, etc.[4].

This approach has several advantages: policy checks are enforced by the kernel, so it does not require a broker for each application, it is reviewed by professionals, it is already installed in all cases, and updated along with the OS. However, it is unclear whether the capsicum-linux project has been discontinued for good, and there is no indication from Microsoft of any intention of implementing an equivalent API, so we cannot rely on Capsicum APIs being available.

Work published in the Capsicum project and its patchset for Linux have been of interest, at the very least:
- for its inventory of global namespaces which need to be locked down;
- for its use of seccomp BPF filtering, instead of kernel modifications;
- for its approach of file restrictions through a new `O_BENEATH` flag, and its warning of race conditions when allowing `..\` in path lookups;
- for its precise documentation.

## gVisor

This project, written and Go and started by Google, uses virtualization and a virtual machine monitor bundled with a minimal kernel. It mostly targets containers, by offering a container runtime compatible with e.g. Docker, but may also be used to sandbox individual applications.

Since this approach uses a hypervisor, it requires a hypervisor to be installed and administrator privileges, which is not compatible with our end-user requirements.

## Cappsule

This project, written in C and assembly and started by Quarkslab, inserts a minimal hypervisor (~15'000 lines of C) under the running OS, and creates lightweight VMs for each application. VMs have a single vCPU, a copy-on-write view of system RAM, and no access to the hardware. Processes in VMs communicate with the original OS via shared memory to emulate network features, filesystem features, and GUI features (through the same code as Qubes OS).

Since this approach uses a custom Linux hypervisor, it requires administrator privileges to load kernel modules, and does not work for e.g. Windows, which is not compatible with our end-user requirements.

## Chromium Web browser

        - https://chromium.googlesource.com/chromium/src.git/+/master/docs/linux/sandboxing.md
        - https://chromium.googlesource.com/chromium/src/+/master/docs/design/sandbox_faq.md
        - https://lwn.net/Articles/347547/

## Mozilla Firefox

        - https://wiki.mozilla.org/Security/Sandbox

## Brave Web browser

## Systemd units

## Adobe Reader

## OpenSSH

        - https://github.com/openssh/openssh-portable/blob/master/sandbox-seccomp-filter.c

## WebKitGTK

## GNOME

## Apple's SecurityServer

## SELinux sandbox context

## BubbleWrap

## Flatpak

## Firejail

        - https://firejail.wordpress.com/
        - https://wiki.archlinux.org/index.php/firejail
        - https://github.com/netblue30/firejail
        - Past vulnerabilities:
                - https://seclists.org/oss-sec/2017/q1/20

## Internet Explorer Protected Mode

Simply used a Low Integrity Level 
Low integrity level was used for Internet Explorer's "Protected Mode", without being an officially supported security boundary.

# References

    [1] https://github.com/google/capsicum-linux
    [2] http://capsicum-linux.org
    [3] https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf
    [4] https://www.freebsd.org/cgi/man.cgi?query=rights&sektion=4
    [5] https://www.usenix.org/legacy/publications/library/proceedings/sec05/tech/full_papers/linn/linn.pdf
    [6] https://www.researchgate.net/publication/220796742_Detection_of_injected_dynamically_generated_and_obfuscated_malicious_code/
