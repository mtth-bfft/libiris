# Concepts

**Sandboxing** is an ambiguous term in the information security field, which can be related to antiviruses and emulation[1], or, as is the case in this project, "everything one can do to reduce the impact of a program being compromised by an attacker".

A program can become compromised if it handles data from untrusted sources, crafted by attackers in unexpected ways in order to alter all or part of the intended program behavior (e.g. deploy a ransomware on personal files, open a backdoor for later access, etc.). It can also become compromised as a result of supply-chain attacks, in which case it can act maliciously even before handling any input.

Everything a comprehensive sandbox does to achieve its goal can be classified into two categories:

1. reduce the **ambient authority** of the code handling untrusted data, that is everything it can legitimately do just because of its identity: what files it can open, whether it can reboot the computer, connect to the network, etc.[2] Reducing ambient authority to the least a program needs in order to function is the **principle of least privilege**, a general security best practice;

2. reduce the **attack surface** reachable from the sandbox. The attack surface is every line of code an attacker inside the sandbox can trigger (directly, or indirectly by a chain of events) outside the sandbox:
- in another process, via remote procedure calls: some D-Bus services on Linux[3] or ALPC servers[4] on Windows run as administrator;
- in the kernel, via system calls: for instance, CVE-2016-5195 in Linux allowed full system compromise using system calls all users can trigger (`open(/proc/self/mem), open(/etc/passwd, O_RDONLY), mmap(), madvise()`) no matter their identity[5];
- in another computer, via the network: for instance, CVE-2017-0144 or CVE-2020-1472 allow a full Windows system compromise from any network neighbour able to send network packets.
Each additional reachable line of code statistically increases the risk of a vulnerability in it being exploitable by an attacker to gain more ambient authority (a **sandbox escape**).

Reducing the ambient authority will often, as an added benefit, also reduce the attack surface (e.g. by removing the possibility of exploiting vulnerabilities in code located after a privilege check). Nevertheless, the two categories are distinct: if all an attacker needs to do to escape is to chain a second vulnerability in decades-old unmaintained code, reducing ambient authority will not be enough to stop them. Attack surface reduction should prevent these chained attacks, as a defense in depth.

Reducing ambient authority can be done to various extents, by splitting code into more or fewer sandboxes with different ambient authorities. Theoretically, each piece of code could run in a sandbox with exactly the privileges it requires. In practice, each split costs hardware resources (processor time, memory), requires introducing communication channels which need to be developped and tested, may introduce security vulnerabilities, and may even introduce too much performance overhead just to communicate back and forth. The other end of the spectrum consists in running the entire program in one big sandbox (possibly without it even being aware, a good example of such a sandbox being firejail[6]). This allows retrofitting a sandbox around an unmodified executable, if you do not control or do not want to modify its source code. This is oviously easier, and can be done by end users without support from developers. However, even when done to a full extent, it can only reduce the ambient authority and attack surface to the overall union of what each part of the program needs to function. This is not acceptable for lots of programs nowadays, which typically require access to several types of resources (e.g. a media player might need in one continuous run to read local files, download a video from arbitrary Internet sources, write that video to a local file, all while using security-sensitive functions in the graphics card). In such cases, multiple more fine-grained sandboxes are required.

## References

    [1] https://www.blackhat.com/docs/us-14/materials/us-14-Kruegel-Full-System-Emulation-Achieving-Successful-Automated-Dynamic-Analysis-Of-Evasive-Malware-WP.pdf
    [2] https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf
    [3] https://github.com/netblue30/firejail/issues/796
    [4] https://pacsec.jp/psj17/PSJ2017_Rouault_Imbert_alpc_rpc_pacsec.pdf
    [5] https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
    [6] https://github.com/netblue30/firejail

