## Introduction

This tool evolved from an educational hobby project, whose goal was to learn about sandboxing primitives and sandbox escapes on various operating systems.

This project emerged when talking with VideoLAN about a series of vulnerabilities found in their VLC media player[1]. They had already trained their developers about secure coding practices, hardened their application with compile-time and link-time mitigations, and enforced code reviews. Most of the problem lied in media libraries they depend on but do not maintain, some of them not actively maintained or being developped with performance in mind and not security.

Because of the functionalities provided and depended on by VLC, using application-level sandboxes provided by operating systems like macOS, iOS, or Android meant asking for all sensitive permissions (read and write access to personal files, Internet access, etc.), so it would not mitigate any risk[2].

Looking at existing sandboxes used by large popular projects (e.g. Chromium, Mozilla Firefox, Adobe Reader), all used the sandbox developped within the Chromium Web browser. An attempt had been made to retrofit it in VLC as well, but it had not made significant progress in a couple of years. The biggest difficulties mentionned by developers were grasping what was specific to the Chromium Web browser (in terms of authorisation policies, inter-process communication, etc.), learning Windows-specific security concepts (in a developer community more versed in Unixes), and changing existing build processes to integrate build toolchains from Google[2].

A contributor of the Chromium sandbox suggested building a smaller sandbox, targetting only the latest version of each of the most popular OSes. The idea was to reduce the entry cost for a project with no sandbox (and even without process separation, as in the case of VLC, more on that later), by reducing complexity and relying only on modern and simpler to use APIs. If the proof of concept seemed viable, it could later be turned into a full blown project, and in any case the work put into splitting up VLC into cooperating privileged domains would not be lost.

## Project goals

The first goal of this project is to document, in the most readable way for project owners and maintainers, how to integrate a sandbox. This includes both high-level problems and how security primitives work at a low level.

Then, if people want to use this project's code as a bootstrap to a first working sandbox in their project, the goal is to maintain a viable one:

- comprehensively documented so that it is easy to audit;
- able to block access to any personal user data;
- promptly patched when security vulnerabilities are discovered;
- easy to use, to facilitate its integration in projects in need of a generic sandbox: provide documentation, examples, and a simple and versioned API;
- based on supported security mechanisms provided by each OS it supports, so that their security vulnerabilities are fixed promptly;
- transparent to end-users and not require modifying the end-user system's logic or settings (e.g. adding a kernel driver, modifying file access control lists) or change behaviour of any other program (e.g. modify settings, even if they are local to the session).

## References

    [1] https://blog.checkpoint.com/2017/05/23/hacked-in-translation/
    [2] https://www.nolimitsecu.fr/software-sandboxing/ (in French)

