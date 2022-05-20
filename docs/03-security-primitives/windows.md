# Identities

Several types of objects can have distinct identities: local users, users from an Active Directory domain if the computer is federated into one, service processes running in the background, etc.
All identities are identified by their **Security IDentifiers (SID)**, a list of integers split hierarchically in the form:

	S-<revision number, must be 1>-<authority>[-<subauthority>]*-<relative ID>

Lots of SIDs are so-called **well-known**[3], meaning they are the same across all Windows hosts. A common example is S-1-5-18 (LocalSystem, the most privileged identity used by the operating system itself).

# Mandatory Access Control model



# Discretionary Access Control model

Windows represents most data exposed to userland processes in the form of **objects**, a kernel data structure which provides userland references in the form of **handles** (indexes in a per-process table of pointers).

Most object types (files, registry keys, processes themselves, etc.) are **securable objects**[2]: they can have a **security descriptor** attached, a structure describing (among other things) the owner and a **discretionary access control list** (DACL). Ownership gives the right to modify the DACL, to keep access to the object in all cases. ACLs contain zero to many **access control entries** (ACE), each containing a **trustee** (a SID) and a list of access rights to grant or deny.

When a handle is requested by userland, a list of access rights is requested too, and ACEs are scanned in order until all requested rights have been granted or until one right has been denied. Each handle is stored alongside its list of granted access rights, and no further rights can be granted, so access checks when performing operations on that handle are simple bitwise AND comparisons with the granted access mask.

Some types are **unsecurable objects**, meaning their security descriptor is always a NULL pointer: all access rights are systematically granted to anyone.

# Non-Discretionary Access Control

Not all sensitive operations on a system are performed on objects with a security descriptor. For each of these operations, a **privilege**[4] to perform it can be granted to some users, according to a policy defined by local administrators.

Privileges are added in some Windows releases. Ways are publicly documented to abuse some of them in order to acquire more privileges. These privileges can, by definition, never be safely granted to a sandboxed process:

- SeAssignPrimaryTokenPrivilege: set the token of child processes to any token opened with the `TOKEN_DUPLICATE` right[5];
- SeAuditPrivilege: append entries in the system's Security event log. This can be abused to fool investigations or to remove entries from the Security log by appending a large number of entries to overwrite older ones;
- SeBackupPrivilege: read any file or registry key, bypassing any discretionary and mandatory access control, including reading authentication secrets of administrators from the HKLM\SAM and HKLM\SYSTEM and open a network session as Administrator;
- SeCreatePagefilePrivilege: create and remove a pagefile, which can later be used to read memory from the kernel or other processes;
- SeCreateTokenPrivilege: create a token containing arbitrary SIDs to impersonate anyone;
- SeDebugPrivilege: open processes with arbitrary access rights, which can be used to inject malware into processes running as LocalSystem;
- SeEnableDelegationPrivilege: only present on Active Directory domain controllers, allows enabling Kerberos delegation on any domain account, which in turns can be used to compromise the entire Active Directory and the domain controller itself;
- SeLoadDriverPrivilege: load a kernel driver (which still needs to pass signing requirements, depending on Windows version and configuration), including a vulnerable one (e.g. CVE-2018-15732) to exploit its vulnerability;
- SeImpersonatePrivilege: set the impersonation token of a thread to any token opened with the `TOKEN_IMPERSONATE` right[5];
- SeManageVolumePrivilege: send the `FSCTL_SD_GLOBAL_CHANGE` to change the security descriptor of the root of the system volume, to modify system files and configuration and elevate to LocalSystem;
- SeRestorePrivilege: write to any file or registry key and replace their security descriptor with anything, including e.g. changing a privileged service configuration in the registry;
- SeRelabelPrivilege: grants the ability to lower the mandatory integrity label of any resource except System, but also to change the owner of any resource like SeTakeOwnershipPrivilege[7];
- SeTakeOwnershipPrivilege: set oneself as the owner of any file and registry key, which in turns grants the implicit right to modify the DACL, which grants the same rights as SeBackupPrivilege and SeRestorePrivilege combined;
- SeSystemEnvironmentPrivilege: change firmware variables, such as Windows boot options, to lower security settings at the next boot;
- SeTrustedCredManAccessPrivilege: read any user's saved credentials for websites, file shares, other computers, etc.
- SeTcbPrivilege: raise the integrity level of a token to System;
- SeSyncAgentPrivilege: only present on Active Directory domain controllers, allows replicating all objects and attributes including administrator secrets;

Other privileges may be granted to a sandboxed process without trivially breaking its security model, if they are required:

- SeIncreaseBasePriorityPrivilege: set the priority class of the current process above High, e.g. to Real-time which preempts the operating system and can freeze the entire computer;
- SeCreateGlobalPrivilege: create objects outside the session-specific object namespace;
- SeCreatePermanentPrivilege: create an object which is not destroyed when all handles pointing to it are closed;
- SeCreateSymbolicLinkPrivilege: create symbolic links, which can be used to trick privileged processes into leaking or modifying the contents of sensitive files. Support for unprivileged symbolic link creation is a work in progress since Windows 10 1703, when Windows is booted in developer mode[6];
- SeDelegateSessionUserImpersonatePrivilege: 
- SeIncreaseQuotaPrivilege: 
- SeIncreaseWorkingSetPrivilege: 
- SeLockMemoryPrivilege: 
- SeMachineAccountPrivilege: only present on Active Directory domain controllers, allows joining new computers to the domain;
- SeRemoteShutdownPrivilege: shut down the computer, even when logged in a session of type 3 (network logon)
- SeSecurityPrivilege: replace the auditing rules on any object, for instance to disable auditing of some privileges actions;
- SeShutdownPrivilege: shut down the computer;
- SeProfileSingleProcessPrivilege: 
- SeSystemProfilePrivilege: 
- SeSystemtimePrivilege: change the date and time for the entire computer, can be abused to hide log entries by setting a date far in the past;
- SeTimeZonePrivilege: change the time zone for the entire user session;
- SeUndockPrivilege: unused as far as documentation goes;
- SeUnsolicitedInputPrivilege: unused as far as documentation goes;

# Access tokens

Each user, when logging in, is given a **token** containing their SID, and a list of groups to which 

Whenever a user logs in, a new Session object is created for them, and a Token object is given to the first process in the session. Every time a child process is created, a (possibly modified) copy of that token is given to the child. These tokens contain all the information about their processes' ambient authority, they are what's checked when performing privileged operations.

Each token contains (you can see this using e.g. Sysinternals Process Explorer):
- a primary user, identified by SID ;
- a primary group, identified by SID (this is a deprecated feature of the POSIX subsystem, not used anymore) ;
- a list of groups, identified by SID ;
	- each group can be enabled (taken into account when checking access), or disabled (not taken into account, mostly unused setting), or mandatory (enabled and cannot be disabled, the default for most groups) ;
	- each group can be a **restricted SID**: when at least one restricted SID
- a list of privileges, identified by LUID (Locally Unique IDentifier) ;
	- each privilege can be enabled (taken into account when checking access), or disabled (the default for sensitive privileges, so they have to be enabled manually to avoid e.g. using the *SeRestorePrivilege* to overwrite a system file when all we wanted to do was write to a log file) ;

Access tokens cannot be edited freely for sandboxing purposes: only when creating a derived token (see Restricted Tokens and AppContainers mitigations) can a SIDs be removed or integrity levels changed.

# Integrity level

[Mandatory Access Control](https://docs.microsoft.com/en-us/windows/desktop/secauthz/mandatory-integrity-control) in Windows is enforced through the use of **integrity levels** assigned to each and every object, in the form of a SID amongst the following predefined values (gaps are left for future added integrity levels):


## Restricted tokens

Introduced in Windows XP as a primitive way of sandboxing, a new type of token can be created and assigned to child processes by unprivileged processes using the [documented](https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken) `CreateRestrictedToken()` API and then the [documented](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) `CreateProcessAsUser()` API.

A restricted token contains:
- all SIDs of its parent token, but some can also be set to `DENY_ONLY` ;
- all privileges of its parent token, but they can also be removed ;
- optionally, a list of **restricted SIDs**, all of which are permanently enabled, can only be removed (not appended), and will be checked in parallel of the main SID list in all access checks. Both access checks will now have to succeed before any access is granted.

# Access check

When an operation is performed on a securable object, the `SeAccessCheck()` (https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-seaccesscheck)  method is called in the kernel and returns true or false to indicate if the user can be granted the rights they requested. At each step, if any of the access rights requested is denied, the access check returns false immediately.

1. If token integrity level < objet integrity level? If so, apply the object's MAC policy: no read up? no write up? no exec up?
2. Token user == object owner? If so, grant `WRITE_DAC` and continue
3. Is there a DACL? If not, grant access
4. Is there at least one restricted SID in the DACL? If so, do an access check with restricted SIDs only. If it fails, deny access
5. For each ACE in the DACL, if the trustee SID is the user or is held and enabled in the token groups, apply the ACE's action to the ACE's access mask



# Windows Sandboxing Primitives

## Discretionary Access Control overview

## Jobs

## Windowing system isolation

## Restricted Tokens

## AppContainers

## Less-Privileged AppContainers

File access can be restricted in a new process by creating it with a restricted token (`CreateRestrictedToken()`) or with an AppContainer token (`CreateProcess()` with `STARTUPINFOEXA.lpAttributeList` specifying `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`). However, both these methods lack granularity:

- When using restricted tokens, SIDs specific to the current user cannot be disabled, since doing so would prevent any file access in e.g. their home directory. Thus, a restricted SID needs to be added, only allowing access to files allowed by policy, but this requires modifying the security descriptor of each file and directory. This is not possible for files the user can only read and not modify.

- When using AppContainers, file and directory access is restricted to only those which explicitly grant access to `All Application Packages` (or even `All Restricted Application Packages` when using Less-Privileged AppContainers). Thus, this requires modifying the security descriptor of each file and directory, and is not possible for the same reason.

=> The only way to restrict access to files and directories based on their path is to remove all filesystem access, and intercept functions which operate on these resources by path to forward each request to a privileged broker.

- Using the WinRT broker?
	=> requires reversing, or creating a minimal WinRT app. But the entire WinRT ecosystem seems to be abandonned by Microsoft (was supposed to be "Windows 10X" but they moved on to Windows 11)

## Network

- Three capabilities control network access from within an AppContainer:
	internetClient - Grants client access to the Internet
	internetClientServer - Grants client and server access to the Internet
	privateNetworkClientServer - Grants client and server access to local private networks.


## Process Mitigation Options

- ForceASLR 0x100 see https://support.microsoft.com/fr-fr/topic/an-update-is-available-for-the-aslr-feature-in-windows-7-or-in-windows-server-2008-r2-aec38646-36f1-08e8-32d2-6374d3c83d9e
	- even more: [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]  "MitigationOptions"=hex:00,01,01,00,00,00,00,00,00,00,00,00,00,00,00,00
	(otherwise, "forcing ASLR" only forces a relocation by simulating base address conflict, and does not randomize dynamic allocations. [https://msrc-blog.microsoft.com/2017/11/21/clarifying-the-behavior-of-mandatory-aslr/])

# Sources

	[1] The Windows Sandbox Paradox, James Forshaw, 2015 https://nullcon.net/website/archives/goa-2015.php
	[2] https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects
	[3] https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	[4] https://docs.microsoft.com/en-us/windows/desktop/secauthz/privilege-constants
	[5] https://github.com/ohpe/juicy-potato
	[6] https://blogs.windows.com/windowsdeveloper/2016/12/02/symlinks-windows-10/
	[7] https://www.tiraniddo.dev/2021/06/the-much-misunderstood.html
