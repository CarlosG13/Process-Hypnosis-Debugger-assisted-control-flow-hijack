# Process Hypnosis: Debugger assisted control flow hijack

One of the most common techniques employed by attackers for evading defenses is **Process Injection**. The idea is to execute arbitrary malicious code in the address space of a target process, in order to evade process-based defenses and, possibly, even elevate privileges.

The **classic technique** of process injection is as follows: A malicious program (**Loader**) requests a handle of a target process (legitimate program to be injected) via the Win32 API *OpenProcess*. Then, it reserves a memory region via *VirtualAllocEx*, writes the malicious code using *WriteProcessMemory*, and creates a new execution thread with *CreateRemoteThread*:

![1 kxs_gK_tV82GTjx4VntZxg](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/65e2f6bd-60ca-42c3-893c-c88f0f100851)

[Image retrived from "On Detection: Tactical to Functional by Jared Atkinson"](https://posts.specterops.io/on-detection-tactical-to-functional-f37c9b0b8874)

This pattern/behavior is already well-known. It's a practically trivial task for a good Antivirus and/or EDR to detect and stop malicious artifacts based on this classic technique. For this reason, multiple effective evasion techniques have emerged that have refined this concept of classic process injection, such as:

1. Injecting to Remote Process via Thread Hijacking *(SetThreadContext)*.
2. APC Queue Code Injection.
3. Process Hollowing and Portable Executable Relocations.
4. And others.

Techniques like **Process Hollowing** were very effective at one point, and indeed, they may still be used against certain Anti-Malware solutions/products. However, generally speaking, it's a technique that EDRs are quite familiar with. The moment we create a process *(CreateProcessW)* in a **suspended** state *(CREATE_SUSPENDED)*, it's a very distinctive indicator/trait that could potentially signify the initiation of a technique like **Process Hollowing** or similar ones.

### Process Hypnosis Pt.1 - Concept

![image](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/58a2c722-4f15-455c-87cc-a292aa0035fd)

As an alternative to well-known **Process Injection** techniques, during my studies and research on Windows internals, I discovered that it's not necessary to rely on common API calls like *GetModuleHandle* to obtain the base address of a module or *GetProcAddress* to obtain the address of a function exported by a DLL. Typically, advanced malware developers nowadays implement their own customized versions of *GetModuleHandle* and *GetProcAddress*. However, with this new approach, we'll explore alternatives to both functions. Moreover, this approach doesn't require us to allocate space in the remote process with *VirtualAllocEx*, and we could even dispense with flags like *CREATE_SUSPENDED* (which is well-known) and APIs like ResumeThread, CreateRemoteThread, and similar ones.

The fundamental idea is that we develop a malicious artifact that behaves like a debugger. As a result, we gain the ability to control the execution flow of a program being debugged and obtain relevant information from it, such as: creation of new threads, loaded modules, exceptions, and more.

### Process Hypnosis Pt.2 - Freeze

Before explaining how Process Hypnosis works, we must understand a fundamental concept of Windows: **Freeze**.

According to **Windows Internals 7th Edition**: *"Freezing is a mechanism by which processes enter a suspended state that cannot be changed by calling ResumeThread on threads in the process... A flag in the KTHREAD structure indicates whether a thread is frozen. For a thread to be able to execute, its suspend count must be 0 and the frozen flag must be clear."*

The functionality of freezing a process or thread is not directly exposed in user mode. However, it's possible to freeze a process via **Jobs**, meaning by calling the Native function *NtSetInformationJobObject*. The ability to freeze and unfreeze a **Job**, though, is not publicly documented.

Debugging the Windows kernel, I realized that it is indeed possible to freeze and unfreeze a thread from user mode using functions intended for debugging purposes.

### Process Hypnosis Pt.3 - Steps to reproduce

**1.** The first step is to create a new process with *CreateProcessW*, but instead of using the *CREATE_SUSPENDED* flag, we'll use *DEBUG_ONLY_THIS_PROCESS*. As a result, we declare ourselves as the debugger for the new child process being created.

**IMPORTANT:** We could also utilize the *DEBUG_PROCESS* flag instead of *DEBUG_ONLY_THIS_PROCESS*. However, for our purpose, *DEBUG_PROCESS* is not necessary because we would not be fully leveraging all that this flag offers. The distinction lies in the fact that *DEBUG_PROCESS* is employed when we want to *debug a new process and any child processes it spawns*. In our use case, we do not intend to interact with or debug child processes, as *we will be injecting code directly into the new process*; therefore, *DEBUG_ONLY_THIS_PROCESS* is the optimal approach.

```cpp
wchar_t cmdLine[] = L"C:\\Windows\\System32\\mrt.exe";
CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, si, pi)
```

Due to the *DEBUG_ONLY_THIS_PROCESS* flag, the threads of the new process will be *frozen*. This works this way because the process has new **debugging events** pending to be sent.

At this point, it's possible to observe in action how the main thread is *frozen* just at the moment when the process to be debugged *(mrt.exe)* is created by placing a **BreakPoint** in the *'PsFreezeProcess'* function:

Likewise, we can see how the **'Frozen Count'** value is equal to **1**. Since the thread is *frozen*, it won't be possible to resume its execution via a function like *NtResumeThread*.

On the other hand, we observe that the function used to *unfreeze* is *'PsThawProcess'*, which is not publicly documented.

`bp nt!PsFreezeProcess "!process -1 0"`

![image](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/bb1efbc5-4b06-4ae4-a148-0aa59a896cef)


2. Then we receive the new events in the debugger (parent process) via the Win32 API *WaitForDebugEvent*:

```cpp
WaitForDebugEvent(DbgEvent, INFINITE)
```

Within the events, we have: 
    
  - **CREATE_PROCESS_DEBUG_EVENT:**  Reports a create-process debugging event (includes both a process and its main thread). The value of **u.CreateProcessInfo** specifies a **CREATE_PROCESS_DEBUG_INFO** structure. 

  - **CREATE_THREAD_DEBUG_EVENT:**  Reports a create-thread debugging event (does not include the main thread of a process, see `CREATE_PROCESS_DEBUG_EVENT`). The value of **u.CreateThread** specifies a **CREATE_THREAD_DEBUG_INFO** structure. 
  
  - **LOAD_DLL_DEBUG_EVENT:**  Reports a load-dynamic-link-library (DLL) debugging event. The value of **u.LoadDll** specifies a **LOAD_DLL_DEBUG_INFO** structure. 

  For more information, please visit the following link to Microsoft's official documentation: 
        [DEBUG_EVENT structure](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-debug_event)

3. What's interesting to note is that within the **CREATE_PROCESS_DEBUG_INFO** structure (populated when the process is created), it contains the address of the main thread of the process **(lpStartAddress)**:

```cpp
   typedef struct _CREATE_PROCESS_DEBUG_INFO {
  HANDLE                 hFile;
  HANDLE                 hProcess;
  HANDLE                 hThread;
  LPVOID                 lpBaseOfImage;
  DWORD                  dwDebugInfoFileOffset;
  DWORD                  nDebugInfoSize;
  LPVOID                 lpThreadLocalBase;
  LPTHREAD_START_ROUTINE lpStartAddress;
  LPVOID                 lpImageName;
  WORD                   fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;
```

4. Next, we can write our malicious code with *WriteProcessMemory*. Even though the thread's memory page we're modifying has read and execute permissions (RX), it isn't mandatory to call *VirtualProtectEx* to assign write permissions because *WriteProcessMemory* has the capability to directly call *NtProtectVirtualMemory* to change the page permissions for writing and then restore them to their original state:

```cpp
WriteProcessMemory(pi->hProcess, DbgEvent->u.CreateProcessInfo.lpStartAddress, buf, sizeof(buf), &writtenBytes
```

5. Even though we're aware that we can write and/or modify the code of the main thread or any other created thread, an important question arises: how do we unfreeze the thread and enable the flow of execution if *ResumeThread* alone cannot achieve this? The solution lies in *"DebugActiveProcessStop"*, a Win32 API capable of preventing our malicious debugger from debugging the specified process *(mrt.exe)*.

What we're achieving with *DebugActiveProcessStop* is detaching from the process we're debugging without the need to kill it; in other words, we simply let its execution flow continue. This way, we avoid the need for functions like *CreateRemoteThread*, *SetThreadContext*, among others.

```cpp
DebugActiveProcessStop(pi->dwProcessId)
```

### Process Hypnosis Pt.3 - Profit

In the following figure, we observe how it was possible to enumerate the different modules that were loaded into the remote process *(mrt.exe)* without the need for *GetModuleHandle* or a direct call to *LoadLibrary*. This was made possible thanks to the **LOAD_DLL_DEBUG_EVENT** event.

On the other hand, we appreciate how, by leveraging the Win32 API *SymFromName*, we can obtain the absolute address of the *CreateRemoteThread* function (this was a randomly selected function to demonstrate the concept), thereby eliminating *GetProcAddress* from the equation. Finally, we see relevant information concerning the new threads that are being created:

![image](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/6a6c3613-e49c-46af-9205-c2a6be9fa848)

![image](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/3b4cfe0a-58ad-4ab4-bc59-d5747f5b1123)

Finally, we can see how it's possible to execute our malicious code and perform an execution flow hijack by detaching ourselves from the process:

![image](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/3903251b-6168-4939-b887-5495ca8a87b6)

### Process Hypnosis Pt.4 - Attack Summary

![image](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/edf0f80e-b9db-46b4-8d62-dcd3282dcbd1)

### Process Hypnosis Pt.5 - What do we evade and achieve?

  * We can use *DEBUG_ONLY_THIS_PROCESS* as an alternative to the well-known *CREATE_SUSPENDED* flag.
    
  * We evade mechanisms such as *IAT* and *Inline Hooking*, as we avoid the use of well-known functions like *VirtualAllocEx*, *CreateRemoteThread*, *ResumeThread*, among others.

### Process Hypnosis Pt.6 - Detection

Based on my research, I identified a distinctive indicator that could be leveraged that could be leveraged to detect this type of attack. Essentially, when the process is being debugged, it invokes the function *"RtlQueryProcessDebugInformationRemote"*. The issue arises from the undocumented nature of this function (it is not referenced in any documentation).

![image](https://github.com/CarlosG13/Process-Hypnosis-Debugger-assisted-control-flow-hijack/assets/69405457/499b2bd2-d089-4f43-8922-dcdbfe44a336)


