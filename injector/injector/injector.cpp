#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>


void InjectDLL(DWORD pid, const char* dllPath) {
	// Open the target process with necessary permissions
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("Could not open process: %d\n", GetLastError());
		return;
	}

	// Allocate memory in the target process for the DLL path
	void* pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pDllPath == NULL) {
		printf("Could not allocate memory: %d\n", GetLastError());
		CloseHandle(hProcess);
		return;
	}

	// Write the DLL path into the allocated memory
	if (!WriteProcessMemory(hProcess, pDllPath, (void*)dllPath, strlen(dllPath) + 1, NULL)) {
		printf("Could not write process memory: %d\n", GetLastError());
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	// Get the address of LoadLibraryA in kernel32.dll
	LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pLoadLibrary == NULL) {
		printf("Could not find LoadLibrary: %d\n", GetLastError());
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	// Create a remote thread to load the DLL
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
	if (hThread == NULL) {
		printf("Could not create remote thread: %d\n", GetLastError());
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	// Wait for the DLL to be loaded
	WaitForSingleObject(hThread, INFINITE);

	// Cleanup
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	printf("DLL injected successfully into PID: %lu\n", pid);
}



// Helper function, looking for all Notepad instances to inject the DLL into.
void InjectAllNotepadInstances(const char* dllPath) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (_stricmp(entry.szExeFile, "notepad.exe") == 0) {
				InjectDLL(entry.th32ProcessID, dllPath);
			}
		}
	}

	CloseHandle(snapshot);
}


int main(int argc, char *argv[]) {

	char dllPath[] = "PATH_TO_APIHooking.dll";

	if (argc == 2) {
		DWORD pid = (DWORD)atoi(argv[1]);
		InjectDLL(pid, dllPath);
	}

	else {
		printf("Usage: injector.exe <PID>\n");
	}

	return 0;
}
