#include <windows.h>
#include <psapi.h>
#include <iostream>



bool UnloadDll(DWORD processID, const char* libraryPath) {
	// Attempt to open the target process with full access
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (processHandle == NULL) {
		return false; // Failed to open process
	}

	// Find the filename part of the library path
	const char* libraryName = strrchr(libraryPath, '\\');
	if (libraryName != NULL) {
		libraryName++; // Move past the backslash
	}
	else {
		libraryName = libraryPath; // No backslash found, use the full path
	}

	// Get a handle to kernel32.dll
	HMODULE kernel32Handle = GetModuleHandle("Kernel32.dll");
	if (kernel32Handle == NULL) {
		CloseHandle(processHandle);
		return false; // Failed to get handle to Kernel32.dll
	}

	// Get the address of the FreeLibrary function
	PVOID freeLibraryAddress = (PVOID)GetProcAddress(kernel32Handle, "FreeLibrary");
	if (freeLibraryAddress == NULL) {
		CloseHandle(processHandle);
		return false; // Failed to get address of FreeLibrary
	}

	// Enumerate modules in the target process
	HMODULE modules[1024];
	DWORD bytesNeeded;
	if (EnumProcessModules(processHandle, modules, sizeof(modules), &bytesNeeded)) {
		for (DWORD i = 0; i < (bytesNeeded / sizeof(HMODULE)); i++) {
			CHAR moduleName[MAX_PATH];
			if (GetModuleBaseNameA(processHandle, modules[i], moduleName, MAX_PATH)) {
				// Compare module name to the library name
				if (_stricmp(moduleName, libraryName) == 0) {
					// Create a thread in the target process to call FreeLibrary
					HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)freeLibraryAddress, (LPVOID)modules[i], 0, NULL);

					if (threadHandle != NULL) {
						WaitForSingleObject(threadHandle, INFINITE);
						CloseHandle(threadHandle);
					}

					CloseHandle(processHandle);
					return true; // Library released successfully
				}
			}
		}
	}

	CloseHandle(processHandle);
	return false; // Library not found or other failure
}



int main(int argc, char *argv[]) {

	const char* DllPath = "C:\\Users\\ISE\\source\\repos\\APIHooking\\x64\\Debug\\APIHooking.dll";

	if (argc == 2) {
		DWORD dwProcID = (DWORD)atoi(argv[1]);
		if (UnloadDll(dwProcID, DllPath)) {
			std::cout << "Successfully returns the target hooked process " << dwProcID << " to the normal behavior!" << std::endl;
		}
		else {
			std::cout << "Failed to reverts to the normal behavior." << std::endl;
		}
	}

	else {
		printf("Usage: hideInject.exe <PID>\n");
	}

	return 0;
}