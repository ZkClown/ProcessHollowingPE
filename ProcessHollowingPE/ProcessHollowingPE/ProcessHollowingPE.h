#pragma once

#include <iostream>
#include <Windows.h>
#include <winternl.h>

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE ProcessHandle,
                                                    DWORD ProcessInformationClass,
                                                    PVOID ProcessInformation,
                                                    DWORD ProcessInformationLength,
                                                    PDWORD ReturnLength);


typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;