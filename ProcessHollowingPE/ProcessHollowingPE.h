#pragma once

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma once

#ifdef _DEBUG
#include <stdio.h>

#define DBG "DBG"
#define ERR "ERR"
#define WRN "WRN"
#define INF "INF"

#define _log(level, format, ...) printf("[%s] %s:%d - " format, level, __FUNCTION__, __LINE__, ## __VA_ARGS__);
#define _dbg(format, ...) _log(DBG, format, ## __VA_ARGS__)
#define _err(format, ...) _log(ERR, format, ## __VA_ARGS__)
#define _wrn(format, ...) _log(WRN, format, ## __VA_ARGS__)
#define _inf(format, ...) _log(INF, format, ## __VA_ARGS__)
#else
#define DBG
#define ERR
#define WRN
#define INF
#define _log(level, format, ...)
#define _dbg(format, ...)
#define _err(format, ...)
#define _wrn(format, ...)
#define _inf(format, ...)
#endif

#define DATA_FREE( d, l ) \
    if ( d ) \
    { \
        memset( d, 0, l ); \
        LocalFree( d ); \
        d = NULL; \
    }


typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, LPCVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, LPTHREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* _NtThreadContext)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* _NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);


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

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _API_SET_HASH_ENTRY {
	ULONG Hash;
	ULONG Index;
} API_SET_HASH_ENTRY, * PAPI_SET_HASH_ENTRY;

typedef struct _API_SET_NAMESPACE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG HashedLength;
	ULONG ValueOffset;
	ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, * PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_VALUE_ENTRY {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, * PAPI_SET_VALUE_ENTRY;


typedef struct _PE_SECTION
{
	PIMAGE_SECTION_HEADER header;
	PVOID addrSection;
}PE_SECTION, * PPE_SECTION;

typedef struct _PE_STRUCT
{
	PVOID imageBase;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PVOID* dataDirectories;
	PPE_SECTION sections;

} PE_STRUCT, * PPE_STRUCT;
