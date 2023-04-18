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