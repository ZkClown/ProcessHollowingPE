#pragma once

#include <Windows.h>
#include <winternl.h>

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


BOOL readPipe(HANDLE hPipe, PVOID* data, PDWORD dataLen);

BOOL loadPEFromDisk(LPCSTR peName, LPVOID& peContent);

BOOL launchSuspendedProcess(LPSTR processName, LPPROCESS_INFORMATION pi, HANDLE & hStdOutPipeRead, HANDLE & htStdInPipeWrite);

PCHAR strConcat(PCHAR str1, PCHAR str2);

PWSTR strToWstr(PCHAR str);