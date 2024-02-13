#include "Utils.h"

BOOL readPipe(HANDLE hPipe, PVOID* data, PDWORD dataLen)
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
				return FALSE;
			}
		}
	}
	else
	{
		_err("[SMB] PeekNamedPipe: Failed[%d]\n", GetLastError());
		CloseHandle(hPipe);
		return FALSE;
	}


	*dataLen = bytesSize;
	return TRUE;
}


BOOL loadPEFromDisk(LPCSTR peName, LPVOID& peContent)
{
	HANDLE hPe = NULL;
	hPe = CreateFileA(peName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hPe == INVALID_HANDLE_VALUE || !hPe)
	{

		_err("[-] Error PE to load does not exist: %x\r\n", GetLastError());
		return FALSE;

	}
	DWORD peSize = GetFileSize(hPe, NULL);

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

BOOL launchSuspendedProcess(LPSTR processName, LPPROCESS_INFORMATION pi,  HANDLE& hStdOutPipeRead, HANDLE& htStdInPipeWrite)
{
	HANDLE hStdOutPipeWrite = NULL;
	HANDLE hStdInPipeRead = NULL;



	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	STARTUPINFOA si = { 0 };


	//Creating Pipe for output of exe
	if (!CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0))
	{
		_err("[CMD] Failed Output pipe: %x\r\n", GetLastError());
		return FALSE;
	}
	if (!CreatePipe(&hStdInPipeRead, &htStdInPipeWrite, &sa, 0))
	{
		_err("[CMD] Failed Input pipe %x\r\n", GetLastError());
		return FALSE;
	}

	//Redirection STDOUT/STDERR into pipe
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdError = hStdOutPipeWrite;
	si.hStdOutput = hStdOutPipeWrite;
	si.hStdInput = hStdInPipeRead;
	if (!CreateProcessA(processName, processName, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, pi))
	{
		_err("[-] ERROR: Cannot create process %s\r\n", processName);
		return FALSE;
	}
	_dbg("[+] Launching process %s with PID: %d\r\n", processName, pi->dwProcessId);
	return TRUE;
}