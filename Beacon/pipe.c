#include "pch.h"

BOOL PipeConnect(LPCSTR lpFileName, HANDLE* pipe, DWORD flags)
{
	while(TRUE)
	{
		*pipe = CreateFileA(lpFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, flags, NULL);
		if (*pipe != INVALID_HANDLE_VALUE)
		{
			DWORD mode = PIPE_READMODE_BYTE;
			if (!SetNamedPipeHandleState(*pipe, &mode, NULL, NULL))
			{
				DisconnectNamedPipe(*pipe);
				CloseHandle(*pipe);
				return FALSE;
			}

			return TRUE;
		}

		// If the file is not found, wait for it to be created
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			return FALSE;
		}

		if (!WaitNamedPipeA(lpFileName, 10000))
		{
			SetLastError(WAIT_TIMEOUT);
			return FALSE;
		}
	}
}