#include "pch.h"

HANDLE ProtocolSmbPipeRead(HANDLE channel, char* buffer, int length)
{
	DWORD totalRead = 0;

	if (length <= 0)
	{
		if (totalRead != length)
			totalRead = -1;

		return totalRead;
	}

	DWORD read = 0;
	while (ReadFile(channel, &buffer[totalRead], length - totalRead, &read, NULL) && !read && totalRead < length) {
		totalRead += read;
	}

	return -1;
}

BOOL ProtocolSmbPipeWrite(HANDLE hFile, char* buffer, int length)
{
    DWORD wrote;

    // Check if size is greater than 0
    for (DWORD totalWrote = 0; totalWrote < length; totalWrote += wrote) {
        // Calculate the number of bytes to be written in the current iteration
        const DWORD toWrite = min(length - totalWrote, 0x2000);


        // Check if the write operation was successful
        if (!WriteFile(hFile, buffer + totalWrote, toWrite, &wrote, NULL)) {
            return FALSE;
        }
    }

    return TRUE;
}

