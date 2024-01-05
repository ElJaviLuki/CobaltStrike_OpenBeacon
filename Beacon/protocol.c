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
