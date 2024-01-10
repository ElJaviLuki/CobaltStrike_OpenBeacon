#include "pch.h"

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

#define CHANNEL_TYPE_BIND 2

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