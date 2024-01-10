#include "pch.h"

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