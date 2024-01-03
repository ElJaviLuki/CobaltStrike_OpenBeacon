#include "pch.h"

BOOL gNetworkIsInit = FALSE;

void NetworkInit(void)
{
	if (gNetworkIsInit)
		return;

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		WSACleanup();
		exit(1);
	}

	// FIXME: DNS Settings here...

	gNetworkIsInit = TRUE;
}