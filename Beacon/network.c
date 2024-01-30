#include "pch.h"

#include "network.h"

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

ULONG NetworkGetActiveAdapterIPv4()
{
	SOCKET sock = WSASocketA(AF_INET, SOCK_DGRAM, 0, NULL, 0, 0);
	if (sock == INVALID_SOCKET)
	{
		return 0;
	}

	DWORD bytesReturned;
	int numInterfaces = 0;
	INTERFACE_INFO interfaceInfo[20];
	if (!WSAIoctl(sock, SIO_GET_INTERFACE_LIST, NULL, 0, interfaceInfo, sizeof(interfaceInfo), &bytesReturned, NULL, NULL))
	{
		numInterfaces = bytesReturned / sizeof(INTERFACE_INFO);
	}

	for (int i = 0; i < numInterfaces; i++)
	{
		if (!(interfaceInfo[i].iiFlags & IFF_LOOPBACK) && interfaceInfo[i].iiFlags & IFF_UP)
		{
			closesocket(sock);
			return interfaceInfo[i].iiAddress.AddressIn.sin_addr.s_addr;
		}
	}

	closesocket(sock);
	return 0;
}