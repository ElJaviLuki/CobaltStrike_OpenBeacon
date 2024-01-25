#include "pch.h"

typedef struct WEB_RESPONSE
{
	SOCKET socket;
	int contentLength;
	int headerLength;
	char* content;
	char* header;
	char* data;
} WEB_RESPONSE, *PWEB_RESPONSE;

WEB_RESPONSE* WebResponseInit(SOCKET socket, char* content, int contentLength)
{
#define MAX_HEADER_SIZE 0x100
#define MAX_DATA_SIZE 0x800
	WEB_RESPONSE* webResponse = malloc(sizeof(WEB_RESPONSE));
	webResponse->socket = socket;

	webResponse->content = malloc(contentLength);
	webResponse->contentLength = contentLength;
	memcpy(webResponse->content, content, contentLength);

	webResponse->header = malloc(MAX_HEADER_SIZE);
	snprintf(webResponse->header,
		MAX_HEADER_SIZE,
		"HTTP/1.1 200 OK\r\n"
		       "Content-Type: application/octet-stream\r\n"
		       "Content-Length: %d\r\n\r\n",
		contentLength);
	webResponse->headerLength = strlen(webResponse->header);

	webResponse->data = malloc(MAX_DATA_SIZE);
}
