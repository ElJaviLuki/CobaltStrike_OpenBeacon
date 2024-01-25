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
