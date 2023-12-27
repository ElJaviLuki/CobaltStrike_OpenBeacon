#include "pch.h"

#include "beacon.h"

void BeaconDataParse(datap * parser, char * buffer, int size) {
	*parser = (datap){ buffer, buffer, size, size };
}

char* BeaconDataPtr(datap* parser, int size)
{
	if (parser->length < size)
		return NULL;

	char* data = parser->buffer;

	parser->length -= size;
	parser->buffer += size;

	return data;
}

int BeaconDataInt(datap* parser)
{
	if (parser->length < sizeof(int))
		return 0;

	int data = ntohl(*(int*)parser->buffer);

	parser->length -= sizeof(int);
	parser->buffer += sizeof(int);

	return data;
}

short BeaconDataShort(datap* parser)
{
	if (parser->length < sizeof(short))
		return 0;

	short data = ntohs(*(short*)parser->buffer);

	parser->length -= sizeof(short);
	parser->buffer += sizeof(short);

	return data;
}

char BeaconDataChar(datap* parser)
{
	if (parser->length < sizeof(char))
		return 0;

	char data = *(char*)parser->buffer;

	parser->length -= sizeof(char);
	parser->buffer += sizeof(char);

	return data;
}

char* BeaconDataOriginal(datap* parser)
{
	return parser->original;
}

int BeaconDataLength(datap* parser)
{
	return parser->length;
}

void BeaconDataSizedBuffer(datap* parser, sizedbuf* sb)
{
	int size = BeaconDataInt(parser);
	char* data = BeaconDataPtr(parser, size);

	*sb = (sizedbuf){ data, size };
}

char* BeaconDataExtract(datap* parser, int* size)
{
	sizedbuf sb;
	BeaconDataSizedBuffer(parser, &sb);

	if(size)
		*size = sb.size;

	if (sb.size == 0)
		return NULL;

	return sb.buffer;
}

void BeaconFormatAlloc(formatp* format, int maxsz)
{
	char* buffer = (char*)malloc(maxsz);
	*format = (formatp){ buffer, buffer, 0, maxsz };
}

void BeaconFormatReset(formatp* format)
{
	*format = (formatp){ format->original, format->original, 0, format->size };
}

void BeaconFormatAppend(formatp* format, char* text, int len)
{
	if(format->size - format->length >= len)
		return;

	if (len == 0)
		return;

	memcpy(format->buffer, text, len);
	format->buffer += len;
	format->length += len;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	int len = vsnprintf(format->buffer, format->size - format->length, fmt, args);
	format->buffer += len;
	format->length += len;

	va_end(args);
}

char* BeaconFormatToString(formatp* format, int* size)
{
	if(!size)
		return NULL;

	*size = BeaconDataLength(format);
	return BeaconDataOriginal(format);
}

void BeaconFormatFree(formatp* format)
{
	/* note: we don't force memzero the buffer explicitly, as free is already overwritten to do that */
	free(format->original);
}

void BeaconFormatInt(formatp* format, int value)
{
	value = htonl(value);
	BeaconFormatAppend(format, (char*)&value, sizeof(int));
}

void BeaconFormatShort(formatp* format, short value)
{
	value = htons(value);
	BeaconFormatAppend(format, (char*)&value, sizeof(short));
}

void BeaconFormatChar(formatp* format, char value)
{
	BeaconFormatAppend(format, (char*)&value, sizeof(char));
}
