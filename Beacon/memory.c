#include "pch.h"

typedef struct RECORD
{
	char* ptr;
	size_t size;
} RECORD;

typedef struct RECORD_ENTRY
{
	RECORD record;
	int allocType;
	BOOL isHeap;
	void(__stdcall* callback)(void* Block);
} RECORD_ENTRY;


long long gRecordCount = 0;
long long gRecordCapacity = 0;
RECORD_ENTRY* gRecords;
BOOL gIsHeapFiltering = TRUE;
#define RECORD_CAPACITY_INCREMENT 25
void MemoryInsert(char* buffer, int length, int type, BOOL isHeap, void(* cleanupCallback)(void* block))
{
	if(gRecordCount + 1 >= gRecordCapacity)
	{
		if(gRecords)
		{
			gRecords = realloc(gRecords, sizeof(RECORD_ENTRY) * (gRecordCapacity + RECORD_CAPACITY_INCREMENT));
		} else
		{
			gRecords = malloc(sizeof(RECORD_ENTRY) * RECORD_CAPACITY_INCREMENT);
		}
		memset(&gRecords[gRecordCapacity], 0, sizeof(RECORD_ENTRY) * RECORD_CAPACITY_INCREMENT);
		gRecordCapacity += RECORD_CAPACITY_INCREMENT;
	}

	gRecords[gRecordCount] = (RECORD_ENTRY) {
		.record = {
			.ptr = buffer,
			.size = length
		},
		.allocType = type,
		.isHeap = isHeap,
		.callback = cleanupCallback
	};

	gIsHeapFiltering = gIsHeapFiltering || isHeap;
	gRecordCount++;
}