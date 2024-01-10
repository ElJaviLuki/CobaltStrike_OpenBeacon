#include "pch.h"

#include "filesystem.h"

#include "beacon.h"

void FilesystemCd(char* buffer, int length)
{
	char path[1024];

	if (length > sizeof(path))
		return;

	strncpy(path, buffer, length);
	path[length] = '\0';

	SetCurrentDirectoryA(path);
}

void FilesystemPwd()
{
	char data[2048];
	int length = GetCurrentDirectoryA(sizeof(data), data);
	if (length == 0)
		return;
	BeaconOutput(CALLBACK_PWD, data, length);
}

void FilesystemMkdir(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	char* path = BeaconDataStringPointerCopy(&parser, 0x4000);

	// Create the directory
	CreateDirectoryA(path, NULL);

	free(path);
}

void FilesystemMove(char* buffer, int length)
{
#define MAX_SRC 0x2000
#define MAX_DST 0x2000
	datap* locals = BeaconDataAlloc(MAX_SRC + MAX_DST);
	char* src = BeaconDataPtr(locals, MAX_SRC);
	char* dst = BeaconDataPtr(locals, MAX_DST);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	BeaconDataStringCopySafe(&parser, src, MAX_SRC);
	BeaconDataStringCopySafe(&parser, dst, MAX_DST);

	// Move the file
	if(!MoveFileA(src, dst))
	{
		DWORD lastError = GetLastError();
		LERROR("Move failed: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_MOVE_FAILED, lastError);
	}

	BeaconDataFree(locals);
}