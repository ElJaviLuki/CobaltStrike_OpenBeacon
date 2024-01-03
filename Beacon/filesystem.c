#include "pch.h"

#include "filesystem.h"

void FilesystemCd(char* buffer, int length)
{
	char path[1024];

	if (length > sizeof(path))
		return;

	strncpy(path, buffer, length);
	path[length] = '\0';

	SetCurrentDirectoryA(path);
}