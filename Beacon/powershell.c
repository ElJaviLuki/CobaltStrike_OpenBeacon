#include "pch.h"

#include "powershell.h"

char* gImportedPshScript;

char* PowershellImport(char* buffer, int size)
{
	if (gImportedPshScript)
		free(gImportedPshScript);

	gImportedPshScript = (char*)malloc(size + 1);
	memcpy(gImportedPshScript, buffer, size);
	gImportedPshScript[size] = 0;
	return gImportedPshScript;
}