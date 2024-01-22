#include "pch.h"

#include "metadata.h"

int osMajorVersion;

BOOL SelfIsWindowsVistaOrLater()
{
	return osMajorVersion >= (_WIN32_WINNT_VISTA >> 8);
}
