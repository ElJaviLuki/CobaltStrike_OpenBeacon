#include "pch.h"

#include "argument.h"

typedef struct _ARGUMENT_ENTRY
{
	BOOL isActive;
	const char expandedCmd[8192];
	const char expandedFullCmd[8192];
	struct _ARGUMENT_ENTRY* next;
} ARGUMENT_ENTRY;

ARGUMENT_ENTRY* gArguments = NULL;

BOOL ArgumentFindMatch(EXPANDED_CMD* extendedCmd, const char* cmd)
{
	for (const ARGUMENT_ENTRY* current = gArguments; current != NULL; current = current->next)
	{
		if (current->isActive && strstr(cmd, current->expandedCmd) == cmd)
		{
			*extendedCmd = (EXPANDED_CMD) { current->expandedFullCmd, current->expandedCmd };
			return TRUE;
		}
	}

	return FALSE;
}
