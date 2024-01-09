#include "pch.h"

#include "argument.h"

#include "beacon.h"

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

ARGUMENT_ENTRY* ArgumentFindOrCreate(char* expanded)
{
	for (ARGUMENT_ENTRY* current = gArguments; current != NULL; current = current->next)
	{
		if (!current->isActive && strcmp(expanded, current->expandedCmd) == 0)
			return current;
	}

	ARGUMENT_ENTRY* current = gArguments;

	while(current && current->isActive)
		current = current->next;

	ARGUMENT_ENTRY* argument;
	if (!current)
	{
		// Create a new entry for the new argument
		argument = (ARGUMENT_ENTRY*)malloc(sizeof(ARGUMENT_ENTRY));
		*argument = (ARGUMENT_ENTRY){ .isActive = FALSE, .expandedCmd = NULL, .expandedFullCmd = NULL, .next = current };
		gArguments = argument;
	} else
	{
		// Reuse this entry for the new argument
		argument = current;
	}

	return argument;
}