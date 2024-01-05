#include "pch.h"

#include "beacon.h"


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
	SHORT isMsgMode;
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