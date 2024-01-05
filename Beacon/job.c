#include "pch.h"



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


DWORD gJobCurrentId = 0;
JOB_ENTRY* gJobs = NULL;

JOB_ENTRY* JobAdd(JOB_ENTRY* newJob)
{
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
