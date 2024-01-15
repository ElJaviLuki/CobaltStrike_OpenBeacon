#pragma once
#include "beacon.h"

typedef struct bapi
{
	HMODULE (*fnLoadLibraryA)(LPCSTR lpLibFileName);
	BOOL (*fnFreeLibrary)(HMODULE hLibModule);
	FARPROC (*fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	HMODULE (*fnGetModuleHandleA)(LPCSTR lpModuleName);
	void (*fnBeaconDataParse)(datap* parser, char* buffer, int size);
	char*(*fnBeaconDataPtr)(datap* parser, int size);
	int (*fnBeaconDataInt)(datap* parser);
	short (*fnBeaconDataShort)(datap* parser);
	int (*fnBeaconDataLength)(datap* parser);
	char*(*fnBeaconDataExtract)(datap* parser, int* size);
	void (*fnBeaconFormatAlloc)(formatp* format, int maxsz);
	void (*fnBeaconFormatReset)(formatp* format);
	void (*fnBeaconFormatPrintf)(formatp* format, char* fmt, ...);
	void (*fnBeaconFormatAppend)(formatp* format, char* text, int len);
	void (*fnBeaconFormatFree)(formatp* format);
	char*(*fnBeaconFormatToString)(formatp* format, int* size);
	void (*fnBeaconFormatInt)(formatp* format, int value);
	void (*fnBeaconOutput)(int type, char* data, int len);
	void (*fnBeaconPrintf)(int type, char* fmt, ...);
	void (*fnBeaconErrorD)(int type, int d1);
	void (*fnBeaconErrorDD)(int type, int d1, int d2);
	void (*fnBeaconErrorNA)(int type);
	BOOL (*fnBeaconUseToken)(HANDLE token);
	BOOL (*fnBeaconIsAdmin)();
	void (*fnBeaconRevertToken)();
	void (*fnBeaconGetSpawnTo)(BOOL x86, char* buffer, int length);
	void (*fnBeaconCleanupProcess)(PROCESS_INFORMATION* pInfo);
	void (*fnBeaconInjectProcess)(HANDLE hProcess, int pid, char* payload, int p_len, int p_offset, char* arg,
	                              int a_len);
	BOOL (*fnBeaconSpawnTemporaryProcess)(BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pInfo);
	void (*fnBeaconInjectTemporaryProcess)(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset,
	                                       char* arg, int a_len);
	BOOL (*fnToWideChar)(char* src, wchar_t* dst, int max);
};

void BeaconAPI(bapi* beaconApi)
{
	*beaconApi = (bapi){
		LoadLibraryA,
		FreeLibrary,
		GetProcAddress,
		GetModuleHandleA,
		BeaconDataParse,
		BeaconDataPtr,
		BeaconDataInt,
		BeaconDataShort,
		BeaconDataLength,
		BeaconDataExtract,
		BeaconFormatAlloc,
		BeaconFormatReset,
		BeaconFormatPrintf,
		BeaconFormatAppend,
		BeaconFormatFree,
		BeaconFormatToString,
		BeaconFormatInt,
		BeaconOutput,
		BeaconPrintf,
		BeaconErrorD,
		BeaconErrorDD,
		BeaconErrorNA,
		BeaconUseToken,
		BeaconIsAdmin,
		BeaconRevertToken,
		BeaconGetSpawnTo,
		BeaconCleanupProcess,
		BeaconInjectProcess,
		BeaconSpawnTemporaryProcess,
		BeaconInjectTemporaryProcess,
		toWideChar
	};
}