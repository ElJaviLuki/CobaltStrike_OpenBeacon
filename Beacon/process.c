#include "pch.h"
#include "beacon.h"
BOOL GetAccountNameFromToken(HANDLE hProcess, char* accountName, int length) {
	HANDLE hToken;
	BOOL result = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (!result) {
		return FALSE;
	}

	result = IdentityGetUserInfo(hToken, accountName, length);
	CloseHandle(hToken);
	return result;
}
