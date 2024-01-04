#pragma once

extern HANDLE gIdentityToken;
extern BOOL gIdentityIsLoggedIn;
extern WCHAR gIdentityDomain[256];
extern WCHAR gIdentityUsername[256];
extern WCHAR gIdentityPassword[256];

void IdentityConditionalRevert(BOOL ignoreToken);
void IdentityConditionalImpersonate(BOOL ignoreToken);