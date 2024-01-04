#pragma once

extern HANDLE gIdentityToken;
extern BOOL gIdentityIsLoggedIn;

void IdentityConditionalRevert(BOOL ignoreToken);
void IdentityConditionalImpersonate(BOOL ignoreToken);