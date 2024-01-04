#pragma once

extern HANDLE gIdentityToken;
void IdentityConditionalRevert(BOOL ignoreToken);
void IdentityConditionalImpersonate(BOOL ignoreToken);