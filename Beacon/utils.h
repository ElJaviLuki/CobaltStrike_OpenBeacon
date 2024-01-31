#pragma once

DWORD ExpandEnvironmentStrings_s(const char* lpSrc, char* lpDst, size_t size);

int RandomEvenInt(void);

int ToNetbios(char nb, const char* in, int inlen, char* out, int outlen);

int FromNetbios(char nb, const char* in, int inlen, char* out, int outlen);

int XorMask(const char* in, int inlen, char* out, int outlen);

int XorUnmask(const char* in, int inlen, char* out, int outlen);