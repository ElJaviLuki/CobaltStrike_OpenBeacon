#pragma once

/*
 * Include convention for this project:
 * 1. Precompiled header
 * 2. The ".h" file for the current source file
 * 3. C standard library headers
 * 4. Third-party library headers
 * 5. Windows headers
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <time.h>

#define LTM_DESC
#define LTC_NO_HASHES
//Only SHA256 is needed
#define LTC_SHA256
#define LTC_HASH_HELPERS
#define LTC_NO_MACS
#define LTC_HMAC
#include "tomcrypt.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>

#include "logger.h"
#include "macros.h"

// This forces the programmer to not use 'auto' keyword ever, otherwise the compiler will throw an error.
#define auto error