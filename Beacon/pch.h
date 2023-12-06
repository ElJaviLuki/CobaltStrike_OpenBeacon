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

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>