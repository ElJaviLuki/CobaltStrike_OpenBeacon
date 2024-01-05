#pragma once

typedef union _CHANNEL {
	HANDLE handle;
} CHANNEL;

typedef struct _PROTOCOL {
	CHANNEL channel;
} PROTOCOL;
