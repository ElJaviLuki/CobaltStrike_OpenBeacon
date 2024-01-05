#pragma once



typedef union _CHANNEL {
	HANDLE handle;
} CHANNEL;

typedef struct _PROTOCOL {
	CHANNEL channel;
	HANDLE(*read)(struct _PROTOCOL*, char*, int);
	BOOL (*write)(struct _PROTOCOL*, char*, int);
	void (*close)(struct _PROTOCOL*);
	void (*flush)(struct _PROTOCOL*);
	BOOL(*waitForData)(struct _PROTOCOL*, DWORD);
} PROTOCOL;