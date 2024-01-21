#pragma once
#include "protocol.h"

void LinkViaTcp(char* buffer, int length);

SOCKET LinkViaTcpConnect(char* target, short port);

BOOL LinkAdd(PROTOCOL* protocol, int flags);

void PipeReopen(char* buffer, int length);

void PipeClose(char* buffer, int length);

void PipeRoute(char* buffer, int length);
