#pragma once
#include "protocol.h"

void LinkViaTcp(char* data, int length);

BOOL LinkAdd(PROTOCOL* protocol, int flags);