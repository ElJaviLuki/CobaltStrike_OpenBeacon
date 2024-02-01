#include "pch.h"

#include "strategy.h"

#include "settings.h"
#include "utils.h"

#define STRATEGY_DEFAULT 0
#define STRATEGY_RANDOM 1
#define STRATEGY_FAILOVER 2

#if S_DOMAIN_STRATEGY == STRATEGY_DEFAULT
#include "strategy_default.c"
#elif S_DOMAIN_STRATEGY == STRATEGY_RANDOM
#include "strategy_random.c"
#elif S_DOMAIN_STRATEGY == STRATEGY_FAILOVER
#include "strategy_failover.c"
#else
#error "Invalid domain strategy"
#endif