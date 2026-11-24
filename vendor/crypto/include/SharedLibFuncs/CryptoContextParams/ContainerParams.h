#pragma once

#include "../../Common/mstring.h"

struct ContainerParams {
	int32_t typeOfParams;
	const mchar* pass;
	const void* cont;
	uint32_t len;
	bool needBlockByRand;
};