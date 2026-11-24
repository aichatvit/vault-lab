#pragma once

#ifdef _WIN32

#include "SharedLibOwner_Win.h"
using SharedLibOwner = SharedLibOwner_Win;

#else

#include "SharedLibOwner_Linux.h"
using SharedLibOwner = SharedLibOwner_Linux;

#endif