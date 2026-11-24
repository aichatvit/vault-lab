#pragma once

#ifdef _WIN32
#include "../Common/mStringHelper_Win.h"
//using mStringHelper = LicensingConsole::Common::mStringHelper_Win;
//typedef /*LicensingConsole::Common::*/mStringHelper_Win mStringHelper;
#else
#include "../Common/mStringHelper_Linux.h"
//using mStringHelper = /*LicensingConsole::Common::*/mStringHelper_Linux;
#endif // _WIN32