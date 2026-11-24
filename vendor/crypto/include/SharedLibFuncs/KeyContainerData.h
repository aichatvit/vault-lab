#pragma once

#include <cstdint>

enum class KeyContainerData : std::uint32_t
{
	keyPublicData,
	guid,
	expTimePeriod,

	_max,
};