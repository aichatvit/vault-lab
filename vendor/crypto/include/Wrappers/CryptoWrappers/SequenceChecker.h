//SequenceChecker

#pragma once

#include <vector>
#include <algorithm>
#include <cassert>

#include "../../Common/mstring.h"
#include "../../SharedLibFuncs/RandomAlgDef.h"
#include "../SystemAbstractions/SystemPrimitives.h"

class SequenceChecker
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr char* name_checkSequence_port{ "checkSequence_port" };

	typedef bool (*def_checkSequence_port)(void* cryptoContext, void* seq, uint32_t lenOfSeq, int32_t* error_out);

	def_checkSequence_port func_checkSequence_port{};

	bool isInit{ false };
	void* cryptoContext{ nullptr };
	type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

	SequenceChecker(type_sharedLibHandle libH_, void* cryptoContext_)
		: cryptoContext(cryptoContext_), libH(libH_)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext != nullptr);
	}

	void init()
	{
		assert(!isInit);
		assert(libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		int32_t error{};

		isInit = true;
	}

	bool checkSequence(uint8_t* seq, size_t lenOfSeq, int32_t* error_out) const
	{
		assert(isInit);
		assert(lenOfSeq <= std::numeric_limits<uint32_t>::max());

		return func_checkSequence_port(cryptoContext, seq, static_cast<uint32_t>(lenOfSeq), error_out);
	}
	bool checkSequence(void* cryptoInst, uint8_t* seq, size_t lenOfSeq, int32_t* error_out) const
	{
		assert(isInit);
		assert(lenOfSeq <= std::numeric_limits<uint32_t>::max());

		return func_checkSequence_port(cryptoInst, seq, static_cast<uint32_t>(lenOfSeq), error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_checkSequence_port);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_checkSequence_port = reinterpret_cast<def_checkSequence_port>(funcAddress);
	}
};