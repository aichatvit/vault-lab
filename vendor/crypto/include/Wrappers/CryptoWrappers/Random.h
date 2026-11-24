#pragma once

#include <vector>
#include <algorithm>

#include "../../SharedLibFuncs/RandomAlgDef.h"

class Random
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_createRandInstance{ "createRandInstance" };
	static constexpr const char* name_deleteRandInstance{ "deleteRandInstance" };
	static constexpr const char* name_genRandSeq{ "genRandSeq" };

	typedef void* (*def_createRandInstance)(void* cryptoContext, int32_t algDef, int32_t* error_out);
	typedef bool (*def_deleteRandInstance)(void* cryptoContext, void* randInst);
	typedef bool (*def_genRandSeq)(void* cryptoInst, void* randInst, void* seq, /*uint32_t lenStrong, */uint32_t lenRand,
		int32_t* error_out);

	struct _Internal_ {
		def_createRandInstance func_createRandInstance{};
		def_deleteRandInstance func_deleteRandInstance{};
		def_genRandSeq func_genRandSeq{};

		bool isInit{ false };
		bool isOwner{ false };
		void* cryptoContext{ nullptr };
		void* randInstance{ nullptr };
		RandomAlgDef algDef{};
		type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

		_Internal_(type_sharedLibHandle libH_, void* cryptoContext_, RandomAlgDef algDef_, bool own) 
			: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), libH(libH_) {
		}
	};

	_Internal_ inst;

	Random(type_sharedLibHandle libH_, void* cryptoContext_, RandomAlgDef algDef_, bool own)
		: inst(libH_, cryptoContext_, algDef_, own)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext_ != nullptr);
	}
	Random(const Random&) = delete;
	Random(Random&& obj) 
		: inst(std::move(obj.inst)) {
		obj.inst.isInit = false;
		obj.inst.isOwner = false;
	}
	~Random()
	{
		if (!inst.isInit || !inst.isOwner)
			return;

		inst.func_deleteRandInstance(inst.cryptoContext, inst.randInstance);
	}

	void init()
	{
		assert(!inst.isInit);
		assert(inst.libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		int32_t error{};
		if (inst.isOwner)
		{
			inst.randInstance = inst.func_createRandInstance(inst.cryptoContext, static_cast<int32_t>(inst.algDef),
				/*strongRand.data(), static_cast<uint32_t>(strongRand.size()),*/ &error);

			if (error != 0)
				throw error;
		}

		inst.isInit = true;
	}

	bool genRandSeq(void* randSeq, size_t lenRand, int32_t* error_out)
	{
		assert(inst.isInit);

		return inst.func_genRandSeq(inst.cryptoContext, inst.randInstance, randSeq, /*0, */static_cast<uint32_t>(lenRand), error_out);
	}
	bool genRandSeq(void* cryptoInst, void* randInst, void* seq, size_t lenStrong, size_t lenRand,
		int32_t* error_out) const
	{
		assert(inst.isInit);

		return inst.func_genRandSeq(cryptoInst, randInst, seq, /*static_cast<uint32_t>(lenStrong), */static_cast<uint32_t>(lenRand),
			error_out);
	}
	bool deleteRandInstance(void* cryptoContext, void* randInstance_) const
	{
		assert(cryptoContext != nullptr);
		assert(randInstance_ != nullptr);

		return inst.func_deleteRandInstance(cryptoContext, randInstance_);
	}
	void* createRandInstance(void* cryptoContext, int32_t algDef, int32_t* error_out) const 
	{
		assert(cryptoContext != nullptr);

		return inst.func_createRandInstance(cryptoContext, algDef, error_out);
	}
	void* createRandInstance(void* cryptoContext, int32_t* error_out)
	{
		assert(inst.isInit);
		assert(cryptoContext != nullptr);

		return createRandInstance(cryptoContext, static_cast<int32_t>(inst.algDef), error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_createRandInstance);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_createRandInstance = reinterpret_cast<def_createRandInstance>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_deleteRandInstance);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_deleteRandInstance = reinterpret_cast<def_deleteRandInstance>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_genRandSeq);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_genRandSeq = reinterpret_cast<def_genRandSeq>(funcAddress);
	}

};