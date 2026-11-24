#pragma once

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "InitMethodType.h"
#include "../../SharedLibFuncs/HashAlgDef.h"

class Hash
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_createHashInst{ "createHashInst" };
	static constexpr const char* name_deleteHashInst{ "deleteHashInst" };
	static constexpr const char* name_compHash{ "compHash" };
	static constexpr const char* name_compHash_port{ "compHash_port" };
	static constexpr const char* name_updateHash{ "updateHash" };
	static constexpr const char* name_finalResult{ "finalResult" };

	typedef void* (*def_createHashInst)(void* cryptoContext, int32_t algDef, int32_t hashLen, int32_t* error_out);
	typedef bool (*def_deleteHashInst)(void* cryptoContext, void* hashInst);
	typedef bool (*def_compHash)(void* hashInst, const void* seq, uint32_t lenOfSeq, void* result, int32_t* error_out);
	typedef bool (*def_compHash_port)(void* cryptoContext, int32_t algDef, int32_t hashLen, const void* seq,
		uint32_t lenOfSeq, void* result, int32_t* error_out);
	typedef bool (*def_updateHash)(void* hashInst, void* seq, uint32_t lenOfSeq, int32_t* error_out);
	typedef bool (*def_finalResult)(void* hashInst, void* result, int32_t* error_out);

	struct _Internal_ {
		def_createHashInst func_createHashInst{};
		def_deleteHashInst func_deleteHashInst{};
		def_compHash func_compHash{};
		def_compHash_port func_compHash_port{};
		def_updateHash func_updateHash{};
		def_finalResult func_finalResult{};

		bool isInit{ false };
		bool isOwner{ false };
		void* cryptoContext{ nullptr };
		void* hashInst{ nullptr };
		HashAlgDef algDef{};
		HashLen  len{ HashLen::hash_256_bit };
		type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };
		void* key{ nullptr };
		size_t lenOfKey{};

		_Internal_(type_sharedLibHandle libH_, void* cryptoContext_, HashAlgDef algDef_, HashLen hashLen, bool own) 
			: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), len(hashLen), libH(libH_) {
		}
	};

	_Internal_ inst;

	Hash(type_sharedLibHandle libH_, void* cryptoContext_, HashAlgDef algDef_, HashLen hashLen, bool own)
		: inst(libH_, cryptoContext_, algDef_, hashLen, own)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext_ != nullptr);
	}
	Hash(const Hash&) = delete;
	Hash(Hash&& obj) 
		:inst(std::move(obj.inst)) {
		obj.inst.isInit = false;
		obj.inst.isOwner = false;
	}
	~Hash()
	{
		if (!inst.isInit || !inst.isOwner)
			return;

		deleteHashInst(inst.cryptoContext, inst.hashInst);
	}

	[[nodiscard]] size_t get_hashLen() const
	{
		if (inst.len == HashLen::hash_256_bit)
			return 32;
		else
			return 64;
	}

	void init()
	{
		assert(!inst.isInit);
		assert(inst.libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		int32_t error{};
		if (inst.isOwner)
		{
			inst.hashInst = inst.func_createHashInst(inst.cryptoContext,
				static_cast<std::underlying_type_t<HashAlgDef>>(inst.algDef), static_cast<std::underlying_type_t<HashLen>>(inst.len),
				&error);

			if (error != 0)
				throw error;
		}

		inst.isInit = true;
	}

	void* createHashInst(void* cryptoContext, int32_t* error_out)
	{
		assert(inst.isInit);
		assert(cryptoContext != nullptr);

		return inst.func_createHashInst(cryptoContext, static_cast<std::underlying_type_t<HashAlgDef>>(inst.algDef),
			static_cast<std::underlying_type_t<HashLen>>(inst.len), error_out);
	}
	bool deleteHashInst(void* cryptoContext, void* hashInst) const
	{
		assert(inst.isInit);
		assert(cryptoContext != nullptr);

		return inst.func_deleteHashInst(cryptoContext, hashInst);
	}
	bool compHash(const void* seq, size_t lenOfSeq, void* result, int32_t* error_out) const
	{
		assert(inst.isOwner);

		return compHash(inst.hashInst, seq, lenOfSeq, result, error_out);
	}
	bool compHash(void* hashInst, const void* seq, size_t lenOfSeq, void* result, int32_t* error_out) const
	{
		assert(inst.isInit);
		assert(hashInst != nullptr);
		assert(seq != nullptr);
		assert(lenOfSeq != 0);
		assert(result != nullptr);

		return inst.func_compHash(hashInst, seq, static_cast<uint32_t>(lenOfSeq), result, error_out);
	}
	bool updateHash(void* seq, size_t lenOfSeq, int32_t* error_out) const
	{
		assert(inst.isOwner);

		return updateHash(inst.hashInst, seq, lenOfSeq, error_out);
	}
	bool updateHash(void* hashInst, void* seq, size_t lenOfSeq, int32_t* error_out) const
	{
		assert(inst.isInit);
		assert(hashInst != nullptr);
		assert(seq != nullptr);
		assert(lenOfSeq != 0);

		return inst.func_updateHash(hashInst, seq, static_cast<uint32_t>(lenOfSeq), error_out);
	}
	bool finalResult(void* result, int32_t* error_out) const
	{
		assert(inst.isOwner);

		return finalResult(inst.hashInst, result, error_out);
	}
	bool finalResult(void* hashInst, void* result, int32_t* error_out) const
	{
		assert(inst.isInit);
		assert(hashInst != nullptr);
		assert(result != nullptr);

		return inst.func_finalResult(hashInst, result, error_out);
	}


private:
	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_createHashInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_createHashInst = reinterpret_cast<def_createHashInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_deleteHashInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_deleteHashInst = reinterpret_cast<def_deleteHashInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_compHash);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_compHash = reinterpret_cast<def_compHash>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_compHash_port);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_compHash_port = reinterpret_cast<def_compHash_port>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_updateHash);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_updateHash = reinterpret_cast<def_updateHash>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_finalResult);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_finalResult = reinterpret_cast<def_finalResult>(funcAddress);
	}
};