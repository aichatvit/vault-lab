#pragma once
#include <cassert>

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "../../SharedLibFuncs/KdfTreeAlgDef.h"
#include "../../SharedLibFuncs/KdfTreeData.h"

class KdfTree
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_KdfTree_getData{ "KdfTree_getData" };
	static constexpr const char* name_KdfTree_deriveBytes{ "KdfTree_deriveBytes" };
static constexpr const char* name_KdfTree_deriveBytesBySymKey{ "KdfTree_deriveBytesBySymKey" };
	static constexpr const char* name_KdfTree_createInst{ "KdfTree_createInst" };
	static constexpr const char* name_KdfTree_deleteInst{ "KdfTree_deleteInst" };
	static constexpr const char* name_KdfTree_deriveBytesInst{ "KdfTree_deriveBytesInst" };
	static constexpr const char* name_KdfTree_deriveBytesBySymKeyInst{ "KdfTree_deriveBytesBySymKeyInst" };

	typedef bool (*def_KdfTree_getData)(int32_t algDef, int32_t r, KdfTreeData* data, int32_t* error_out);
	typedef bool (*def_KdfTree_deriveBytes)(void* cryptoContext, int32_t algDef, int32_t r,
		const void* key, uint32_t lenOfKey,
		const void* label, uint32_t lenOfLabel,
		const void* seed, uint32_t lenOfSeed,
		void* buf, uint32_t sizeOfBuf, int32_t* error_out);
typedef bool (*def_KdfTree_deriveBytesBySymKey)(void* cryptoContext, int32_t algDef, int32_t r,
		void* symKey,
		const void* label, uint32_t lenOfLabel,
		const void* seed, uint32_t lenOfSeed,
		void* buf, uint32_t sizeOfBuf, int32_t* error_out);
	typedef void* (*def_KdfTree_createInst)(void* cryptoContext, int32_t algDef, int32_t* error_out);
	typedef bool (*def_KdfTree_deleteInst)(void* cryptoContext, void* kdfInst);
	typedef bool (*def_KdfTree_deriveBytesInst)(void* kdfInst, int32_t r,
		const void* key, uint32_t lenOfKey,
		const void* label, uint32_t lenOfLabel,
		const void* seed, uint32_t lenOfSeed,
		void* buf, uint32_t sizeOfBuf, int32_t* error_out);
	typedef bool (*def_KdfTree_deriveBytesBySymKeyInst)(void* kdfInst, int32_t r,
		void* symKey,
		const void* label, uint32_t lenOfLabel,
		const void* seed, uint32_t lenOfSeed,
		void* buf, uint32_t sizeOfBuf, int32_t* error_out);

	def_KdfTree_getData func_KdfTree_getData{};
	def_KdfTree_deriveBytes func_KdfTree_deriveBytes{};
def_KdfTree_deriveBytesBySymKey func_KdfTree_deriveBytesBySymKey{};
	def_KdfTree_createInst func_KdfTree_createInst{};
	def_KdfTree_deleteInst func_KdfTree_deleteInst{};
	def_KdfTree_deriveBytesInst func_KdfTree_deriveBytesInst{};
	def_KdfTree_deriveBytesBySymKeyInst func_KdfTree_deriveBytesBySymKeyInst{};

	bool isInit{ false };
	void* cryptoContext{ nullptr };
	type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

	KdfTree(type_sharedLibHandle libH_, void* cryptoContext_)
		: cryptoContext(cryptoContext_), libH(libH_)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext != nullptr);
	}

	~KdfTree() = default;

	void init()
	{
		assert(!isInit);
		assert(libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		isInit = true;
	}

	bool getData(int32_t algDef, int32_t r, KdfTreeData* data, int32_t* error_out) const
	{
		assert(isInit);

		return func_KdfTree_getData(algDef, r, data, error_out);
	}

	bool getData(KdfTreeAlgDef algDef_, KdfTreeR r_, KdfTreeData* data, int32_t* error_out) const
	{
		return getData(static_cast<int32_t>(algDef_), static_cast<int32_t>(r_), data, error_out);
	}

	bool deriveBytes(int32_t algDef, int32_t r,
		const void* key, size_t lenOfKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		assert(isInit);

		return deriveBytes(cryptoContext, algDef, r, key, lenOfKey, label, lenOfLabel, seed, lenOfSeed, buf, sizeOfBuf, error_out);
	}

	bool deriveBytes(KdfTreeAlgDef algDef_, KdfTreeR r_,
		const void* key, size_t lenOfKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		return deriveBytes(static_cast<int32_t>(algDef_), static_cast<int32_t>(r_),
			key, lenOfKey, label, lenOfLabel, seed, lenOfSeed, buf, sizeOfBuf, error_out);
	}

	bool deriveBytes(void* cryptoContext_, int32_t algDef, int32_t r,
		const void* key, size_t lenOfKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		assert(isInit);

		return func_KdfTree_deriveBytes(cryptoContext_, algDef, r, key, static_cast<uint32_t>(lenOfKey),
			label, static_cast<uint32_t>(lenOfLabel), seed, static_cast<uint32_t>(lenOfSeed),
			buf, static_cast<uint32_t>(sizeOfBuf), error_out);
	}

	bool deriveBytesBySymKey(int32_t algDef, int32_t r, void* symKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		assert(isInit);
	
		return deriveBytesBySymKey(cryptoContext, algDef, r, symKey, label, lenOfLabel, seed,
			lenOfSeed, buf, sizeOfBuf, error_out);
	}

	bool deriveBytesBySymKey(KdfTreeAlgDef algDef_, KdfTreeR r_, void* symKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		return deriveBytesBySymKey(static_cast<int32_t>(algDef_), static_cast<int32_t>(r_), symKey,
			label, lenOfLabel, seed, lenOfSeed, buf, sizeOfBuf, error_out);
	}

	bool deriveBytesBySymKey(void* cryptoContext_, int32_t algDef, int32_t r, void* symKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		assert(isInit);
	
		return func_KdfTree_deriveBytesBySymKey(cryptoContext_, algDef, r, symKey,
			label, static_cast<uint32_t>(lenOfLabel), seed, static_cast<uint32_t>(lenOfSeed),
			buf, static_cast<uint32_t>(sizeOfBuf), error_out);
	}

	void* createInst(int32_t algDef, int32_t* error_out) const
	{
		assert(isInit);

		return func_KdfTree_createInst(cryptoContext, algDef, error_out);
	}

	void* createInst(KdfTreeAlgDef algDef_, int32_t* error_out) const
	{
		return createInst(static_cast<int32_t>(algDef_), error_out);
	}

	bool deleteInst(void* kdfInst) const
	{
		assert(isInit);

		return func_KdfTree_deleteInst(cryptoContext, kdfInst);
	}

	bool deriveBytesInst(void* kdfInst, int32_t r,
		const void* key, size_t lenOfKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		assert(isInit);

		return func_KdfTree_deriveBytesInst(kdfInst, r, key, static_cast<uint32_t>(lenOfKey),
			label, static_cast<uint32_t>(lenOfLabel), seed, static_cast<uint32_t>(lenOfSeed),
			buf, static_cast<uint32_t>(sizeOfBuf), error_out);
	}

	bool deriveBytesInst(void* kdfInst, KdfTreeR r_,
		const void* key, size_t lenOfKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		return deriveBytesInst(kdfInst, static_cast<int32_t>(r_), key, lenOfKey, label, lenOfLabel,
			seed, lenOfSeed, buf, sizeOfBuf, error_out);
	}

	bool deriveBytesBySymKeyInst(void* kdfInst, int32_t r, void* symKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		assert(isInit);

		return func_KdfTree_deriveBytesBySymKeyInst(kdfInst, r, symKey,
			label, static_cast<uint32_t>(lenOfLabel), seed, static_cast<uint32_t>(lenOfSeed),
			buf, static_cast<uint32_t>(sizeOfBuf), error_out);
	}

	bool deriveBytesBySymKeyInst(void* kdfInst, KdfTreeR r_, void* symKey,
		const void* label, size_t lenOfLabel,
		const void* seed, size_t lenOfSeed,
		void* buf, size_t sizeOfBuf, int32_t* error_out) const
	{
		return deriveBytesBySymKeyInst(kdfInst, static_cast<int32_t>(r_), symKey, label, lenOfLabel,
			seed, lenOfSeed, buf, sizeOfBuf, error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_KdfTree_getData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_KdfTree_getData = reinterpret_cast<def_KdfTree_getData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_KdfTree_deriveBytes);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_KdfTree_deriveBytes = reinterpret_cast<def_KdfTree_deriveBytes>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_KdfTree_deriveBytesBySymKey);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_KdfTree_deriveBytesBySymKey = reinterpret_cast<def_KdfTree_deriveBytesBySymKey>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_KdfTree_createInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_KdfTree_createInst = reinterpret_cast<def_KdfTree_createInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_KdfTree_deleteInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_KdfTree_deleteInst = reinterpret_cast<def_KdfTree_deleteInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_KdfTree_deriveBytesInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_KdfTree_deriveBytesInst = reinterpret_cast<def_KdfTree_deriveBytesInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_KdfTree_deriveBytesBySymKeyInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_KdfTree_deriveBytesBySymKeyInst = reinterpret_cast<def_KdfTree_deriveBytesBySymKeyInst>(funcAddress);
	}
};
