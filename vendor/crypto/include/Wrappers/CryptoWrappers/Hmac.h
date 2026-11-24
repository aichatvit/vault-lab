#pragma once
#include <cassert>

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "InitMethodType.h"
#include "../../SharedLibFuncs/HmacAlgDef.h"
#include "../../SharedLibFuncs/HmacData.h"

class Hmac
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_getData_KeySizes{ "Hmac_getData_KeySizes" };
	static constexpr const char* name_Hmac_getData{ "Hmac_getData" };
	static constexpr const char* name_createHmacInst{ "createHmacInst" };
	static constexpr const char* name_createHmacInst_key{ "createHmacInst_key" };
	static constexpr const char* name_deleteHmacInst{ "deleteHmacInst" };
	static constexpr const char* name_setKeyInst{ "setKeyInst" };
	static constexpr const char* name_compHmac{ "compHmac" };
	static constexpr const char* name_updateHmac{ "updateHmac" };
	static constexpr const char* name_finalHmac{ "finalHmac" };

	typedef bool (*def_Hmac_getData)(const void* hmacContext, HmacData* data, int32_t* error_out);
	typedef void* (*def_createHmacInst)(void* cryptoContext, int32_t algDef, int32_t hmacLen, int32_t* error_out);
	typedef void* (*def_createHmacInst_key)(void* cryptoContext, int32_t algDef, int32_t hmacLen, void* key, uint32_t lenOfKey,
		int32_t* error_out);
	typedef bool (*def_deleteHmacInst)(void* cryptoContext, void* hmacInst);
	typedef bool (*def_setKeyInst)(void* hmacContext, void* key, uint32_t lenOfKey, int32_t* error_out);
	typedef bool (*def_compHmac)(void* hmacInst, void* seq, uint32_t lenOfSeq, void* result, int32_t* error_out);
	typedef bool (*def_updateHmac)(void* hmacInst, void* seq, uint32_t lenOfSeq, int32_t* error_out);
	typedef bool (*def_finalHmac)(void* hmacInst, void* result, int32_t* error_out);

	//def_Hmac_getData_KeySizes func_Hmac_getData_KeySizes{};
	def_Hmac_getData func_Hmac_getData{};
	def_createHmacInst func_createHmacInst{};
	def_createHmacInst_key func_createHmacInst_key{};
	def_deleteHmacInst func_deleteHmacInst{};
	def_setKeyInst func_setKeyInst{};
	def_compHmac func_compHmac{};
	def_updateHmac func_updateHmac{};
	def_finalHmac func_finalHmac{};

	bool isInit{ false };
	bool isOwner{ false };
	void* cryptoContext{ nullptr };
	void* hmacInst{ nullptr };
	HmacAlgDef algDef{};
	HmacLen len{ HmacLen::Hmac_256_bit };
	type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };
	void* key{ nullptr };
	size_t lenOfKey{};

	Hmac(type_sharedLibHandle libH_, void* cryptoContext_, HmacAlgDef algDef_, HmacLen hmacLen, bool own)
		: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), len(hmacLen), libH(libH_)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext != nullptr);
	}
	Hmac(type_sharedLibHandle libH_, void* cryptoContext_, HmacAlgDef algDef_, HmacLen hmacLen, bool own, 
		void* key_, size_t lenOfKey_)
		: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), len(hmacLen), libH(libH_), key(key_), lenOfKey(lenOfKey_)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext != nullptr);
		assert(key != nullptr);
		assert(lenOfKey != 0);
	}
	~Hmac()
	{
		if (!isInit || !isOwner)
			return;

		deleteHmacInst(cryptoContext, hmacInst);
	}

	[[nodiscard]] size_t get_hmacLen() const
	{
		if (len == HmacLen::Hmac_256_bit)
			return 32;
		else
			return 64;
	}

	void init()
	{
		assert(!isInit);
		assert(libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		int32_t error{};
		if (isOwner)
		{
			if (key == nullptr)
			{
				hmacInst = func_createHmacInst(cryptoContext,
					static_cast<std::underlying_type_t<HmacAlgDef>>(algDef), static_cast<std::underlying_type_t<HmacLen>>(len), 
					&error);
			}
			else
			{
				hmacInst = func_createHmacInst_key(cryptoContext,
					static_cast<std::underlying_type_t<HmacAlgDef>>(algDef), static_cast<std::underlying_type_t<HmacLen>>(len),
					key, static_cast<uint32_t>(lenOfKey), &error);
			}
			
			if (error != 0)
				throw error;
		}

		isInit = true;
	}

	//typedef void (*def_Hmac_getData_KeySizes)(int32_t algDef, int32_t hmacLen, HmacData_KeySizes* data, int32_t* error_out);
	
	bool getData(HmacData* data, int32_t* error_out) const
	{
		return getData(hmacInst, data, error_out);
	}
	bool getData(const void* hmacContext, HmacData* data, int32_t* error_out) const
	{
		assert(isInit);

		return func_Hmac_getData(hmacContext, data, error_out);
	}
	bool finalHmac(void* result, int32_t* error_out) const
	{
		assert(isOwner);

		return finalHmac(hmacInst, result, error_out);
	}
	bool finalHmac(void* hmacInst_, void* result, int32_t* error_out) const
	{
		assert(isInit);

		return func_finalHmac(hmacInst_, result, error_out);
	}
	//void (*def_updateHmac)(void* hmacInst, void* seq, uint32_t lenOfSeq, int32_t* error_out);
	bool updateHmac(void* seq, size_t lenOfSeq, int32_t* error_out) const
	{
		assert(isOwner);

		return updateHmac(hmacInst, seq, lenOfSeq, error_out);
	}
	bool updateHmac(void* hmacInst_, void* seq, size_t lenOfSeq, int32_t* error_out) const
	{
		assert(isInit);

		return func_updateHmac(hmacInst_, seq, static_cast<uint32_t>(lenOfSeq), error_out);
	}
	//typedef void (*def_compHmac)(void* hmacInst, void* seq, uint32_t lenOfSeq, void* result, int32_t* error_out);
	bool compHmac(void* seq, size_t lenOfSeq, void* result, int32_t* error_out) const
	{
		assert(isOwner);

		return compHmac(hmacInst, seq, lenOfSeq, result, error_out);
	}
	bool compHmac(void* hmacInst_, void* seq, size_t lenOfSeq, void* result, int32_t* error_out) const
	{
		assert(isInit);

		return func_compHmac(hmacInst_, seq, static_cast<uint32_t>(lenOfSeq), result, error_out);
	}
	//(*def_setKeyInst)(void* hmacContext, void* key, uint32_t lenOfKey, int32_t* error_out);
	bool setKeyInst(void* key, uint32_t lenOfKey, int32_t& error_out) const
	{
		assert(isOwner);

		return setKeyInst(hmacInst, key, lenOfKey, error_out);
	}
	bool setKeyInst(void* hmacContext, void* key, size_t lenOfKey, int32_t& error_out) const
	{
		assert(isInit);

		return func_setKeyInst(hmacContext, key, static_cast<uint32_t>(lenOfKey), &error_out);
	}
	bool deleteHmacInst(void* cryptoContext, void* hmacInst) const
	{
		assert(cryptoContext != nullptr);
		assert(hmacInst != nullptr);

		return func_deleteHmacInst(cryptoContext, hmacInst);
	}
	void* createHmacInst_key(void* cryptoContext, void* key, uint32_t lenOfKey, int32_t* error_out)
	{
		assert(isInit);
		assert(cryptoContext != nullptr);
		assert(key != nullptr);
		assert(lenOfKey != 0);

		return func_createHmacInst_key(cryptoContext, static_cast<std::underlying_type_t<HmacAlgDef>>(algDef),
			static_cast<std::underlying_type_t<HmacLen>>(len), key, lenOfKey, error_out);
	}
	void* createHmacInst(void* cryptoContext, int32_t* error_out)
	{
		assert(isInit);
		assert(cryptoContext != nullptr);

		return func_createHmacInst(cryptoContext, static_cast<std::underlying_type_t<HmacAlgDef>>(algDef),
			static_cast<std::underlying_type_t<HmacLen>>(len), error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_Hmac_getData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_Hmac_getData = reinterpret_cast<def_Hmac_getData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_createHmacInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_createHmacInst = reinterpret_cast<def_createHmacInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_createHmacInst_key);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_createHmacInst_key = reinterpret_cast<def_createHmacInst_key>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_deleteHmacInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_deleteHmacInst = reinterpret_cast<def_deleteHmacInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_setKeyInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_setKeyInst = reinterpret_cast<def_setKeyInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_compHmac);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_compHmac = reinterpret_cast<def_compHmac>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_updateHmac);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_updateHmac = reinterpret_cast<def_updateHmac>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_finalHmac);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_finalHmac = reinterpret_cast<def_finalHmac>(funcAddress);

		/*funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_setKeyInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_setKeyInst = reinterpret_cast<def_setKeyInst>(funcAddress);*/
	}
};