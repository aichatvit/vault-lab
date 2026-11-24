#pragma once

#include <cassert>

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "InitMethodType.h"
#include "../../SharedLibFuncs/AsymmetricAlgDef.h"

class Asymmetric
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_asymm_importKeyByPass{ "asymm_importKeyByPass" };
	static constexpr const char* name_asymm_exportKeyByPass{ "asymm_exportKeyByPass" };
	static constexpr const char* name_createAsymmetricContext{ "createAsymmetricContext" };
	static constexpr const char* name_destroyAsymmetricContext{ "destroyAsymmetricContext" };
	static constexpr const char* name_importPublicData{ "importPublicData" };
	static constexpr const char* name_exportPublicData{ "exportPublicData" };
	static constexpr const char* name_encrypt{ "encrypt" };
	static constexpr const char* name_decrypt{ "decrypt" };

	typedef bool (*def_asymm_importKeyByPass)(void* asymmetricContext, const mchar* pass,
		const uint8_t* container, uint32_t lenOfContainer, int32_t* error_out);
	typedef void* (*def_asymm_exportKeyByPass)(void* asymmetricContext, const  mchar* pass, uint32_t* lenOfContainer_out,
		int32_t* error_out);
	typedef void* (*def_createAsymmetricContext)(void* cryptoContext, int32_t algDef, int32_t* error_out);
	typedef bool (*def_destroyAsymmetricContext)(void* cryptoContext, void* asymmetricContext);
	typedef bool (*def_importPublicData)(void* asymmetricContext, const uint8_t* data, uint32_t lenOfData, int32_t* error_out);
	typedef void* (*def_exportPublicData)(void* asymmetricContext, bool includeAll, uint32_t* lenOfData_out, int32_t* error_out);
	typedef void* (*def_encrypt)(void* asymmetricContext, const uint8_t* data, uint32_t lenOfData, uint32_t* destLen_out,
		int32_t* error_out);
	typedef void* (*def_decrypt)(void* asymmetricContext, const uint8_t* data, uint32_t lenOfData, uint32_t* destLen_out,
		int32_t* error_out);

	def_asymm_importKeyByPass func_asymm_importKeyByPass{};
	def_asymm_exportKeyByPass func_asymm_exportKeyByPass{};
	def_createAsymmetricContext func_createAsymmetricContext{};
	def_destroyAsymmetricContext func_destroyAsymmetricContext{};
	def_importPublicData func_importPublicData{};
	def_exportPublicData func_exportPublicData{};
	def_encrypt func_encrypt{};
	def_decrypt func_decrypt{};

	bool isInit{ false };
	bool isOwner{ false };
	void* cryptoContext{ nullptr };
	void* asymmInst{ nullptr };
	AsymmetricAlgDef algDef{};
	type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

	Asymmetric(type_sharedLibHandle libH_, void* cryptoContext_, AsymmetricAlgDef algDef_, bool own)
		: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), libH(libH_)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext != nullptr);
	}
	~Asymmetric()
	{
		if (!isInit || !isOwner)
			return;

		func_destroyAsymmetricContext(cryptoContext, asymmInst);
	}

	[[nodiscard]] void* getAsymmInst() const
	{
		return asymmInst;
	}

	void init()
	{
		assert(!isInit);
		assert(libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		int32_t error{};
		if (isOwner)
		{
			asymmInst = func_createAsymmetricContext(cryptoContext, static_cast<int32_t>(algDef), &error);

			if (error != 0)
				throw error;
		}

		isInit = true;
	}

	void* asymm_exportKeyByPass(const mchar* pass, size_t* lenOfContainer_out,
		int32_t* error_out)
	{
		return asymm_exportKeyByPass(asymmInst, pass, lenOfContainer_out, error_out);
	}
	void* asymm_exportKeyByPass(void* asymmetricContext, const mchar* pass, size_t* lenOfContainer_out,
		int32_t* error_out)
	{
		return func_asymm_exportKeyByPass(asymmetricContext, pass, reinterpret_cast<uint32_t*>(lenOfContainer_out),
			error_out);
	}
	bool asymm_importKeyByPass(const mchar* pass, const uint8_t* container,
		size_t lenOfContainer, int32_t* error_out)
	{
		return asymm_importKeyByPass(asymmInst, pass, container, lenOfContainer, error_out);
	}
	bool asymm_importKeyByPass(void* asymmetricContext, const mchar* pass, const uint8_t* container, 
		size_t lenOfContainer, int32_t* error_out)
	{
		return func_asymm_importKeyByPass(asymmetricContext, pass, container, static_cast<uint32_t>(lenOfContainer), error_out);
	}
	void* decrypt(const uint8_t* data, size_t lenOfData, size_t* destLen_out,
		int32_t* error_out)
	{
		return decrypt(asymmInst, data, lenOfData, destLen_out, error_out);
	}
	void* decrypt(void* asymmetricContext, const uint8_t* data, size_t lenOfData, size_t* destLen_out,
		int32_t* error_out)
	{
		return func_decrypt(asymmetricContext, data, static_cast<uint32_t>(lenOfData), reinterpret_cast<uint32_t*>(destLen_out),
			error_out);
	}
	void* encrypt(const uint8_t* data, size_t lenOfData, size_t* destLen_out,
		int32_t* error_out)
	{
		return encrypt(asymmInst, data, lenOfData, destLen_out, error_out);
	}
	void* encrypt(void* asymmetricContext, const uint8_t* data, size_t lenOfData, size_t* destLen_out,
		int32_t* error_out)
	{
		return func_encrypt(asymmetricContext, data, static_cast<uint32_t>(lenOfData), 
			reinterpret_cast<uint32_t*>(destLen_out), error_out);
	}
	void* exportPublicData(bool includeAll, size_t* lenOfData_out, int32_t* error_out)
	{
		return exportPublicData(asymmInst, includeAll, lenOfData_out, error_out);
	}
	void* exportPublicData(void* asymmetricContext, bool includeAll, size_t* lenOfData_out, int32_t* error_out)
	{
		return func_exportPublicData(asymmetricContext, includeAll, reinterpret_cast<uint32_t*>(lenOfData_out), error_out);
	}
	bool importPublicData(const uint8_t* data, size_t lenOfData, int32_t* error_out)
	{
		return importPublicData(asymmInst, data, static_cast<uint32_t>(lenOfData), error_out);
	}
	bool importPublicData(void* asymmetricContext, const uint8_t* data, size_t lenOfData, int32_t* error_out)
	{
		return func_importPublicData(asymmetricContext, data, static_cast<uint32_t>(lenOfData), error_out);
	}
	bool destroyAsymmetricContext(void* cryptoContext, void* asymmetricContext)
	{
		return func_destroyAsymmetricContext(cryptoContext, asymmetricContext);
	}
	void* createAsymmetricContext(void* cryptoContext, int32_t* error_out)
	{
		return func_createAsymmetricContext(cryptoContext, static_cast<int32_t>(algDef), error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_asymm_exportKeyByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_asymm_exportKeyByPass = reinterpret_cast<def_asymm_exportKeyByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_asymm_importKeyByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_asymm_importKeyByPass = reinterpret_cast<def_asymm_importKeyByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_decrypt);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_decrypt = reinterpret_cast<def_decrypt>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_encrypt);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_encrypt = reinterpret_cast<def_encrypt>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_exportPublicData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_exportPublicData = reinterpret_cast<def_exportPublicData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_importPublicData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_importPublicData = reinterpret_cast<def_importPublicData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_destroyAsymmetricContext);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_destroyAsymmetricContext = reinterpret_cast<def_destroyAsymmetricContext>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_createAsymmetricContext);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_createAsymmetricContext = reinterpret_cast<def_createAsymmetricContext>(funcAddress);
	}
};