#pragma once

#include <cassert>

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "InitMethodType.h"
#include "../../SharedLibFuncs/SignAlgDef.h"

class Signanture
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_sign_exportPublicData{ "sign_exportPublicData" };
	static constexpr const char* name_sign_importPublicData{ "sign_importPublicData" };
	static constexpr const char* name_sign_deleteSignInst{ "sign_deleteSignInst" };
	static constexpr const char* name_sign_verify{ "sign_verify" };
	static constexpr const char* name_sign{ "sign" };
	static constexpr const char* name_sign_exportByPass{ "sign_exportByPass" };
	static constexpr const char* name_sign_importByPass{ "sign_importByPass" };
	static constexpr const char* name_sign_createSignAlgInstanse{ "sign_createSignAlgInstanse" };

	typedef void* (*def_exportPublicData)(void* signContext, uint32_t* len_out, bool includeAllPublicData,
		int32_t* error_out);
	typedef bool (*def_importPublicData)(void* signContext, void* publicData, uint32_t lenOfPublicData,
		bool includeAllPublicData, int32_t* error_out);
	typedef bool (*def_verify)(void* signContext, uint8_t* dataRawPtr, uint32_t sizeOfData, uint8_t* signRawPtr,
		uint32_t sizeOfSign, int32_t* error_out);
	typedef void* (*def_sign)(void* signContext, const uint8_t* dataRawPtr, uint32_t sizeOfData, uint32_t* sizeOfSign_out,
		int32_t* error_out);
	typedef void* (*def_exportByPass)(void* diffContext, const mchar* pass, uint32_t* len_out, int32_t* error_out);
	typedef bool (*def_importByPass)(void* signContext, void* container, size_t lenOfContainer,
		const mchar* pass, int32_t* error_out);
	typedef void* (*def_createSignAlgInstanse)(void* cryptoContext, int32_t algDef, int32_t* error_out);
	typedef bool (*def_deleteSignInst)(void* cryptoContext, void* signContext);

	def_exportPublicData func_exportPublicData{};
	def_importPublicData func_importPublicData{};
	def_verify func_verify{};
	def_sign func_sign{};
	def_importByPass func_importByPass{};
	def_exportByPass func_exportByPass{};
	def_createSignAlgInstanse func_createSignAlgInstanse{};
	def_deleteSignInst func_deleteSignInst{};

	bool isInit{ false };
	bool isOwner{ false };
	void* cryptoContext{ nullptr };
	void* signInst{ nullptr };
	SignAlgDef algDef{};
	type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

	Signanture(type_sharedLibHandle libH_, void* cryptoContext_, SignAlgDef algDef_, bool own)
		: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), libH(libH_)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext != nullptr);
	}
	~Signanture()
	{
		if (!isInit || !isOwner)
			return;

		const auto res = func_deleteSignInst(cryptoContext, signInst);
		assert(res);
	}

	void init()
	{
		assert(!isInit);
		assert(libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		int32_t error{};
		if (isOwner)
		{
			signInst = func_createSignAlgInstanse(cryptoContext, static_cast<std::underlying_type_t<SignAlgDef>>(algDef), &error);

			if (error != 0)
				throw error;
		}

		isInit = true;
	}

	bool deleteSignInst(void* cryptoContext, void* signContext)
	{
		return func_deleteSignInst(cryptoContext, signContext);
	}
	void* createSignAlgInstanse(void* cryptoContext, int32_t* error_out)
	{
		return func_createSignAlgInstanse(cryptoContext, static_cast<std::underlying_type_t<SignAlgDef>>(algDef), error_out);
	}
	bool importByPass(void* container, size_t lenOfContainer, const mchar* pass, int32_t* error_out) const
	{
		return importByPass(signInst, container, lenOfContainer, pass, error_out);
	}
	bool importByPass(void* signContext, void* container, size_t lenOfContainer, const mchar* pass, int32_t* error_out) const
	{
		return func_importByPass(signContext, container, lenOfContainer, pass, error_out);
	}
	void* exportByPass(const mchar* pass, size_t* len_out, int32_t* error_out)
	{
		return exportByPass(signInst, pass, len_out, error_out);
	}
	void* exportByPass(void* signContext, const mchar* pass, size_t* len_out, int32_t* error_out)
	{
		return func_exportByPass(signContext, pass, reinterpret_cast<uint32_t*>(len_out), error_out);
	}
	void* sign(const uint8_t* dataRawPtr, size_t sizeOfData, size_t* sizeOfSign_out, int32_t* error_out)
	{
		return sign(signInst, dataRawPtr, sizeOfData, sizeOfSign_out, error_out);
	}
	void* sign(void* signContext, const uint8_t* dataRawPtr, size_t sizeOfData, size_t* sizeOfSign_out, int32_t* error_out)
	{
		return func_sign(signContext, dataRawPtr, static_cast<uint32_t>(sizeOfData), reinterpret_cast<uint32_t*>(sizeOfSign_out), 
			error_out);
	}
	bool verify(uint8_t* dataRawPtr, size_t sizeOfData, uint8_t* signRawPtr,
		size_t sizeOfSign, int32_t* error_out)
	{
		return verify(signInst, dataRawPtr, sizeOfData, signRawPtr, sizeOfSign, error_out);
	}
	bool verify(void* signContext, uint8_t* dataRawPtr, size_t sizeOfData, uint8_t* signRawPtr,
		size_t sizeOfSign, int32_t* error_out)
	{
		return func_verify(signContext, dataRawPtr, static_cast<uint32_t>(sizeOfData), signRawPtr, 
			static_cast<uint32_t>(sizeOfSign), error_out);
	}
	bool importPublicData(void* publicData, size_t lenOfPublicData, bool includeAllPublicData, int32_t* error_out) const
	{
		return importPublicData(signInst, publicData, lenOfPublicData, includeAllPublicData, error_out);
	}
	bool importPublicData(void* signContext, void* publicData, size_t lenOfPublicData,
		bool includeAllPublicData, int32_t* error_out) const
	{
		return func_importPublicData(signContext, publicData, static_cast<uint32_t>(lenOfPublicData),
			includeAllPublicData, error_out);
	}
	void* exportPublicData(size_t* len_out, bool includeAllPublicData, int32_t* error_out)
	{
		return exportPublicData(signInst, len_out, includeAllPublicData, error_out);
	}
	void* exportPublicData(void* signContext, size_t* len_out, bool includeAllPublicData, int32_t* error_out)
	{
		return func_exportPublicData(signContext, reinterpret_cast<uint32_t*>(len_out), includeAllPublicData, error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign_exportPublicData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_exportPublicData = reinterpret_cast<def_exportPublicData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign_importPublicData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_importPublicData = reinterpret_cast<def_importPublicData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign_deleteSignInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_deleteSignInst = reinterpret_cast<def_deleteSignInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign_createSignAlgInstanse);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_createSignAlgInstanse = reinterpret_cast<def_createSignAlgInstanse>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign_exportByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_exportByPass = reinterpret_cast<def_exportByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign_importByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_importByPass = reinterpret_cast<def_importByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_sign = reinterpret_cast<def_sign>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_sign_verify);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_verify = reinterpret_cast<def_verify>(funcAddress);
	}
};