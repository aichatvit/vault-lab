#pragma once

#include <cstdint>
#include <cassert>
#include <type_traits>

#include "../../Common/mstring.h"
#include "../../SharedLibFuncs/SymmAlgDef.h"
#include "../../SharedLibFuncs/SymmAlgMode.h"
#include "../SystemAbstractions/SystemPrimitives.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "../../SharedLibFuncs/SymmAlgData.h"

class Symmetric
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_sym_getData{ "sym_getData" };
	static constexpr const char* name_sym_importKeyBySymAlg{ "sym_importKeyBySymAlg" };
	static constexpr const char* name_sym_exportKeyBySymAlg{ "sym_exportKeyBySymAlg" };
	static constexpr const char* name_sym_importKeyByAssymetricEncrypter{ "sym_importKeyByAssymetricEncrypter" };
	static constexpr const char* name_sym_exportKeyByAssymetricEncrypter{ "sym_exportKeyByAssymetricEncrypter" };
	static constexpr const char* name_sym_importKeyByPass{ "sym_importKeyByPass" };
	static constexpr const char* name_sym_exportKeyByPass{ "sym_exportKeyByPass" };
	static constexpr const char* name_sym_decrypt{ "sym_decrypt" };
	static constexpr const char* name_sym_encrypt{ "sym_encrypt" };
	static constexpr const char* name_sym_setKey{ "sym_setKey" };
	static constexpr const char* name_sym_getKey{ "sym_getKey" };
	static constexpr const char* name_sym_deleteInst{ "sym_deleteInst" };
	static constexpr const char* name_sym_createSymAlgInstanceByPass{ "sym_createSymAlgInstance_pass" };
	static constexpr const char* name_sym_createSymAlgInstance{ "sym_createSymAlgInstance" };

	typedef bool (*def_getData)(void* symInst, SymmAlgData* algData_out, int32_t* error_out);
	typedef bool (*def_importKeyBySymAlg)(void* symInst, void* symInst_export, const uint8_t* container,
		uint32_t lenOfContainer, int32_t* error_out);
	typedef void* (*def_exportKeyBySymAlg)(void* symInst, void* symInst_export, uint32_t* lenOfContainer_out, int32_t* error_out);
	typedef bool (*def_importKeyByAssymetricEncrypter)(void* symInst, void* assymetricEncrypterInst, const uint8_t* container,
		uint32_t lenOfContainer, int32_t* error_out);
	typedef void* (*def_exportKeyByAssymetricEncrypter)(void* symInst, void* assymetricEncrypterInst,
		uint32_t* lenOfContainer_out, int32_t* error_out);
	typedef bool (*def_importKeyByPass)(void* symInst, const mchar* pass, const uint8_t* container, uint32_t lenOfContainer,
		int32_t* error_out);
	typedef void* (*def_exportKeyByPass)(void* symInst, const mchar* pass, uint32_t* lenOfContainer_out, int32_t* error_out);
	typedef bool (*def_decrypt)(void* symInst, const uint8_t* data, uint32_t lenOfData, uint8_t* result, uint32_t lenOfResult,
		const uint8_t* iv, uint32_t lenOfIv, int32_t* error_out);
	typedef bool (*def_encrypt)(void* symInst, const uint8_t* data, uint32_t lenOfData, uint8_t* result, uint32_t lenOfResult,
		const uint8_t* iv, uint32_t lenOfIv, int32_t* error_out);
	typedef bool (*def_setKey)(void* symInst, const uint8_t* key, uint32_t lenOfKey, int32_t* error_out);
	typedef void* (*def_getKey)(void* symInst, uint32_t* len_out, int32_t* error_out);
	typedef bool (*def_deleteInst)(void* cryptoContext, void* symInst);
	typedef void* (*def_createSymAlgInstance_pass)(void* cryptoContext, const char* pass, uint32_t lenOfPass, 
		const uint8_t* salt, uint32_t lengthOfSalt, int32_t* error_out);
	typedef void* (*def_createSymAlgInstance)(void* cryptoContext, int32_t algDef, int32_t mode, int32_t* error_out);

	struct _Internal_ {
		def_getData func_getData{};
		def_importKeyBySymAlg func_importKeyBySymAlg{};
		def_exportKeyBySymAlg func_exportKeyBySymAlg{};
		def_importKeyByAssymetricEncrypter func_importKeyByAssymetricEncrypter{};
		def_exportKeyByAssymetricEncrypter func_exportKeyByAssymetricEncrypter{};
		def_importKeyByPass func_importKeyByPass{};
		def_exportKeyByPass func_exportKeyByPass{};
		def_decrypt func_decrypt{};
		def_encrypt func_encrypt{};
		def_setKey func_setKey{};
		def_getKey func_getKey{};
		def_deleteInst func_deleteInst{};
		def_createSymAlgInstance func_createSymAlgInstance{};
		def_createSymAlgInstance_pass func_createSymAlgInstanceByPass{};

		bool isInit{ false };
		bool isOwner{ false };
		void* cryptoContext{ nullptr };
		void* symmInst{ nullptr };
		SymmAlgDef algDef{ SymmAlgDef::Gost_34_12 };
		SymmAlgMode algMode{ SymmAlgMode::cbc };
		type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };
		SymmAlgData data_{};

		_Internal_(type_sharedLibHandle libH_, void* cryptoContext_, bool own) 
			: isOwner(own), cryptoContext(cryptoContext_), libH(libH_) {
		}
		_Internal_(type_sharedLibHandle libH_, void* cryptoContext_, SymmAlgDef algDef_, SymmAlgMode algMode_, bool own) 
			: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), libH(libH_), algMode(algMode_) {
		}
	};

	_Internal_ inst;

	Symmetric(type_sharedLibHandle libH_, void* cryptoContext_, bool own) :
		inst(libH_, cryptoContext_, own) {
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext_ != nullptr);
	}
	Symmetric(type_sharedLibHandle libH_, void* cryptoContext_, SymmAlgDef algDef_, SymmAlgMode algMode_, bool own)
		: inst(libH_, cryptoContext_, algDef_, algMode_, own) 
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext_ != nullptr);
	}
	Symmetric(const Symmetric&) = delete;
	Symmetric(Symmetric&& obj) noexcept
		: inst(std::move(obj.inst)) {
		obj.inst.isInit = false;
		obj.inst.isOwner = false;
	}
	Symmetric& operator=(const Symmetric&) = delete;
	Symmetric& operator=(Symmetric&& obj) {
		this->~Symmetric();

		inst = std::move(obj.inst);

		obj.inst.isInit = false;
		obj.inst.isOwner = false;
		return *this;
	}
	~Symmetric()
	{
		if (!inst.isInit || !inst.isOwner)
			return;

		inst.isInit = false;
		const auto res = inst.func_deleteInst(inst.cryptoContext, inst.symmInst);
		assert(res);
	}

	[[nodiscard]] const SymmAlgData& getData() const
	{
		return inst.data_;
	}

	int32_t init(const char* pass, size_t lengthOfPass, const uint8_t* salt, size_t lengthOfSalt) {
		assert(!inst.isInit);
		assert(inst.libH != SystemPrimitives::nullLibHandle);

		loadFunctions();

		int32_t error{};
		inst.symmInst = inst.func_createSymAlgInstanceByPass(inst.cryptoContext, pass, lengthOfPass, salt, lengthOfSalt, &error);
		if (error != 0)
			return error;
		getData(inst.symmInst, &inst.data_, &error);
		if (error != 0)
			return error;

		inst.isInit = true;
		return 0;
	}
	int32_t init()
	{
		using namespace std;

		assert(!inst.isInit);
		assert(inst.libH != SystemPrimitives::nullLibHandle);

		loadFunctions();

		int32_t error{};
		static_assert(is_same_v<std::underlying_type_t<SymmAlgDef>, int32_t>);
		static_assert(is_same_v<std::underlying_type_t<SymmAlgMode>, int32_t>);
		inst.symmInst = inst.func_createSymAlgInstance(inst.cryptoContext, static_cast<std::underlying_type_t<SymmAlgDef>>(inst.algDef),
			static_cast<std::underlying_type_t<SymmAlgMode>>(inst.algMode), &error);
		if (error != 0)
			return error;
		getData(inst.symmInst, &inst.data_, &error);
		if (error != 0)
			return error;

		inst.isInit = true;
		return 0;
	}

	bool getData(void* symInst, SymmAlgData* algData_out, int32_t* error_out) const
	{
		return inst.func_getData(symInst, algData_out, error_out);
	}
	void* createSymAlgInstanceByPass(void* cryptoContext, const char* pass, size_t lenOfPass, 
		const uint8_t* salt, size_t lengthOfSalt, int32_t* error_out) {
		return inst.func_createSymAlgInstanceByPass(cryptoContext, pass, static_cast<uint32_t>(lenOfPass), salt,
			static_cast<uint32_t>(lengthOfSalt), error_out);
	}
	void* createSymAlgInstance(void* cryptoContext, SymmAlgDef algDef, SymmAlgMode mode, int32_t* error_out)
	{
		using namespace std;

		static_assert(is_same_v<std::underlying_type_t<SymmAlgDef>, int32_t>);
		static_assert(is_same_v<std::underlying_type_t<SymmAlgMode>, int32_t>);
		return inst.func_createSymAlgInstance(cryptoContext, static_cast<std::underlying_type_t<SymmAlgDef>>(algDef),
			static_cast<std::underlying_type_t<SymmAlgMode>>(inst.algMode), error_out);
	}
	bool deleteInst(void* cryptoContext, void* symInst) const
	{
		return inst.func_deleteInst(cryptoContext, symInst);
	}
	void* getKey(uint32_t* len_out, int32_t* error_out) const {
		return inst.func_getKey(inst.symmInst, len_out, error_out);
	}
	void* getSymInst() const { return inst.symmInst; }
	bool setKey(const uint8_t* key, size_t lenOfKey, int32_t* error_out) const
	{
		return setKey(inst.symmInst, key, static_cast<uint32_t>(lenOfKey), error_out);
	}
	bool setKey(void* symInst, const uint8_t* key, size_t lenOfKey, int32_t* error_out) const
	{
		return inst.func_setKey(symInst, key, static_cast<uint32_t>(lenOfKey), error_out);
	}
	bool encrypt(const uint8_t* data, size_t lenOfData, uint8_t* result, size_t lenOfResult, const uint8_t* iv,
		size_t lenOfIv, int32_t* error_out) const
	{
		return encrypt(inst.symmInst, data, lenOfData, result, lenOfResult, iv, lenOfIv, error_out);
	}
	bool encrypt(void* symInst, const uint8_t* data, size_t lenOfData, uint8_t* result, size_t lenOfResult, const uint8_t* iv,
		size_t lenOfIv, int32_t* error_out) const
	{
		return inst.func_encrypt(symInst, data, static_cast<uint32_t>(lenOfData), result, static_cast<uint32_t>(lenOfResult), iv,
			static_cast<uint32_t>(lenOfIv), error_out);
	}
	bool decrypt(const uint8_t* data, size_t lenOfData, uint8_t* result, size_t lenOfResult, const uint8_t* iv,
		size_t lenOfIv, int32_t* error_out) const
	{
		return decrypt(inst.symmInst, data, static_cast<uint32_t>(lenOfData), result, lenOfResult, iv,
			lenOfIv, error_out);
	}
	bool decrypt(void* symInst, const uint8_t* data, size_t lenOfData, uint8_t* result, size_t lenOfResult, const uint8_t* iv,
		size_t lenOfIv, int32_t* error_out) const
	{
		return inst.func_decrypt(symInst, data, static_cast<uint32_t>(lenOfData), result, static_cast<uint32_t>(lenOfResult), iv,
			static_cast<uint32_t>(lenOfIv), error_out);
	}
	void* exportKeyByPass(const mchar* pass, size_t* lenOfContainer_out, int32_t* error_out) const
	{
		return exportKeyByPass(inst.symmInst, pass, lenOfContainer_out, error_out);
	}
	void* exportKeyByPass(void* symInst, const mchar* pass, size_t* lenOfContainer_out, int32_t* error_out) const
	{
		return inst.func_exportKeyByPass(symInst, pass, reinterpret_cast<uint32_t*>(lenOfContainer_out), error_out);
	}
	bool importKeyByPass(const mchar* pass, const uint8_t* container, size_t lenOfContainer,
		int32_t* error_out) const
	{
		return importKeyByPass(inst.symmInst, pass, container, lenOfContainer, error_out);
	}
	bool importKeyByPass(void* symInst, const mchar* pass, const uint8_t* container, size_t lenOfContainer,
		int32_t* error_out) const
	{
		return inst.func_importKeyByPass(symInst, pass, container, static_cast<uint32_t>(lenOfContainer), error_out);
	}
	void* exportKeyByAssymetricEncrypter(void* assymetricEncrypterInst, size_t* lenOfContainer_out,
		int32_t* error_out) const
	{
		return exportKeyByAssymetricEncrypter(inst.symmInst, assymetricEncrypterInst, lenOfContainer_out, error_out);
	}
	void* exportKeyByAssymetricEncrypter(void* symInst, void* assymetricEncrypterInst, size_t* lenOfContainer_out, 
		int32_t* error_out) const
	{
		return inst.func_exportKeyByAssymetricEncrypter(symInst, assymetricEncrypterInst,
			reinterpret_cast<uint32_t*>(lenOfContainer_out), error_out);
	}
	bool importKeyByAssymetricEncrypter(void* assymetricEncrypterInst, const uint8_t* container,
		size_t lenOfContainer, int32_t* error_out) const
	{
		return importKeyByAssymetricEncrypter(inst.symmInst, assymetricEncrypterInst, container, lenOfContainer,
			error_out);
	}
	bool importKeyByAssymetricEncrypter(void* symInst, void* assymetricEncrypterInst, const uint8_t* container,
		size_t lenOfContainer, int32_t* error_out) const
	{
		return inst.func_importKeyByAssymetricEncrypter(symInst, assymetricEncrypterInst, container, static_cast<uint32_t>(lenOfContainer),
			error_out);
	}
	void* exportKeyBySymAlg(void* symInst_export, size_t* lenOfContainer_out, int32_t* error_out) const
	{
		return exportKeyBySymAlg(inst.symmInst, symInst_export, lenOfContainer_out, error_out);
	}
	void* exportKeyBySymAlg(void* symInst, void* symInst_export, size_t* lenOfContainer_out, int32_t* error_out) const
	{
		return inst.func_exportKeyBySymAlg(symInst, symInst_export, reinterpret_cast<uint32_t*>(lenOfContainer_out), error_out);
	}
	bool importKeyBySymAlg(void* symInst_export, const uint8_t* container, size_t lenOfContainer,
		int32_t* error_out) const
	{
		return importKeyBySymAlg(inst.symmInst, symInst_export, container, lenOfContainer, error_out);
	}
	bool importKeyBySymAlg(void* symInst, void* symInst_export, const uint8_t* container, size_t lenOfContainer, 
		int32_t* error_out) const
	{
		return inst.func_importKeyBySymAlg(symInst, symInst_export, container, static_cast<uint32_t>(lenOfContainer), error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };
		
		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_getKey);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_getKey = reinterpret_cast<def_getKey>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_createSymAlgInstanceByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_createSymAlgInstanceByPass = reinterpret_cast<def_createSymAlgInstance_pass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_getData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_getData = reinterpret_cast<def_getData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_createSymAlgInstance);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_createSymAlgInstance = reinterpret_cast<def_createSymAlgInstance>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_deleteInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_deleteInst = reinterpret_cast<def_deleteInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_setKey);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_setKey = reinterpret_cast<def_setKey>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_encrypt);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_encrypt = reinterpret_cast<def_encrypt>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_decrypt);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_decrypt = reinterpret_cast<def_decrypt>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_exportKeyByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_exportKeyByPass = reinterpret_cast<def_exportKeyByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_importKeyByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_importKeyByPass = reinterpret_cast<def_importKeyByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_exportKeyByAssymetricEncrypter);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_exportKeyByAssymetricEncrypter = reinterpret_cast<def_exportKeyByAssymetricEncrypter>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_importKeyByAssymetricEncrypter);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_importKeyByAssymetricEncrypter = reinterpret_cast<def_importKeyByAssymetricEncrypter>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_exportKeyBySymAlg);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_exportKeyBySymAlg = reinterpret_cast<def_exportKeyBySymAlg>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_sym_importKeyBySymAlg);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_importKeyBySymAlg = reinterpret_cast<def_importKeyBySymAlg>(funcAddress);
	}
};