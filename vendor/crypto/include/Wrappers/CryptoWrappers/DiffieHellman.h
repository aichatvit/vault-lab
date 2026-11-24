#pragma once

#include <cassert>

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "InitMethodType.h"
#include "../../SharedLibFuncs/DiffieHellmanAlgDef.h"

class DiffieHellman
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_DiffieHellman_createDiffHellInst{ "DiffieHellman_createDiffHellInst" };
	static constexpr const char* name_DiffieHellman_deleteDiffHellInst{ "DiffieHellman_deleteDiffHellInst" };
	static constexpr const char* name_DiffieHellman_importByPass{ "DiffieHellman_importByPass" };
	static constexpr const char* name_DiffieHellman_exportByPass{ "DiffieHellman_exportByPass" };
	static constexpr const char* name_DiffieHellman_importPublicData{ "DiffieHellman_importPublicData" };
	static constexpr const char* name_DiffieHellman_exportPublicData{ "DiffieHellman_exportPublicData" };
	static constexpr const char* name_DiffieHellman_deriveKeyMaterial{ "DiffieHellman_deriveKeyMaterial" };
	static constexpr const char* name_DiffieHellman_exportDerivedKeyMaterialByPass{ "DiffieHellman_exportDerivedKeyMaterialByPass" };
	static constexpr const char* name_DiffieHellman_getAdditionalPrivateParams{ "DiffieHellman_getAdditionalPrivateParams" };
	static constexpr const char* name_DiffieHellman_setAdditionalPrivateParams{ "DiffieHellman_setAdditionalPrivateParams" };

	typedef void* (*def_createDiffHellInst)(void* cryptoContext, int32_t algDef, int32_t* error_out);
	typedef bool (*def_deleteDiffHellInst)(void* cryptoContext, void* diffContext);
	typedef bool (*def_importByPass)(void* diffContext, const uint8_t* container, uint32_t lenOfContainer, const mchar* pass, 
		int32_t* error_out);
	typedef void* (*def_exportByPass)(void* diffContext, const mchar* pass, uint32_t* size_out, int32_t* error_out);
	typedef bool (*def_importPublicData)(void* diffContext, void* publicData, uint32_t lenOfPublicData,
		bool includeAllPublicData, int32_t* error_out);
	typedef void* (*def_exportPublicData)(void* diffContext, bool includeAllPublicData, uint32_t* len_out, int32_t* error_out);
	typedef void* (*def_deriveKeyMaterial)(void* diffContext, void* seq, uint32_t lenOfSeq, uint32_t* len_out,
		int32_t* error_out, bool* finish);
	typedef void* (*def_exportDerivedKeyMaterialByPass)(void* diffContext, const mchar* pass, uint32_t* len_out, int32_t* error_out);
	typedef void* (*def_getAdditionalPrivateParams)(void* diffContext, uint32_t* size_out, int32_t* error_out);
	typedef bool (*def_setAdditionalPrivateParams)(void* diffContext, const void* memory, uint32_t size, int32_t* error_out);

	def_createDiffHellInst func_createDiffHellInst{};
	def_deleteDiffHellInst func_deleteDiffHellInst{};
	def_importByPass func_importByPass{};
	def_exportByPass func_exportByPass{};
	def_importPublicData func_importPublicData{};
	def_exportPublicData func_exportPublicData{};
	def_deriveKeyMaterial func_deriveKeyMaterial{};
	def_exportDerivedKeyMaterialByPass func_exportDerivedKeyMaterialByPass{};
	def_getAdditionalPrivateParams func_getAdditionalPrivateParams{};
	def_setAdditionalPrivateParams func_setAdditionalPrivateParams{};

	bool isInit{ false };
	bool isOwner{ false };
	void* cryptoContext{ nullptr };
	void* diffHellInst{ nullptr };
	DiffieHellmanAlgDef algDef{};
	type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

	DiffieHellman(type_sharedLibHandle libH_, void* cryptoContext_, DiffieHellmanAlgDef algDef_, bool own)
		: isOwner(own), cryptoContext(cryptoContext_), algDef(algDef_), libH(libH_)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext != nullptr);
	}
	~DiffieHellman()
	{
		if (!isInit || !isOwner)
			return;

		const auto res = func_deleteDiffHellInst(cryptoContext, diffHellInst);
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
			diffHellInst = func_createDiffHellInst(cryptoContext, static_cast<std::underlying_type_t<DiffieHellmanAlgDef>>(algDef),
				&error);

			if (error != 0)
				throw error;
		}

		isInit = true;
	}

	void* createDiffHellInst(void* cryptoContext, int32_t* error_out)
	{
		return func_createDiffHellInst(cryptoContext, static_cast<std::underlying_type_t<decltype(algDef)>>(algDef), error_out);
	}
	bool deleteDiffHellInst(void* cryptoContext, void* diffContext)
	{
		return func_deleteDiffHellInst(cryptoContext, diffContext);
	}
	bool importByPass(const uint8_t* container, size_t lenOfContainer, const mchar* pass, int32_t* error) const
	{
		return importByPass(diffHellInst, container, lenOfContainer, pass, error);
	}
	bool importByPass(void* diffContext, const uint8_t* container, size_t lenOfContainer, const mchar* pass, int32_t* error) const
	{
		return func_importByPass(diffContext, container, static_cast<uint32_t>(lenOfContainer), pass, error);
	}
	void* exportByPass(const mchar* pass, size_t* size_out, int32_t* error_out) const 
	{
		return exportByPass(diffHellInst, pass, size_out, error_out);
	}
	void* exportByPass(void* diffContext, const mchar* pass, size_t* size_out, int32_t* error_out) const
	{
		return func_exportByPass(diffContext, pass, reinterpret_cast<uint32_t*>(size_out), error_out);
	}
	bool importPublicData(void* publicData, uint32_t lenOfPublicData, bool includeAllPublicData,
		int32_t* error_out) const
	{
		return importPublicData(diffHellInst, publicData, lenOfPublicData, includeAllPublicData, error_out);
	}
	bool importPublicData(void* diffContext, void* publicData, uint32_t lenOfPublicData, bool includeAllPublicData, 
		int32_t* error_out) const
	{
		return func_importPublicData(diffContext, publicData, lenOfPublicData, includeAllPublicData, error_out);
	}
	void* exportPublicData(bool includeAllPublicData, size_t* len_out, int32_t* error_out)
	{
		return exportPublicData(diffHellInst, includeAllPublicData, len_out, error_out);
	}
	void* exportPublicData(void* diffContext, bool includeAllPublicData, size_t* len_out, int32_t* error_out)
	{
		return func_exportPublicData(diffContext, includeAllPublicData, reinterpret_cast<uint32_t*>(len_out), error_out);
	}
	void* deriveKeyMaterial(void* seq, size_t lenOfSeq, size_t* len_out, int32_t* error_out, bool* finish)
	{
		return deriveKeyMaterial(diffHellInst, seq, lenOfSeq, len_out, error_out, finish);
	}
	void* deriveKeyMaterial(void* diffContext, void* seq, size_t lenOfSeq, size_t* len_out, int32_t* error_out, bool* finish)
	{
		return func_deriveKeyMaterial(diffContext, seq, static_cast<uint32_t>(lenOfSeq), reinterpret_cast<uint32_t*>(len_out), 
			error_out, finish);
	}
	void* exportDerivedKeyMaterialByPass(const mchar* pass, size_t* len_out, int32_t* error_out)
	{
		return exportDerivedKeyMaterialByPass(diffHellInst, pass, len_out, error_out);
	}
	void* exportDerivedKeyMaterialByPass(void* diffContext, const mchar* pass, size_t* len_out, int32_t* error_out)
	{
		return func_exportDerivedKeyMaterialByPass(diffContext, pass, reinterpret_cast<uint32_t*>(len_out), error_out);
	}
	void* getAdditionalPrivateParams(size_t* size_out, int32_t* error_out)
	{
		return getAdditionalPrivateParams(diffHellInst, size_out, error_out);
	}
	void* getAdditionalPrivateParams(void* diffContext, size_t* size_out, int32_t* error_out)
	{
		return func_getAdditionalPrivateParams(diffContext, reinterpret_cast<uint32_t*>(size_out), 
			error_out);
	}
	bool setAdditionalPrivateParams(const void* memory, size_t size, int32_t* error_out) const
	{
		return setAdditionalPrivateParams(diffHellInst, memory, static_cast<uint32_t>(size), error_out);
	}
	bool setAdditionalPrivateParams(void* diffContext, const void* memory, uint32_t size, int32_t* error_out) const
	{
		return func_setAdditionalPrivateParams(diffContext, memory, size, error_out);
	}

	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_createDiffHellInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_createDiffHellInst = reinterpret_cast<def_createDiffHellInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_deleteDiffHellInst);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_deleteDiffHellInst = reinterpret_cast<def_deleteDiffHellInst>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_importByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_importByPass = reinterpret_cast<def_importByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_exportByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_exportByPass = reinterpret_cast<def_exportByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_importPublicData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_importPublicData = reinterpret_cast<def_importPublicData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_exportPublicData);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_exportPublicData = reinterpret_cast<def_exportPublicData>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_deriveKeyMaterial);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_deriveKeyMaterial = reinterpret_cast<def_deriveKeyMaterial>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_exportDerivedKeyMaterialByPass);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_exportDerivedKeyMaterialByPass = reinterpret_cast<def_exportDerivedKeyMaterialByPass>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_getAdditionalPrivateParams);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_getAdditionalPrivateParams = reinterpret_cast<def_getAdditionalPrivateParams>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(libH, name_DiffieHellman_setAdditionalPrivateParams);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		func_setAdditionalPrivateParams = reinterpret_cast<def_setAdditionalPrivateParams>(funcAddress);
	}
};