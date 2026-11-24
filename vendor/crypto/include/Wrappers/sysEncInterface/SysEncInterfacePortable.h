#pragma once

#include <cstdint>
#include <cassert>
#include <type_traits>

#include "../../Common/mstring.h"
#include "../SystemAbstractions/SystemPrimitives.h"
#include "../SystemAbstractions/SharedLibOwner.h"

#include "../../SharedLibFuncs/sysEncInterface/sysEncInterface.h"

class SysEncInterfacePortable {
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_encSymKey{ "encSymKey" };
	static constexpr const char* name_decSymKey{ "decSymKey" };
	static constexpr const char* name_setRandomSeq{ "setRandomSeq" };
	static constexpr const char* name_encBySymKey{ "encBySymKey" };
	static constexpr const char* name_decBySymKey{ "decBySymKey" };
	static constexpr const char* name_encBySymKey_co{ "encBySymKey_co" };
	static constexpr const char* name_decBySymKey_co{ "decBySymKey_co" };

	typedef int32_t(*def_encSymKey)(const void* symKey, const uint32_t lenOfSymKey, const char* pass, const int32_t pass_encoding,
		const uint32_t lenOfPass, void* buf_symKeyContainer_out, uint32_t* lenOfSymKeyContainer_out, const int32_t flags);
	typedef int32_t(*def_decSymKey)(const void* symKeyContainer, const uint32_t lenOfSymKeyContainer, const char* pass,
		const int32_t pass_encoding, const uint32_t lenOfPass, void* buf_symKey_out, uint32_t lenOfSymKey,
		const int32_t flags);
	typedef int32_t(*def_setRandomSeq)(void* seq, const uint32_t lenOfSeq, const int32_t flags);
	typedef int32_t(*def_encBySymKey)(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);
	typedef int32_t(*def_decBySymKey)(const int32_t algDef, const int32_t mode, const void* seqToDec, const uint32_t lenOfSeqToDec,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);
	typedef int32_t(*def_encBySymKey_co)(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);
	typedef int32_t(*def_decBySymKey_co)(const void* container, const uint32_t len_of_container, const void* key, const uint32_t keyLen,
		void* result_out, uint32_t* result_len_in_out, const int32_t flags);

	struct _Internal_ {
		def_encSymKey func_encSymKey{};
		def_decSymKey func_decSymKey{};
		def_setRandomSeq func_setRandomSeq{};
		def_encBySymKey func_encBySymKey{};
		def_decBySymKey func_decBySymKey{};
		def_encBySymKey_co func_encBySymKey_co{};
		def_decBySymKey_co func_decBySymKey_co{};

		bool isInit{ false };
		//bool isOwner{ false };
		//void* cryptoContext{ nullptr };
		//void* symmInst{ nullptr };
		type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

		_Internal_(type_sharedLibHandle libH_/*, void* cryptoContext_, bool own*/)
			: /*isOwner(own), cryptoContext(cryptoContext_),*/ libH(libH_) {
		}
	};

	_Internal_ inst;

	SysEncInterfacePortable(type_sharedLibHandle libH_) : inst(libH_) {

	}
	SysEncInterfacePortable(const SysEncInterfacePortable&) = default;
	SysEncInterfacePortable(SysEncInterfacePortable&& obj) = default;
	SysEncInterfacePortable& operator=(const SysEncInterfacePortable&) = default;
	SysEncInterfacePortable& operator=(SysEncInterfacePortable&& obj) = default;

	int32_t init() {
		assert(!inst.isInit);
		assert(inst.libH != SystemPrimitives::nullLibHandle);

		loadFunctions();

		inst.isInit = true;
		return 0;
	}

	/*EXPORT int32_t CDECL encSymKey(const void* symKey, const uint32_t lenOfSymKey, const char* pass, const int32_t pass_encoding,
	const uint32_t lenOfPass, void* buf_symKeyContainer_out, uint32_t* lenOfSymKeyContainer_out, const int32_t flags);*/
	int32_t encSymKey(const void* symKey, const uint32_t lenOfSymKey, const char* pass, const int32_t pass_encoding,
		const uint32_t lenOfPass, void* buf_symKeyContainer_out, uint32_t* lenOfSymKeyContainer_out, const int32_t flags) {
		return inst.func_encSymKey(symKey, lenOfSymKey, pass, pass_encoding, lenOfPass, buf_symKeyContainer_out,
			lenOfSymKeyContainer_out, flags);
	}
	/*EXPORT int32_t CDECL decSymKey(const void* symKeyContainer, const uint32_t lenOfSymKeyContainer, const char* pass,
	const int32_t pass_encoding, const uint32_t lenOfPass, void* buf_symKey_out, uint32_t lenOfSymKey,
	const int32_t flags);*/
	int32_t decSymKey(const void* symKeyContainer, const uint32_t lenOfSymKeyContainer, const char* pass,
		const int32_t pass_encoding, const uint32_t lenOfPass, void* buf_symKey_out, uint32_t lenOfSymKey,
		const int32_t flags) {
		return inst.func_decSymKey(symKeyContainer, lenOfSymKeyContainer, pass, pass_encoding, lenOfPass,
			buf_symKey_out, lenOfSymKey, flags);
	}
	/*EXPORT int32_t CDECL setRandomSeq(void* seq, const uint32_t lenOfSeq, const int32_t flags);*/
	int32_t setRandomSeq(void* seq, const uint32_t lenOfSeq, const int32_t flags) {
		return inst.func_setRandomSeq(seq, lenOfSeq, flags);
	}
	/*EXPORT int32_t CDECL encBySymKey(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
	const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);*/
	int32_t encBySymKey(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags) {
		return inst.func_encBySymKey(algDef, mode, seqToEnc, lenOfSeqToEnc_in_out, key, keyLen, result_out, iv, lenOfIv, flags);
	}
	/*EXPORT int32_t CDECL decBySymKey(const int32_t algDef, const int32_t mode, const void* seqToDec, const uint32_t lenOfSeqToDec,
	const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);*/
	int32_t decBySymKey(const int32_t algDef, const int32_t mode, const void* seqToDec, const uint32_t lenOfSeqToDec,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags) {
		return inst.func_decBySymKey(algDef, mode, seqToDec, lenOfSeqToDec, key, keyLen, result_out, iv, lenOfIv, flags);
	}
	/*
	EXPORT int32_t CDECL encBySymKey_co(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);
		int32_t*/
	int32_t encBySymKey_co(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags) {
		return inst.func_encBySymKey_co(algDef, mode, seqToEnc, lenOfSeqToEnc_in_out, key, keyLen, result_out, iv, lenOfIv, flags);
	}
	/*EXPORT int32_t CDECL decBySymKey_co(const void* container, const uint32_t len_of_container, const void* key, const uint32_t keyLen,
		void* result_out, uint32_t* result_len_in_out, const int32_t flags);*/
	int32_t decBySymKey_co(const void* container, const uint32_t len_of_container, const void* key, const uint32_t keyLen,
		void* result_out, uint32_t* result_len_in_out, const int32_t flags) {
		return inst.func_decBySymKey_co(container, len_of_container, key, keyLen, result_out, result_len_in_out, flags);
	}

private:
	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_decBySymKey_co);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_decBySymKey_co = reinterpret_cast<def_decBySymKey_co>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_encBySymKey_co);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_encBySymKey_co = reinterpret_cast<def_encBySymKey_co>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_encSymKey);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_encSymKey = reinterpret_cast<def_encSymKey>(funcAddress);
	
		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_decSymKey);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_decSymKey = reinterpret_cast<def_decSymKey>(funcAddress);
	
		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_setRandomSeq);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_setRandomSeq = reinterpret_cast<def_setRandomSeq>(funcAddress);
	
		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_encBySymKey);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_encBySymKey = reinterpret_cast<def_encBySymKey>(funcAddress);
	
		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_decBySymKey);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_decBySymKey = reinterpret_cast<def_decBySymKey>(funcAddress);
	}
};