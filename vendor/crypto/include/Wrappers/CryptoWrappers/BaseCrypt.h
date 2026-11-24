#pragma once

#include <cassert>

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "InitMethodType.h"
#include "../../SharedLibFuncs/HmacAlgDef.h"
#include "../../SharedLibFuncs/HmacData.h"

#include "CryptoInitByCont.h"

#include "../../SharedLibFuncs/CryptoContextParams/TypeOfParams.h"
#include "../../SharedLibFuncs/CryptoContextParams/SeqParams.h"
#include "../../SharedLibFuncs/CryptoContextParams/SigSeqParams.h"
#include "../../SharedLibFuncs/CryptoContextParams/ContainerParams.h"

template<typename TInitParams>
class BaseCrypt
{
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	static constexpr const char* name_Hmac_getData_KeySizes{ "Hmac_getData_KeySizes" };
	static constexpr const char* name_destroyMemory{ "destroyMemory" };
	static constexpr const char* name_createCryptoContextBySignSeq{ "createCryptoContextBySignSeq" };
	static constexpr const char* name_createCryptoContext{ "createCryptoContext" };
	static constexpr const char* name_destroyCryptoContext{ "destroyCryptoContext" };
	static constexpr const char* name_createKkp{ "createKkp" };
	static constexpr const char* name_createCryptoContextByParams{ "createCryptoContextByParams" };
	//static constexpr char* name_destroyKkp{ "destroyKkp" };

	typedef void (*def_Hmac_getData_KeySizes)(int32_t algDef, int32_t hmacLen, HmacData_KeySizes* data, int32_t* error_out);
	typedef bool (*def_destroyMemory)(void* cryptoContext, void* mem, uint32_t length);
	typedef void* (*def_createKkp)(void* cryptoContext, const mchar* pass, uint32_t* sizeOfKkp_out,
		int32_t* error_out);
	typedef bool (*def_destroyCryptoContext)(void* cryptoContext);
	typedef void* (*def_createCryptoContext)(void* seq_bytes, uint32_t lenOfSeq, int32_t* error_out);
	typedef void* (*def_createCryptoContextBySignSeq)(const uint8_t* containerBeginRawPtr, uint32_t sizeOfContainer,
		const mchar* pass, const uint8_t* seq_rand_rawPtr, uint32_t lenOfSeq, const uint8_t* sign_rawPtr,
		uint32_t lenOfSign, int32_t* error_out);
	typedef void* (*def_createCryptoContextByParams)(const void* params, int32_t* error_out);

	struct _Internal_BaseCrypt_ {
		type_sharedLibHandle libH{};
		bool isInit{ false };
		void* cryptoContext{};
		TInitParams initParams{};
		bool createCryptoContextHere{ false };

		def_Hmac_getData_KeySizes func_Hmac_getData_KeySizes{};
		def_destroyMemory func_destroyMemory{};
		//def_destroyKkp func_destroyKkp{};
		def_createKkp func_createKkp{};
		def_destroyCryptoContext func_destroyCryptoContext{};
		def_createCryptoContext func_createCryptoContext{};
		def_createCryptoContextBySignSeq func_createCryptoContextBySignSeq{};
		def_createCryptoContextByParams func_createCryptoContextByParams{};

		_Internal_BaseCrypt_() = default;
		_Internal_BaseCrypt_(type_sharedLibHandle libH_, TInitParams&& initParams_) :
			libH(libH_), initParams(std::move(initParams_)) {

		}
	};

	using type_internal = _Internal_BaseCrypt_;

	type_internal mInst{};

	def_destroyMemory func_destroyMemory{};

public:
	BaseCrypt() = default;
	BaseCrypt(type_sharedLibHandle libH_, TInitParams&& initParams_) :
		mInst(libH_, std::move(initParams_))
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
	}
	BaseCrypt(const BaseCrypt&) = delete;
	BaseCrypt(BaseCrypt&& obj) :
		mInst(std::move(obj.mInst)), func_destroyMemory(obj.func_destroyMemory) {
		obj.mInst.isInit = false;
	}
	BaseCrypt& operator=(BaseCrypt&& obj)
	{
		dispose();

		mInst = std::move(obj.mInst);
		func_destroyMemory = obj.func_destroyMemory;

		obj.mInst.isInit = false;
		return *this;
	}
	~BaseCrypt()
	{
		dispose();
	}

	void dispose() {
		if (mInst.isInit && mInst.createCryptoContextHere)
		{
			const auto res_del = mInst.func_destroyCryptoContext(mInst.cryptoContext);
			assert(res_del);
		}
	}

	[[nodiscard]] void* get_cryptoContext() const
	{
		return mInst.cryptoContext;
	}
	[[nodiscard]] bool get_isInit() const
	{
		return mInst.isInit;
	}
	[[nodiscard]] const TInitParams& get_params() const 
	{
		return mInst.initParams;
	}

	void init()
	{
		assert(!mInst.isInit);

		loadFunctions();

		int32_t error{};
		const auto cryptoContext_local = createCryptoContext(error);
		if (error != 0)
			throw error;
		mInst.cryptoContext = cryptoContext_local;
		mInst.createCryptoContextHere = true;

		mInst.isInit = true;
	}
	template<typename TVecAlloc>
	void createKkp(const mstringView& passOfKkp, std::vector<uint8_t, TVecAlloc>& kkp_out)
	{
		using namespace std;

		assert(mInst.isInit);
		int32_t error{};
		uint32_t sizeOfKKp{};
		auto* kkp = mInst.func_createKkp(mInst.cryptoContext, passOfKkp.data(), &sizeOfKKp, &error);
		if (error != 0)
			throw error;
		kkp_out.resize(sizeOfKKp);
		copy_n(static_cast<uint8_t*>(kkp), sizeOfKKp, kkp_out.data());
		const auto res_destroyKkp = mInst.func_destroyMemory(mInst.cryptoContext, kkp, sizeOfKKp);
		assert(res_destroyKkp);
	}
	void getData_KeySizes(HmacAlgDef algDef, HmacLen hmacLen, HmacData_KeySizes* data, int32_t* error_out) const
	{
		mInst.func_Hmac_getData_KeySizes(static_cast<int32_t>(algDef), static_cast<int32_t>(hmacLen), data, error_out);
	}

private:
	void* createCryptoContext(int32_t& error_out)
	{
		if constexpr (TInitParams::initType == InitMethodType::bySeq)
		{
			const auto seqTuple = mInst.initParams.getSeqTuple();
			SeqParams pr;
			pr.typeOfParams = static_cast<std::underlying_type_t<TypeOfParams>>(TypeOfParams::seq);
			pr.needRandomBlock = std::get<2>(seqTuple);
			pr.seq = std::get<0>(seqTuple);
			pr.lenOfSeq = static_cast<uint32_t>(std::get<1>(seqTuple));
			return mInst.func_createCryptoContextByParams(&pr, &error_out);
			
			//return func_createCryptoContext(std::get<0>(seqTuple), static_cast<uint32_t>(std::get<1>(seqTuple)), &error_out);
		}
		else if constexpr (TInitParams::initType == InitMethodType::bySignSeq)
		{
			SigSeqParams pr;
			pr.typeOfParams = static_cast<std::underlying_type_t<TypeOfParams>>(TypeOfParams::signSeq);
			pr.kkp = mInst.initParams.getKkp().data();
			pr.lenOfKkp = static_cast<uint32_t>(mInst.initParams.getKkp().size());
			pr.passToKkp = mInst.initParams.getPass().data();
			pr.lenOfPassToKkp = static_cast<uint32_t>(mInst.initParams.getPass().size());
			pr.seq = mInst.initParams.getSeq().data();
			pr.lenOfSeq = static_cast<uint32_t>(mInst.initParams.getSeq().size());
			pr.sign = mInst.initParams.getSign().data();
			pr.lenOfSign = static_cast<uint32_t>(mInst.initParams.getSign().size());
			pr.needRandomBlock = mInst.initParams.getNeedBlock();
			return mInst.func_createCryptoContextByParams(&pr, &error_out);
			/*return func_createCryptoContextBySignSeq(initParams.getKkp().data(), initParams.getKkp().size(),
				initParams.getPass().data(), initParams.getSeq().data(), initParams.getSeq().size(),
				initParams.getSign().data(), initParams.getSign().size(), &error_out);*/
		}
		else if constexpr (TInitParams::initType == InitMethodType::cont) {
			ContainerParams pr{};
			const CryptoInitByCont& initParams = mInst.initParams;
			pr.cont = initParams.mKkp.data();
			pr.len = static_cast<uint32_t>(initParams.mKkp.size());
			pr.pass = initParams.mPass.data();
			pr.needBlockByRand = initParams.mNeedToBlock;
			pr.typeOfParams = static_cast<std::underlying_type_t<TypeOfParams>>(TypeOfParams::cont);
			return mInst.func_createCryptoContextByParams(&pr, &error_out);
		}

		return nullptr;
	}
	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, name_createCryptoContextByParams);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		mInst.func_createCryptoContextByParams = reinterpret_cast<def_createCryptoContextByParams>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, name_createCryptoContextBySignSeq);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		mInst.func_createCryptoContextBySignSeq = reinterpret_cast<def_createCryptoContextBySignSeq>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, name_Hmac_getData_KeySizes);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		mInst.func_Hmac_getData_KeySizes = reinterpret_cast<def_Hmac_getData_KeySizes>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, name_destroyMemory);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();//GetLastError();
			throw error;
		}
		mInst.func_destroyMemory = reinterpret_cast<def_destroyMemory>(funcAddress);
		func_destroyMemory = reinterpret_cast<def_destroyMemory>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, name_createKkp);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		mInst.func_createKkp = reinterpret_cast<def_createKkp>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, name_destroyCryptoContext);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		mInst.func_destroyCryptoContext = reinterpret_cast<def_destroyCryptoContext>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, name_createCryptoContext);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		mInst.func_createCryptoContext = reinterpret_cast<def_createCryptoContext>(funcAddress);
	}
};