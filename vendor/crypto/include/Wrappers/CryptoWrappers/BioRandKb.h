#pragma once

#include <cassert>
#include <variant>

#include "../SystemAbstractions/SystemPrimitives.h"
#include "../../Common/mstring.h"
#include "../SystemAbstractions/SharedLibOwner.h"
#include "../../SharedLibFuncs/BioRandFuncs.h"
#include "../../SharedLibFuncs/BioRandKBFlags.h"
#include "../../SharedLibFuncs/SharedErrors/SharedErrors.h"
#include "../../Wrappers/LibMemoryOwner.h"

class BioRandKb {
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;
	using type_sysError = typename SystemPrimitives::type_errorType;

	static constexpr const char* na_createContext{ "BRa_kb_createContext" };
	static constexpr const char* na_genSymbol{ "BRa_kb_genSymbol" };
	static constexpr const char* na_addSymbolWithTimeCheck{ "BRa_kb_addSymbolWithTimeCheck" };
	static constexpr const char* na_genResult{ "BRa_kb_genResult" };
	static constexpr const char* na_destroyMemory{ "BRa_kb_destroyMemory" };
	static constexpr const char* na_destroyContext{ "BRa_kb_destroyContext" };
	
	typedef void* (*def_createContext)(const int32_t flags, int32_t* error_out);
	typedef mchar (*def_genSymbol)(void* context, const int32_t flags, int32_t* error_out);
	typedef bool (*def_addSymbolWithTimeCheck)(void* context, const int32_t flags, const mchar symbol,
		std::uint64_t* time_out, int32_t* error_out);
	typedef void* (*def_genResult)(void* context, const int32_t flags, std::uint32_t* lenOfRes_out, int32_t* error_out);
	typedef bool (*def_destroyMemory)(void* context, void* mem, uint32_t length);
	typedef bool (*def_destroyContext)(void* context, const int32_t flags);

	struct _Funcs_ {
		def_createContext func_createContext{};
		def_genSymbol func_genSymbol{};
		def_addSymbolWithTimeCheck func_addSymbolWithTimeCheck{};
		def_genResult func_genResult{};
		def_destroyMemory func_destroyMemory{};
		def_destroyContext func_destroyContext{};
	};

	struct _Internal_ {
		type_sharedLibHandle libH{};
#ifndef NDEBUG
		bool isInit{ false };
#endif // !NDEBUG
		void* context{};

		_Funcs_ funcs{};

		_Internal_(type_sharedLibHandle libH_) :
			libH(libH_) 
		{
			assert(SystemPrimitives::nullLibHandle != libH_);
		}
		_Internal_(const _Funcs_& _funcs) :
			funcs(_funcs)
		{
		}
	};

	using t_inst = _Internal_;

	t_inst mInst;

	BioRandKb(type_sharedLibHandle libH_) :
		mInst(libH_) 
	{
	}
	BioRandKb(const BioRandKb&) = delete;
	BioRandKb(BioRandKb&& obj) : 
		mInst(std::move(obj.mInst))
	{
		obj.mInst.context = nullptr;
	}
	BioRandKb(const _Funcs_& funcs) : 
		mInst(funcs)
	{
		assert(funcs.func_addSymbolWithTimeCheck != nullptr);
		assert(funcs.func_createContext != nullptr);
		assert(funcs.func_destroyContext != nullptr);
		assert(funcs.func_destroyMemory != nullptr);
		assert(funcs.func_genResult != nullptr);
		assert(funcs.func_genSymbol != nullptr);
	}

	static _Funcs_ getFuncsFromPlugin() {
		_Funcs_ fns{};
		fns.func_createContext = BRa_kb_createContext;
		fns.func_genSymbol = BRa_kb_genSymbol;
		fns.func_addSymbolWithTimeCheck = BRa_kb_addSymbolWithTimeCheck;
		fns.func_genResult = BRa_kb_genResult;
		fns.func_destroyMemory = BRa_kb_destroyMemory;
		fns.func_destroyContext = BRa_kb_destroyContext;
		return fns;
	}

	std::tuple<type_sysError, int32_t> 
		init() 
	{
		using tL_res = std::tuple<type_sysError, int32_t>;

		assert(!mInst.isInit);

		if (mInst.libH) {
			const type_sysError error = loadFuncs(mInst.funcs);
			if (!SystemPrimitives::isOk(error))
				return tL_res{ error, SharedErrors::ok };
		}

		const auto va_context = createContext<>();
		if (!std::holds_alternative<void*>(va_context))
			return tL_res{ SystemPrimitives::g_okStatus(), std::get<1>(va_context) };//std::variant<type_sysError, int32_t>{std::in_place_index_t<1>{}, std::get<1>(va_context)};

		mInst.context = std::get<0>(va_context);
#ifndef NDEBUG
		mInst.isInit = true;
#endif // !NDEBUG
		return tL_res{ SystemPrimitives::g_okStatus(), {} };
	}

	template<typename... TFlagArgs>
	std::variant<LibMemoryOwner<def_destroyMemory>, int32_t>
		genResult(const TFlagArgs... enumFlags) 
	{
		using tL_res = std::variant<LibMemoryOwner<def_destroyMemory>, int32_t>;

		const auto flagsVal = createFlags(enumFlags...);
		uint32_t len{};
		int32_t status{};
		auto* mem = mInst.funcs.func_genResult(mInst.context, flagsVal, &len, &status);
		if (mem == nullptr)
			return tL_res{ status };

		return tL_res{ LibMemoryOwner<def_destroyMemory>{mInst.funcs.func_destroyMemory, mInst.context, mem, len } };
	}
	template<typename... TFlagArgs>
	std::tuple<bool, uint64_t, int32_t>
		addSymbolWithTimeCheck(const mchar symbol, const TFlagArgs... enumFlags)
	{
		using tl_res = std::tuple<bool, uint64_t, int32_t>;

		const auto flagsVal = createFlags(enumFlags...);
		int32_t status{};
		uint64_t time{};
		const auto suc = mInst.funcs.func_addSymbolWithTimeCheck(mInst.context, flagsVal, symbol, &time, &status);
		
		return tl_res{ suc, time, status };
	}
	template<typename... TFlagArgs>
	std::variant<mchar, int32_t> 
		genSymbol(const TFlagArgs... enumFlags) 
	{
		const auto flagsVal = createFlags(enumFlags...);
		int32_t status{};
		const mchar sumbol = mInst.funcs.func_genSymbol(mInst.context, flagsVal, &status);
		if (status)
			return std::variant<mchar, int32_t>{status};

		return std::variant<mchar, int32_t>{sumbol};
	}
	template<typename... TFlagArgs>
	std::variant<void*, int32_t> 
		createContext(const TFlagArgs... flags)
	{
		const auto flagsVal = createFlags(flags...);
		int32_t status{};
		void* context = mInst.funcs.func_createContext(flagsVal, &status);
		if (!context)
			return std::variant<void*, int32_t>{status};
		
		mInst.context = context;
		return std::variant<void*, int32_t>{context};
	}
	template<typename... TFlagArgs>
	int32_t createFlags(const TFlagArgs... flags) {
		return createFlags_impl<0>(0, flags...);
	}
	
	type_sysError 
		loadFuncs(_Funcs_& funcsStruct) 
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, na_destroyContext);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
			return SystemPrimitives::getLastError();
		mInst.funcs.func_destroyContext = reinterpret_cast<def_destroyContext>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, na_destroyMemory);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
			return SystemPrimitives::getLastError();
		mInst.funcs.func_destroyMemory = reinterpret_cast<def_destroyMemory>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, na_createContext);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
			return SystemPrimitives::getLastError();
		mInst.funcs.func_createContext = reinterpret_cast<def_createContext>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, na_genSymbol);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
			return SystemPrimitives::getLastError();
		mInst.funcs.func_genSymbol = reinterpret_cast<def_genSymbol>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, na_addSymbolWithTimeCheck);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
			return SystemPrimitives::getLastError();
		mInst.funcs.func_addSymbolWithTimeCheck = reinterpret_cast<def_addSymbolWithTimeCheck>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(mInst.libH, na_genResult);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
			return SystemPrimitives::getLastError();
		mInst.funcs.func_genResult = reinterpret_cast<def_genResult>(funcAddress);

		return SystemPrimitives::g_okStatus();
	}

	private:
		template<std::size_t Index, typename... TFlagArgs>
		int32_t createFlags_impl(const int32_t flagsVal, const TFlagArgs... flags) {
			constexpr std::size_t count = sizeof...(flags);
			using t_tuple = decltype(std::make_tuple(flags...));

			if constexpr (Index < count) {
				using tL_elem = std::tuple_element_t<Index, t_tuple>;
				static_assert(std::is_same_v<tL_elem, BioRandKBFlags>);

				const auto flagCur = 1 << static_cast<int>(std::get<Index>(std::make_tuple(flags...)));
				return createFlags_impl<Index + 1>((flagsVal | flagCur), flags...);
			}
			else
				return flagsVal;
		}
};