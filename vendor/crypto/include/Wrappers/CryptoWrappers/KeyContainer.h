#pragma once

#include <cassert>
#include <cstdint>
#include <tuple>

#include "../../SharedLibFuncs/KeyContainerType.h"
#include "../../SharedLibFuncs/KeyContainerData.h"
#include "../../Base/GUID.h"
//#include "../Base/GUID.h"

class KeyContainer {
public:
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_char = mchar;
	using type_funcNameChar = char;
	using type_funcAddress = SystemPrimitives::type_funcAddress;

	/*EXPORT int32_t CDECL KcF_FromBytes(void* cryptoContext, const std::uint32_t containerType, const void* container, 
		const std::uint32_t lenOfContainer, void** conInstance_out);
	EXPORT int32_t CDECL KcF_GetPublicParam(const void* conInstance, const std::uint32_t containerType, 
		const std::uint32_t dataType, void** data_out, std::uint32_t* len_out);
	int32_t KcF_DeleteContainer(void* conInstance, const std::uint32_t containerType, const std::uint32_t lenOfContainer)*/
	static constexpr const char* name_fromBytes{ "KcF_FromBytes" };
	static constexpr const char* name_getPublicParam{ "KcF_GetPublicParam" };
	static constexpr const char* name_DeleteContainer{ "KcF_DeleteContainer" };
	static constexpr const char* name_destroyMemory{ "destroyMemory" };

	typedef int32_t (*def_fromBytes)(void* cryptoContext, const std::uint32_t containerType, const void* container,
		const std::uint32_t lenOfContainer, void** conInstance_out);
	typedef int32_t(*def_getPublicParam)(const void* conInstance, const std::uint32_t containerType,
		const std::uint32_t dataType, void** data_out, std::uint32_t* len_out);
	typedef int32_t(*def_DeleteContainer)(void* conInstance, const std::uint32_t containerType);
	typedef bool (*def_destroyMemory)(void* cryptoContext, void* mem, uint32_t length);

	struct _Internal_ {
		def_fromBytes func_fromBytes{};
		def_getPublicParam func_getPublicParam{};
		def_DeleteContainer func_DeleteContainer{};
		def_destroyMemory func_destroyMemory{};

		bool isInit{ false };
		bool isOwner{ false };
		void* cryptoContext{ nullptr };
		void* containerInstance{ nullptr };
		KeyContainerType conType{};
		type_sharedLibHandle libH{ SystemPrimitives::nullLibHandle };

		_Internal_(type_sharedLibHandle libH_, void* cryptoContext_, KeyContainerType conType_, bool own)
			: isOwner(own), cryptoContext(cryptoContext_), conType(conType_), libH(libH_) {
		}
	};

	_Internal_ inst;

	KeyContainer(type_sharedLibHandle libH_, void* cryptoContext_, KeyContainerType conType_, bool own)
		: inst(libH_, cryptoContext_, conType_, own)
	{
		assert(libH_ != SystemPrimitives::nullLibHandle);
		assert(cryptoContext_ != nullptr);
	}
	KeyContainer(const KeyContainer&) = delete;
	KeyContainer(KeyContainer&& obj)
		: inst(std::move(obj.inst)) {
		obj.inst.isInit = false;
		obj.inst.isOwner = false;
	}
	~KeyContainer()
	{
		if (!inst.isInit || !inst.isOwner)
			return;

		inst.func_DeleteContainer(inst.containerInstance, static_cast<std::uint32_t>(inst.conType));
	}

	void init(const void* con, const std::uint32_t len)
	{
		assert(!inst.isInit);
		assert(inst.libH != SystemPrimitives::nullLibHandle);

		loadFunctions();
		if (inst.isOwner)
		{
			const auto error = inst.func_fromBytes(inst.cryptoContext, static_cast<int32_t>(inst.conType), 
				con, len, &inst.containerInstance);

			if (error != 0)
				throw error;
		}

		inst.isInit = true;
	}
	static constexpr bool existProp(const KeyContainerType conType, const KeyContainerData dataType) {
		return true;
	}

	std::tuple<std::int32_t, void*, std::uint32_t> getProp(const KeyContainerData dataType) {
		void* data;
		std::uint32_t len;
		const auto error = inst.func_getPublicParam(inst.containerInstance, static_cast<std::uint32_t>(inst.conType),
			static_cast<std::uint32_t>(dataType), &data, &len);
		return { error, data, len };
	}
	std::tuple<std::int32_t, Guid> g_Guid() {
		const auto res_prop = getProp(KeyContainerData::guid);
		if (std::get<0>(res_prop) != 0)
			return { std::get<0>(res_prop), {} };

		Guid g = *static_cast<Guid*>(std::get<1>(res_prop));
		assert(std::get<2>(res_prop) == sizeof(Guid));
		inst.func_destroyMemory(inst.cryptoContext, std::get<1>(res_prop), std::get<2>(res_prop));
		return { std::get<0>(res_prop), g };
	}
	std::tuple<std::int32_t, time_t> g_expPeriod() {
		const auto res_prop = getProp(KeyContainerData::expTimePeriod);
		if (std::get<0>(res_prop) != 0)
			return { std::get<0>(res_prop), {} };

		time_t g = *static_cast<time_t*>(std::get<1>(res_prop));
		assert(std::get<2>(res_prop) == sizeof(time_t));
		inst.func_destroyMemory(inst.cryptoContext, std::get<1>(res_prop), std::get<2>(res_prop));
		return { std::get<0>(res_prop), g };
	}

private:
	void loadFunctions()
	{
		type_funcAddress funcAddress{ SystemPrimitives::nullFuncAddress };

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_fromBytes);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_fromBytes = reinterpret_cast<def_fromBytes>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_getPublicParam);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_getPublicParam = reinterpret_cast<def_getPublicParam>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_DeleteContainer);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_DeleteContainer = reinterpret_cast<def_DeleteContainer>(funcAddress);

		funcAddress = SharedLibOwner::loadFuncFromLib(inst.libH, name_destroyMemory);
		if (funcAddress == SystemPrimitives::nullFuncAddress)
		{
			const auto error = SystemPrimitives::getLastError();
			throw error;
		}
		inst.func_destroyMemory = reinterpret_cast<def_destroyMemory>(funcAddress);
	}
};