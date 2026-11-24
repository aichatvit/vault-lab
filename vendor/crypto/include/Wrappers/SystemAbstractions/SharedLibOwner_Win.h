#pragma once

#include "../../Common/mstring.h"
#include "SystemPrimitives.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

class SharedLibOwner_Win
{
	mstring path{};
	bool isInit{ false };
	SystemPrimitives::type_sharedLibHandle libHandle{};

public:
	using type_string = mstring;
	using type_stringView = mstringView;
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_funcAddress = SystemPrimitives::type_funcAddress;
	using type_sysError = SystemPrimitives::type_errorType;

	SharedLibOwner_Win(const mstringView& path_) :
		path(path_)
	{
	}
	SharedLibOwner_Win(const SharedLibOwner_Win&) = delete;
	SharedLibOwner_Win(SharedLibOwner_Win&& obj) :
		path(std::move(obj.path)), isInit(obj.isInit), libHandle(obj.libHandle) {
		obj.isInit = false;
	}
	~SharedLibOwner_Win()
	{
		if (!isInit)
			return;
		else if (libHandle == SystemPrimitives::nullLibHandle)
			return;
		else
		{
			const auto res_freeLib = FreeLibrary(libHandle);
			assert(res_freeLib);
		}
	}

	type_sharedLibHandle get_LibHandle() const
	{
		return libHandle;
	}
	int init() {
		type_sysError sysError_out{};
		return init(sysError_out);
	}
	int init(type_sysError& sysError_out)
	{
		assert(!isInit);

		if (libHandle == SystemPrimitives::nullLibHandle) {
			loadSharedLibrary_impl(path, sysError_out);
			if (sysError_out != 0)
				return -1;
		}

		isInit = true;
		return 0;
	}

	static type_funcAddress loadFuncFromLib(type_sharedLibHandle libH, const char* nameOfFunc)
	{
		const auto funcAddr = GetProcAddress(libH, nameOfFunc);
		return funcAddr;
	}
	static type_sharedLibHandle loadSharedLibrary(const type_stringView& pathToLib)
	{
		static_assert(std::is_same_v<mchar, wchar_t>);
		const auto libH = LoadLibraryW(pathToLib.data());
		return libH;
	}

protected:
	void loadSharedLibrary_impl(const type_stringView& pathToLib, type_sysError& sysError_out)
	{
		static_assert(std::is_same_v<mchar, wchar_t>);
		const auto libH = loadSharedLibrary(pathToLib);
		if (libH == SystemPrimitives::nullLibHandle)
		{
			const auto error = GetLastError();
			sysError_out = error;
		}
		libHandle = libH;
	}
};