#pragma once

#include <cassert>

#include <dlfcn.h>
#include <errno.h>

#include "../../Common/mstring.h"
#include "SystemPrimitives.h"

class SharedLibOwner_Linux
{
	mstring path{};
	bool isInit{ false };
	SystemPrimitives::type_sharedLibHandle libHandle{};

public:
	using type_string = mstring;
	using type_stringView = mstringView;
	using type_sharedLibHandle = SystemPrimitives::type_sharedLibHandle;
	using type_funcAddress = SystemPrimitives::type_funcAddress;
	using type_sysCode = typename SystemPrimitives::type_errorType;

	SharedLibOwner_Linux() = default;
	SharedLibOwner_Linux(const mstringView& path_) :
		path(path_)
	{
	}
	SharedLibOwner_Linux(SharedLibOwner_Linux&& obj) : 
		path(obj.path), isInit(obj.isInit), libHandle(obj.libHandle)
	{
		obj.isInit = false;
		obj.libHandle = nullptr;
	}
	SharedLibOwner_Linux& operator=(SharedLibOwner_Linux&& obj) {
		dispose();

		path = obj.path; 
		isInit = obj.isInit; 
		libHandle = obj.libHandle;

		obj.isInit = false;
		obj.libHandle = nullptr;
		return *this;
	}

	~SharedLibOwner_Linux()
	{
		dispose();
	}

	void dispose() {
		if (!isInit)
			return;
		else if (libHandle == SystemPrimitives::nullLibHandle)
			return;
		else
		{
			const auto res_freeLib = dlclose(libHandle);//FreeLibrary(libHandle);
			assert(res_freeLib == 0);
		}
	}

	type_sharedLibHandle get_LibHandle()
	{
		return libHandle;
	}

	int init() {
		type_sysCode sysCode_out{};
		return init(sysCode_out);
	}
	int init(type_sysCode& sysCode_out)
	{
		assert(!isInit);

		int code{ 0 };
		if (libHandle == SystemPrimitives::nullLibHandle) {
			code = loadSharedLibrary_impl(path);
			if (code != 0)
				return code;
		}

		isInit = true;
		return 0;
	}

	static type_funcAddress loadFuncFromLib(type_sharedLibHandle libH, const char* nameOfFunc)
	{
		const auto funcAddr = dlsym(libH, nameOfFunc);
		return funcAddr;
	}
	static type_sharedLibHandle loadSharedLibrary(const type_stringView& pathToLib)
	{
		static_assert(std::is_same_v<mchar, char>);
		const auto libH = dlopen(pathToLib.data(), RTLD_NOW /*| RTLD_GLOBAL*/);
		return libH;
	}

    static std::string get_error()
    {
        const auto ds = dlerror();
        if(ds) {
            return ds;
        }
        return {};
    }
protected:
	int loadSharedLibrary_impl(const type_stringView& pathToLib)
	{
		static_assert(std::is_same_v<mchar, char>);
		const auto libH = loadSharedLibrary(pathToLib);
		if (libH == SystemPrimitives::nullLibHandle)
			return -1;
		libHandle = libH;
		return 0;
	}
};