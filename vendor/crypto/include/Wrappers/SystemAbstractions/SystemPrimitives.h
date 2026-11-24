#pragma once

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

class SystemPrimitives
{
public:
	using type_systemHandle = HANDLE;
	using type_sharedLibHandle = HMODULE;
	static constexpr type_sharedLibHandle nullLibHandle{ nullptr };
	using type_funcAddress = FARPROC;
	static constexpr type_funcAddress nullFuncAddress{ nullptr };
	using type_errorType = DWORD;

	static type_errorType getLastError()
	{
		return GetLastError();
	}
	static bool isOk(const type_errorType error) {
		return error == S_OK;
	}
	static type_errorType g_okStatus() {
		return S_OK;
	}
};

#else

class SystemPrimitives
{
public:
	using type_systemHandle = int;
	using type_sharedLibHandle = void*;
	static constexpr type_sharedLibHandle nullLibHandle{ nullptr };
	using type_funcAddress = void*;
	static constexpr type_funcAddress nullFuncAddress{ nullptr };
	using type_errorType = int;

	static type_errorType getLastError()
	{
		return errno;
	}
	static bool isOk(const type_errorType error) {
		return error == 0;
	}
	static type_errorType g_okStatus() {
		return 0;
	}
};

#endif


