/** @file BioRandFuncs.h
* Функции биологического датчика случайных чисел.
*
* Функции биологического датчика случайных чисел используются для выработки инициализирующей последовательности для ПДСЧ.
* Это последовательность, в последствии, используется для инициализации всего плагина.
*/ 

#pragma once

#include <cstdint>

#include "../Common/SharedLibFuncsAtr.h"
#include "../Common/mstring.h"

extern "C"
{
	EXPORT void* CDECL BRa_kb_createContext(const int32_t flags, int32_t* error_out);
	EXPORT mchar CDECL BRa_kb_genSymbol(void* context, const int32_t flags, int32_t* error_out);
	EXPORT bool CDECL BRa_kb_addSymbolWithTimeCheck(void* context, const int32_t flags, const mchar symbol, 
		std::uint64_t* time_out, int32_t* error_out);
	EXPORT void* CDECL BRa_kb_genResult(void* context, const int32_t flags, std::uint32_t* lenOfRes_out, int32_t* error_out);
	EXPORT bool CDECL BRa_kb_destroyMemory(void* context, void* mem, uint32_t length);
	EXPORT bool CDECL BRa_kb_destroyContext(void* context, const int32_t flags);
}