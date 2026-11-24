#pragma once

#if defined CpDef_XehEnc_Test
#include "EncrypterTest.h"
#elif defined CpDef_XehEnc_Gost
#elif defined CpDef_XehEnc_Custom
#else
#include "EncrypterTest.h"
#endif


static inline void Cp_XehEnc_EncBlock_K1(const void* block, void* context, void* result) {
	Cp_XehEnc_Impl_EncBlock_K1(block, context, result);
}

static inline void Cp_XehEnc_EncBlock_K2(const void* block, void* context, void* result) {
	Cp_XehEnc_Impl_EncBlock_K2(block, context, result);
}

static inline void Cp_XehEnc_DecBlock_K1(const void* block, void* context, void* result) {
	Cp_XehEnc_Impl_DecBlock_K1(block, context, result);
}