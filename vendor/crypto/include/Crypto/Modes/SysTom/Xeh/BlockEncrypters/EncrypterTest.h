#pragma once

#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

static inline void Cp_XehEnc_Impl_EncBlock_K1(const void* block, void* context, void* result) {
	const __m128i one = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
#ifdef CpDef_Xeh_MemAlign
	_mm_store_si128((__m128i*)result, _mm_xor_si128(_mm_load_si128((const __m128i*)block), one));
#else
	_mm_storeu_si128((__m128i*)result, _mm_xor_si128(_mm_loadu_si128((const __m128i*)block), one));
#endif
}

static inline void Cp_XehEnc_Impl_DecBlock_K1(const void* block, void* context, void* result) {
	Cp_XehEnc_Impl_EncBlock_K1(block, context, result);
}

static inline void Cp_XehEnc_Impl_EncBlock_K2(const void* block, void* context, void* result) {
	Cp_XehEnc_Impl_EncBlock_K1(block, context, result);
}