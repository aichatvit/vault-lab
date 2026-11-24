#pragma once

#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#include "../CommonPlatformDefs.h"

#define CpDef_Xeh_Poly
typedef __m128i t_bPoly;

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Add(const __m128i a, const __m128i b) {
	return _mm_xor_si128(a, b);
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Sub(const __m128i a, const __m128i b) {
	return _mm_xor_si128(a, b);
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Mult(const __m128i a, const __m128i b) {
	return _mm_and_si128(a, b);
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_MultByReductPoly(__m128i a) {
	char Cin = 0;
	char Cout = 0;
	for (int j = 0; j < 16; j++)
	{
		Cout = (((char*)&a)[j] >> 7) & 1;
		((char*)&a)[j] = (char)(((((char*)&a)[j] << 1) + Cin) & 0xFF);
		Cin = Cout;
	}
	if (Cout != 0)
		((char*)&a)[0] ^= 0x87;
	return a;
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_ReverceBytes(const __m128i vec) {
	const __m128i mask = _mm_setr_epi8(
		15, 14, 13, 12, 11, 10, 9, 8,
		7, 6, 5, 4, 3, 2, 1, 0
	);
	return _mm_shuffle_epi8(vec, mask);
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Set(
	char b1, char b2, char b3, char b4, char b5, char b6, char b7, char b8,
	char b9, char b10, char b11, char b12, char b13, char b14, char b15, char b16)
{
	return _mm_setr_epi8(
		b1, b2, b3, b4, b5, b6, b7, b8,
		b9, b10, b11, b12, b13, b14, b15, b16);
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Load(const void* mem) {
#ifdef CpDef_Xeh_MemAlign
	return _mm_load_si128((const __m128i*)mem);
#else
	return _mm_loadu_si128((const __m128i*)mem);
#endif // CpDef_Xeh_MemAlign
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehMath_Impl_Store(const __m128i b, void* mem) {
#ifdef CpDef_Xeh_MemAlign
	return _mm_store_si128((__m128i*)mem, b);
#else
	return _mm_storeu_si128((__m128i*)mem, b);
#endif // CpDef_Xeh_MemAlign
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_LoadInt(const int value) {
	return _mm_set_epi32(0, 0, 0, value);
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Load64Int(const long long value) {
	return _mm_set_epi64x(0, value);
}