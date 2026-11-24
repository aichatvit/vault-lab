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

#if defined(CpDef_Xeh_EnableFuncKernelSse2)
static inline __attribute__((target("pclmul"))) __m128i Cp_XehMath_Impl_Mult(const __m128i a, const __m128i b) {
#else  
static inline __m128i Cp_XehMath_Impl_Mult(const __m128i a, const __m128i b) {
#endif
	__m128i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6,
		tmp7, tmp8, tmp9, tmp10, tmp11, tmp12;
	__m128i XMMMASK = _mm_setr_epi32(0xffffffff, 0x0, 0x0, 0x0);
	tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
	tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
	tmp4 = _mm_shuffle_epi32(a, 78);
	tmp5 = _mm_shuffle_epi32(b, 78);
	tmp4 = _mm_xor_si128(tmp4, a);
	tmp5 = _mm_xor_si128(tmp5, b);
	tmp4 = _mm_clmulepi64_si128(tmp4, tmp5, 0x00);
	tmp4 = _mm_xor_si128(tmp4, tmp3);
	tmp4 = _mm_xor_si128(tmp4, tmp6);
	tmp5 = _mm_slli_si128(tmp4, 8);
	tmp4 = _mm_srli_si128(tmp4, 8);
	tmp3 = _mm_xor_si128(tmp3, tmp5);
	tmp6 = _mm_xor_si128(tmp6, tmp4);
	tmp7 = _mm_srli_epi32(tmp6, 31);
	tmp8 = _mm_srli_epi32(tmp6, 30);
	tmp9 = _mm_srli_epi32(tmp6, 25);
	tmp7 = _mm_xor_si128(tmp7, tmp8);
	tmp7 = _mm_xor_si128(tmp7, tmp9);
	tmp8 = _mm_shuffle_epi32(tmp7, 147);

	tmp7 = _mm_and_si128(XMMMASK, tmp8);
	tmp8 = _mm_andnot_si128(XMMMASK, tmp8);
	tmp3 = _mm_xor_si128(tmp3, tmp8);
	tmp6 = _mm_xor_si128(tmp6, tmp7);
	tmp10 = _mm_slli_epi32(tmp6, 1);
	tmp3 = _mm_xor_si128(tmp3, tmp10);
	tmp11 = _mm_slli_epi32(tmp6, 2);
	tmp3 = _mm_xor_si128(tmp3, tmp11);
	tmp12 = _mm_slli_epi32(tmp6, 7);
	tmp3 = _mm_xor_si128(tmp3, tmp12);

	return _mm_xor_si128(tmp3, tmp6);
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Internal_ShiftLeftByOneBit(__m128i v) {
	__m128i v1 = _mm_slli_epi64(v, 1);
	__m128i v2 = _mm_slli_si128(v, 8);
	v2 = _mm_srli_epi64(v2, 64 - (1));
	v1 = _mm_or_si128(v1, v2);
	return v1;
}
static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Internal_ShiftRightByOneBit(__m128i v) {
	__m128i v1 = _mm_srli_epi64(v, 1);
	__m128i v2 = _mm_srli_si128(v, 8);
	v2 = _mm_slli_epi64(v2, 64 - (1));
	v1 = _mm_or_si128(v1, v2);
	return v1;
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_MultByReductPoly(__m128i a) {
	const int lsbV = ((char*)(&a))[15] & 0x01;
	a = Cp_XehMath_Impl_Internal_ShiftLeftByOneBit(a);
	if (lsbV != 0)
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
#endif
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehMath_Impl_Store(const __m128i b, void* mem) {
#ifdef CpDef_Xeh_MemAlign
	_mm_store_si128((__m128i*)mem, b);
#else
	_mm_storeu_si128((__m128i*)mem, b);
#endif
}

static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_LoadInt(const long value) {
	return _mm_set_epi32(0, 0, 0, value);
}
static inline CpDef_Xeh_FuncKernelSse2 __m128i Cp_XehMath_Impl_Load64Int(const long long value) {
	//return _mm_set_epi64x(0, value); //true

#if defined(CpDef_XehMath_Intrin_Epi64x)
	return _mm_set_epi64x(0, value);
#else
	union {
		long long q[2];
		long r[4];
	} u;
	u.q[0] = value;  u.q[1] = 0;
	return _mm_setr_epi32(u.r[0], u.r[1], u.r[2], u.r[3]);
#endif

//#if defined(/*AMD_64*/__amd64__) && defined(_MSC_VER)
//	return _mm_set_epi64x(0, value);
//#else
//	union {
//		long long q[2];
//		long r[4];
//	} u;
//	u.q[0] = value;  u.q[1] = 0;
//	return _mm_setr_epi32(u.r[0], u.r[1], u.r[2], u.r[3]);
//#endif
}