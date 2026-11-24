#pragma once

//#ifndef CpDef_Xeh_Poly
//
//	#define CpDef_Xeh_Poly
//
//	#include <wmmintrin.h>
//	#include <emmintrin.h>
//	#include <smmintrin.h>
//
//	typedef __m128i t_bPoly;
//
//#endif // !CpDef_Xeh_Poly

#if defined CpDef_XehMath_Test
	#include "testMath.h"
#elif defined CpDef_XehMath_Intrin
	#include "intrinMath.h"
#elif defined CpDef_XehMath_Base
	#include "baseMath.h"
#elif defined CpDef_XehMath_Custom
#else
	#include "testMath.h"
#endif


static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_Add(const t_bPoly a, const t_bPoly b) {
	return Cp_XehMath_Impl_Add(a, b);
}

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_Sub(const t_bPoly a, const t_bPoly b) {
	return Cp_XehMath_Impl_Sub(a, b);
}

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_Mult(const t_bPoly a, const t_bPoly b) {
	return Cp_XehMath_Impl_Mult(a, b);
}

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_MultByReductPoly(t_bPoly a) {
	return Cp_XehMath_Impl_MultByReductPoly(a);
}

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_ReverceBytes(t_bPoly vec) {
	return Cp_XehMath_Impl_ReverceBytes(vec);
}

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_Set(
	char b1, char b2, char b3, char b4, char b5, char b6, char b7, char b8,
	char b9, char b10, char b11, char b12, char b13, char b14, char b15, char b16) 
{
	return Cp_XehMath_Impl_Set(
		b1, b2, b3, b4, b5, b6, b7, b8,
		b9, b10, b11, b12, b13, b14, b15, b16);
}

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_Load(const void* mem) {
	return Cp_XehMath_Impl_Load(mem);
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehMath_Store(const t_bPoly b, void* mem) {
	Cp_XehMath_Impl_Store(b, mem);
}

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_LoadInt(const int value) {
	return Cp_XehMath_Impl_LoadInt(value);
}
static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehMath_Load64Int(const long long value) {
	return Cp_XehMath_Impl_Load64Int(value);
}