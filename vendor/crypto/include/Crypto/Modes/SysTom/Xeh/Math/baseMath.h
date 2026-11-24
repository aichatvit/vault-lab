#pragma once

#define CpDef_Xeh_Poly

typedef struct /*_Alignas(16)*/ {
	/*alignas(16)*//*_Alignas(16)*/ long long int poly[2];
} _polyBase;

typedef _polyBase/*polyBase*/ t_bPoly;

static inline _polyBase Cp_XehMath_Impl_Add(const _polyBase a, const _polyBase b) {
	_polyBase p;
	p.poly[0] = a.poly[0] ^ b.poly[0];
	p.poly[1] = a.poly[1] ^ b.poly[1];
	return p;
}

static inline _polyBase Cp_XehMath_Impl_Sub(const _polyBase a, const _polyBase b) {
	_polyBase p;
	p.poly[0] = a.poly[0] ^ b.poly[0];
	p.poly[1] = a.poly[1] ^ b.poly[1];
	return p;
}

static _polyBase Cp_XehMath_Impl_Internal_LeftShift(_polyBase bytes) {
	char carry = 0;
	for (int i = 15; i >= 0; i--)
	{
		const char byteCopy = ((char*)(&bytes))[i];
		((char*)(&bytes))[i] = ((char*)(&bytes))[i] << 1;
		if (carry == 1)
			((char*)(&bytes))[i] = ((char*)(&bytes))[i] | 0x01;
		carry = (byteCopy & 0x80) >> 7;
	}
	return bytes;
}

static inline void Cp_XehMath_Impl_Store(const _polyBase b, void* mem) {
	*(long long int*)mem = b.poly[0];
	*((long long int*)mem + 1) = b.poly[1];
}

static inline _polyBase Cp_XehMath_Impl_Mult(const _polyBase X/*a*/, const _polyBase V/*b*/) {
	t_bPoly Z = {0};

	for (int i = 127; i >= 0; i--)
	{
		const int j = i / 8;
		const int k = i % 8;
		const int xi = (((char*)(&X))[j] >> (8 - k - 1)) & 1;
		if (xi == 1)
			Z = Cp_XehMath_Impl_Add(Z, V);

		const int lsbV = ((char*)(&V))[0] & 0x80;
		Cp_XehMath_Impl_Store(Cp_XehMath_Impl_Internal_LeftShift(V), &V); //V = Cp_XehMath_Impl_Internal_LeftShift(V);
		if (lsbV != 0)
			((char*)(&V))[15] ^= 0x87;
	}
	return Z;
}

static inline _polyBase Cp_XehMath_Impl_ReverceBytes(_polyBase vec) {
	unsigned char* lo = (unsigned char*)&vec;
	unsigned char* hi = /*start*/(unsigned char*)&vec + 15/*size - 1*/;
	unsigned char swap;
	while (lo < hi) {
		swap = *lo;
		*lo++ = *hi;
		*hi-- = swap;
	}
	return vec;
}

static inline _polyBase Cp_XehMath_Impl_MultByReductPoly(_polyBase a) {
	char Cin = {0};
	char Cout = {0};
	for (int j = 0; j < 16; j++)
	{
		Cout = (((char*)&a)[j] >> 7) & 1;
		((char*)&a)[j] = (char)(((((char*)&a)[j] << 1) + Cin) & 0xFF);
		Cin = Cout;
	}
	if (Cout != 0)
		((char*)&a)[0] ^= 0x87;
	//return a;
	return Cp_XehMath_Impl_ReverceBytes(a);
}

static inline _polyBase Cp_XehMath_Impl_Set(
	char b1, char b2, char b3, char b4, char b5, char b6, char b7, char b8,
	char b9, char b10, char b11, char b12, char b13, char b14, char b15, char b16)
{
	_polyBase pol;
	((char*)&pol)[0] = b1; ((char*)&pol)[1] = b2; ((char*)&pol)[2] = b3; ((char*)&pol)[3] = b4;
	((char*)&pol)[4] = b5; ((char*)&pol)[5] = b6; ((char*)&pol)[6] = b7; ((char*)&pol)[7] = b8;
	((char*)&pol)[8] = b9; ((char*)&pol)[9] = b10; ((char*)&pol)[10] = b11; ((char*)&pol)[11] = b12;
	((char*)&pol)[12] = b13; ((char*)&pol)[13] = b14; ((char*)&pol)[14] = b15; ((char*)&pol)[15] = b16;
	return pol;
}

static inline _polyBase Cp_XehMath_Impl_Load(const void* mem) {
	_polyBase p;
	p.poly[0] = *(const long long int*)mem;
	p.poly[1] = *((const long long int*)mem + 1);
	return p;
}

static inline _polyBase Cp_XehMath_Impl_LoadInt(const int value) {
	return Cp_XehMath_Impl_Set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		((const char*)&value)[3], ((const char*)&value)[2], ((const char*)&value)[1], ((const char*)&value)[0]);
}

static inline _polyBase Cp_XehMath_Impl_Load64Int(const long long value) {
	return Cp_XehMath_Impl_Set(0, 0, 0, 0, 0, 0, 0, 0, 
		((const char*)&value)[7], ((const char*)&value)[6], ((const char*)&value)[5], ((const char*)&value)[4],
		((const char*)&value)[3], ((const char*)&value)[2], ((const char*)&value)[1], ((const char*)&value)[0]);
}