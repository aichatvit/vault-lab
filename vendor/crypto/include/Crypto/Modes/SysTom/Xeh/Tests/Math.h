#pragma once 

#define /*CpDef_XehMath_Intrin*/CpDef_XehMath_Base

//#include "../crypto-plugin/Incs/Crypto/Modes/SysTom/Xeh/Math/mathDef.h"
#include "../Math/mathDef.h"

#include "../CommonPlatformDefs.h"

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehTests_Math() {
	{
		const t_bPoly m_2 = Cp_XehMath_Set(
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x10);
		const t_bPoly z_3Sn = Cp_XehMath_Set(
			0x39, 0xD5, 0x96, 0x23, 0x32, 0x04, 0xA2, 0xE9,
			0xE4, 0x6A, 0x97, 0x55, 0x66, 0x83, 0x2F, 0x14);
		const t_bPoly tau_1Sn = Cp_XehMath_Set(
			0xc7, 0x5f, 0x8a, 0x98, 0xf1, 0xbd, 0xc6, 0x0c,
			0x86, 0x75, 0x0a, 0xd2, 0xd4, 0x7c, 0xc2, 0xd8);
		const t_bPoly mm_2_true = Cp_XehMath_Set(
			0xa6, 0x78, 0x90, 0x06, 0xc4, 0x69, 0x39, 0xe8,
			0xf1, 0x9a, 0x99, 0xec, 0xd3, 0x64, 0xb5, 0x33);
		//math1.add(mm_2_true, math1.add(m_2, z_3Sn));
		const t_bPoly multRes_true = Cp_XehMath_Add(mm_2_true, Cp_XehMath_Add(m_2, z_3Sn));
		//const __m128i multRes = math1.multByReductPoly(math1.reverceBytes(tau_1Sn));
		const t_bPoly multRes = Cp_XehMath_MultByReductPoly(Cp_XehMath_ReverceBytes(tau_1Sn));
		//const __m128i multRes2 = math1.multByReductPoly2(math1.reverceBytes(tau_1Sn));
		//const __m128i mult_tau_1Sn_By_One = math1.mult(tau_1Sn, math1.load_int(1));
		const t_bPoly mult_tau_1Sn_By_One = Cp_XehMath_Mult(tau_1Sn, Cp_XehMath_LoadInt(1));

#ifdef CpDef_XehMath_Intrin
		const t_bPoly mult_byMod = Cp_XehMath_Mult(Cp_XehMath_ReverceBytes(m_2), Cp_XehMath_ReverceBytes(z_3Sn));
#else
		const t_bPoly mult_byMod = Cp_XehMath_Mult(m_2, z_3Sn);
#endif // CpDef_XehMath_Intrin

		int i = 1 + 1;
		//const __m128i multRes_intelMult = math1.mult(math1.reverceBytes(tau_1Sn)/*tau_1Sn*/, math1.load_int(0x87/*0xe1*/));
		//const __m128i multRes_GcMultLe = math1.byGcmMult_le(math1.reverceBytes(tau_1Sn), math1.load_int(0x87/*0xe1*/));
	}
}