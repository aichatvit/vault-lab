#pragma once

#include "Math/mathDef.h"
#include "BlockEncrypters/EncrypterDef.h"
#include "InternalFuncs.h"
#include "StatusCodes/CodesDef.h"
#include "CommonPlatformDefs.h"

/*
Checks defs:

*/

static inline CpDef_Xeh_FuncKernelSse2 t_code Cp_Xeh_EncSector(
	const void* buf, 
	const unsigned long len,
	const unsigned long long sectorNumber,
	void* context, 
	void* buf_degrees,
	void* buf_out) 
{
	//const t_bPoly sn = Cp_XehMath_Load64Int(sectorNumber);

#if defined(CpDef_Xeh_CheckExamples) 
	const t_bPoly sn = Cp_XehMath_ReverceBytes(Cp_XehMath_Load64Int(sectorNumber));
#else
	const t_bPoly sn = Cp_XehMath_Load64Int(sectorNumber);
#endif //CpDef_Xeh_CheckExamples

	t_bPoly tau_1Sn = { 0 };
	Cp_XehEnc_EncBlock_K1(&sn, context, &tau_1Sn);
	t_bPoly tau_2Sn = { 0 };
	Cp_XehEnc_EncBlock_K2(&tau_1Sn, context, &tau_2Sn);
	t_bPoly tau_3Sn = { 0 };
	Cp_XehEnc_EncBlock_K2(&sn, context, &tau_3Sn);

#if defined(CpDef_Xeh_CheckExamples) 
	tau_1Sn = Cp_XehMath_ReverceBytes(tau_1Sn);
	tau_2Sn = Cp_XehMath_ReverceBytes(tau_2Sn);
	tau_3Sn = Cp_XehMath_ReverceBytes(tau_3Sn);
#endif //CpDef_Xeh_CheckExamples

#if CpDef_Xeh_SizeOfSector
	Cp_XehImpl_Internal_psi(buf, 0, tau_1Sn, tau_3Sn, buf_out, buf_degrees);
	Cp_XehImpl_Internal_EncBlocks(buf_out, 0, context, buf_out);
	Cp_XehImpl_Internal_g(buf_out, 0, tau_2Sn, buf_degrees, buf_out);
#else
	if (len % 16 != 0)
		return Cp_XehCodes_InputSeqLen(len, context);

	const long long countOfBlcoks = len / 16;
	Cp_XehImpl_Internal_psi(buf, countOfBlcoks, tau_1Sn, tau_3Sn, buf_out, buf_degrees);
	Cp_XehImpl_Internal_EncBlocks(buf_out, countOfBlcoks, context, buf_out);
	Cp_XehImpl_Internal_g(buf_out, countOfBlcoks, tau_2Sn, buf_degrees, buf_out);
#endif // CpDef_Xeh_SizeOfSector

	return Cp_XehCodes_Ok(context);
}

static inline CpDef_Xeh_FuncKernelSse2 t_code Cp_Xeh_DecSector(
	const void* buf,
	const unsigned long len,
	const unsigned long long sectorNumber,
	void* context,
	void* buf_degrees,
	void* buf_out)
{
	const t_bPoly sn = Cp_XehMath_Load64Int(sectorNumber);
	t_bPoly tau_1Sn = { 0 };
	Cp_XehEnc_EncBlock_K1(&sn, context, &tau_1Sn);
	t_bPoly tau_2Sn = { 0 };
	Cp_XehEnc_EncBlock_K2(&tau_1Sn, context, &tau_2Sn);
	t_bPoly tau_3Sn = { 0 };
	Cp_XehEnc_EncBlock_K2(&sn, context, &tau_3Sn);

#if CpDef_Xeh_SizeOfSector
	Cp_XehImpl_Internal_g_inv(buf, 0, tau_2Sn, tau_3Sn, buf_degrees, buf_out);
	Cp_XehImpl_Internal_DecBlocks(buf_out, 0, context, buf_out);
	Cp_XehImpl_Internal_psi_inv(buf_out, 0, tau_1Sn, buf_degrees, buf_out);
#else
	if (len % 16 != 0)
		return Cp_XehCodes_InputSeqLen(len, context);

	const long long countOfBlcoks = len / 16;
	Cp_XehImpl_Internal_g_inv(buf, countOfBlcoks, tau_2Sn, tau_3Sn, buf_degrees, buf_out);
	Cp_XehImpl_Internal_DecBlocks(buf_out, countOfBlcoks, context, buf_out);
	Cp_XehImpl_Internal_psi_inv(buf_out, countOfBlcoks, tau_1Sn, buf_degrees, buf_out);
#endif // CpDef_Xeh_SizeOfSector

	return Cp_XehCodes_Ok(context);
}