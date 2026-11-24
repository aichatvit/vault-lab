#pragma once

#if (CpDef_Xeh_SizeOfSector != 0) 
#define CpDef_Xeh_CountOfBlocks (CpDef_Xeh_SizeOfSector / 16)
#else
	//#define CpDef_Xeh_CountOfBlocks = 0;
#endif

//#define CpDef_Xeh_CountOfBlocks (CpDef_Xeh_SizeOfSector / 16)
//#define ddss 1

#include "Math/mathDef.h"
#include "BlockEncrypters/EncrypterDef.h"
#include "CommonPlatformDefs.h"

static inline CpDef_Xeh_FuncKernelSse2 t_bPoly Cp_XehImpl_Internal_comp_z3Sn(
	const void* blocks, 
	const int countOfBloks, 
	const t_bPoly tau_3Sn, 
	void* buf_degree_out) 
{
	t_bPoly z_tmp = Cp_XehMath_Load(&((const char*)blocks)[0]);
	t_bPoly tau_degree = tau_3Sn;
	unsigned long long i;
	Cp_XehMath_Store(Cp_XehMath_LoadInt(1), &((char*)buf_degree_out)[0]);
	Cp_XehMath_Store(tau_degree, &((char*)buf_degree_out)[sizeof(t_bPoly)]);
	z_tmp = Cp_XehMath_Add(
		Cp_XehMath_Mult(
			Cp_XehMath_Load(&((const char*)blocks)[sizeof(t_bPoly)]),
			tau_degree),
		z_tmp);
#if /*CpDef_Xeh_SizeOfSector*/CpDef_Xeh_SizeOfSector
	//const int countOfBlocks = CpDef_Xeh_CountOfBlocks;
	for (i = 2; i < CpDef_Xeh_CountOfBlocks/*ddss*//*countOfBlocks*/; i++)
	{
		tau_degree = Cp_XehMath_Mult(tau_degree, tau_3Sn);
		
		Cp_XehMath_Store(tau_degree, &((char*)buf_degree_out)[i * sizeof(t_bPoly)]);
		z_tmp = Cp_XehMath_Add(
			Cp_XehMath_Mult(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]),
				tau_degree),
			z_tmp);
	}
#else
	for (i = 2; i < countOfBloks; i++)
	{
		tau_degree = Cp_XehMath_Mult(tau_degree, tau_3Sn);
		z_tmp = Cp_XehMath_Add(
			Cp_XehMath_Mult(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]),
				tau_degree),
			z_tmp);
	}
#endif

	return z_tmp;
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehImpl_Internal_psi_inv(
	const void* blocks,
	const int countOfBlocks,
	const t_bPoly tau_1Sn,
	const void* tau_3Sn_degrees,
	void* blocks_out) 
{
	t_bPoly mmm1 = Cp_XehMath_Sub(
		Cp_XehMath_Load(&((const char*)blocks)[0]), tau_1Sn);

	t_bPoly multRes = tau_1Sn;
	t_bPoly sumOfMul_3Sn = {0};
	int i;
	//t_bPoly tau_3Sn_degree = tau_3Sn;

#if CpDef_Xeh_SizeOfSector
	for (i = 1; i < CpDef_Xeh_CountOfBlocks; i++) {
		multRes = Cp_XehMath_MultByReductPoly(multRes);
		const t_bPoly m_tmp = Cp_XehMath_Sub(
			Cp_XehMath_Sub(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]), multRes),
			mmm1);
		Cp_XehMath_Store(m_tmp, &((char*)blocks_out)[i * sizeof(t_bPoly)]);

		sumOfMul_3Sn = Cp_XehMath_Add(
			sumOfMul_3Sn,
			Cp_XehMath_Mult(
				m_tmp,
				/*tau_3Sn_degree*/Cp_XehMath_Load(&((const char*)tau_3Sn_degrees)[i * sizeof(t_bPoly)])));
		//tau_3Sn_degree = mMath.mult(tau_3Sn_degree, tau_3Sn);
	}
	mmm1 = Cp_XehMath_Sub(mmm1, sumOfMul_3Sn);
	Cp_XehMath_Store(mmm1, blocks_out);
#else
	for (/*int i = 1*/i = 1; i < countOfBlocks; i++) {
		multRes = Cp_XehMath_MultByReductPoly(multRes);
		const t_bPoly m_tmp = Cp_XehMath_Sub(
			Cp_XehMath_Sub(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]), multRes),
			mmm1);
		Cp_XehMath_Store(m_tmp, &((char*)blocks_out)[i * sizeof(t_bPoly)]);

		sumOfMul_3Sn = Cp_XehMath_Add(
			sumOfMul_3Sn,
			Cp_XehMath_Mult(
				m_tmp,
				/*tau_3Sn_degree*/Cp_XehMath_Load(&((const char*)tau_3Sn_degrees)[i * sizeof(t_bPoly)])));
		//tau_3Sn_degree = mMath.mult(tau_3Sn_degree, tau_3Sn);
	}
	mmm1 = Cp_XehMath_Sub(mmm1, sumOfMul_3Sn);
	Cp_XehMath_Store(mmm1, blocks_out);
#endif
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehImpl_Internal_psi(
	const void* blocks,
	const int countOfBlocks,
	const t_bPoly tau_1Sn,
	const t_bPoly tau_3Sn,
	void* blocks_out,
	void* buf_degree) 
{
	/*const auto z3Sn = comp_z3Sn<MemAlignV>(blocks, countOfBlocks, tau_3Sn, buf_degree);*/
	const t_bPoly z3Sn = Cp_XehImpl_Internal_comp_z3Sn(blocks, countOfBlocks, tau_3Sn, buf_degree);

	/*t_bPoly mm_tmp = mMath.add(z3Sn, tau_1Sn);*/
	t_bPoly mm_tmp = Cp_XehMath_Add(z3Sn, tau_1Sn);
	/*mMath.template store<MemAlignV>(mm_tmp, blocks_out);*/
	Cp_XehMath_Store(mm_tmp, blocks_out);

	t_bPoly multRes = tau_1Sn;
	int i;

#if CpDef_Xeh_SizeOfSector
	for (i = 1; i < CpDef_Xeh_CountOfBlocks; i++)
	{
		multRes = Cp_XehMath_MultByReductPoly(multRes);
		mm_tmp = Cp_XehMath_Add(
			Cp_XehMath_Add(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]), z3Sn),
			multRes);
		Cp_XehMath_Store(mm_tmp, &((char*)blocks_out)[i * sizeof(t_bPoly)]);
	}
#else
	for (i = 1; i < countOfBlocks; i++)
	{
		multRes = Cp_XehMath_MultByReductPoly(multRes);
		mm_tmp = Cp_XehMath_Add(
			Cp_XehMath_Add(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]), z3Sn),
			multRes);
		Cp_XehMath_Store(mm_tmp, &((char*)blocks_out)[i * sizeof(t_bPoly)]);
	}
#endif
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehImpl_Internal_g_inv(
	const void* blocks,
	const int countOfBlocks,
	const t_bPoly tau_2Sn,
	const t_bPoly tau_3Sn,
	void* tau_3Sn_degrees_out,
	void* blocks_out)
{
	int i;
#if CpDef_Xeh_SizeOfSector
	Cp_XehMath_Store(Cp_XehMath_LoadInt(1), &((char*)tau_3Sn_degrees_out)[0]);
	t_bPoly sum = tau_3Sn;
	for (i = 1; i < CpDef_Xeh_CountOfBlocks; i++) {
		Cp_XehMath_Store(sum, &((char*)tau_3Sn_degrees_out)[i * sizeof(t_bPoly)]);
		sum = Cp_XehMath_Mult(sum, tau_3Sn);
	}

	t_bPoly multRes = { 0 };
	sum = multRes;
	for (i = 0; i < CpDef_Xeh_CountOfBlocks - 1; i++) {
		sum = Cp_XehMath_Add(
			sum,
			Cp_XehMath_Mult(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]),
				Cp_XehMath_Add(
					Cp_XehMath_Load(
						&((const char*)tau_3Sn_degrees_out)[(CpDef_Xeh_CountOfBlocks - 1 - i) * sizeof(t_bPoly)]),
					Cp_XehMath_LoadInt(i + 1))));
	}
	/*y_3Sn*/sum = Cp_XehMath_Add(
		Cp_XehMath_Load(&((const char*)blocks)[(CpDef_Xeh_CountOfBlocks - 1) * sizeof(t_bPoly)]),
		sum);

	/*t_bPoly */multRes = tau_2Sn;
	for (i = 0; i < CpDef_Xeh_CountOfBlocks - 1; i++) {
		Cp_XehMath_Store(
			Cp_XehMath_Add(
				/*c_i*/Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]),
				Cp_XehMath_Add(/*y_3Sn*/sum, multRes)),
			&((char*)blocks_out)[i * sizeof(t_bPoly)]);
		multRes = Cp_XehMath_MultByReductPoly(multRes);
	}
	Cp_XehMath_Store(
		Cp_XehMath_Add(/*y_3Sn*/sum, multRes),
		&((char*)blocks_out)[(CpDef_Xeh_CountOfBlocks - 1) * sizeof(t_bPoly)]);
#else
	Cp_XehMath_Store(Cp_XehMath_LoadInt(1), &((char*)tau_3Sn_degrees_out)[0]);
	t_bPoly sum = tau_3Sn;
	for (i = 1; i < countOfBlocks; i++) {
		Cp_XehMath_Store(sum, &((char*)tau_3Sn_degrees_out)[i * sizeof(t_bPoly)]);
		sum = Cp_XehMath_Mult(sum, tau_3Sn);
	}

	t_bPoly multRes = { 0 };
	sum = multRes;
	for (i = 0; i < countOfBlocks - 1; i++) {
		sum = Cp_XehMath_Add(
			sum,
			Cp_XehMath_Mult(
				Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]),
				Cp_XehMath_Add(
					Cp_XehMath_Load(
						&((const char*)tau_3Sn_degrees_out)[(countOfBlocks - 1 - i) * sizeof(t_bPoly)]),
					Cp_XehMath_LoadInt(i + 1))));
	}
	/*y_3Sn*/sum = Cp_XehMath_Add(
		Cp_XehMath_Load(&((const char*)blocks)[(countOfBlocks - 1) * sizeof(t_bPoly)]),
		sum);

	/*t_bPoly */multRes = tau_2Sn;
	for (i = 0; i < countOfBlocks - 1; i++) {
		Cp_XehMath_Store(
			Cp_XehMath_Add(
				/*c_i*/Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]),
				Cp_XehMath_Add(/*y_3Sn*/sum, multRes)),
			&((char*)blocks_out)[i * sizeof(t_bPoly)]);
		multRes = Cp_XehMath_MultByReductPoly(multRes);
	}
	Cp_XehMath_Store(
		Cp_XehMath_Add(/*y_3Sn*/sum, multRes),
		&((char*)blocks_out)[(countOfBlocks - 1) * sizeof(t_bPoly)]);
#endif
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehImpl_Internal_g(
	const void* blocks, 
	const int countOfBlocks, 
	const t_bPoly tau_2Sn, 
	const void* tau_3Sn_degrees, 
	void* blocks_out) 
{
	t_bPoly multRes = tau_2Sn;
	t_bPoly ccc_n;
	int i;
#if CpDef_Xeh_SizeOfSector
	for (i = 0; i < CpDef_Xeh_CountOfBlocks; i++) {
		ccc_n = Cp_XehMath_Sub(Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]), multRes);
		Cp_XehMath_Store(ccc_n, &((char*)blocks_out)[i * sizeof(t_bPoly)]);
		multRes = Cp_XehMath_MultByReductPoly(multRes);
	}

	t_bPoly sum = {0};
	for (i = 0; i < CpDef_Xeh_CountOfBlocks - 1; i++) {
		/*c_i*/multRes = Cp_XehMath_Sub(
			Cp_XehMath_Load(&((const char*)blocks_out)[i * sizeof(t_bPoly)]),
			ccc_n);
		Cp_XehMath_Store(multRes, &((char*)blocks_out)[i * sizeof(t_bPoly)]);

		sum = Cp_XehMath_Add(
			sum,
			Cp_XehMath_Mult(
				/*c_i*/multRes,
				Cp_XehMath_Add(
					Cp_XehMath_Load(&((const char*)tau_3Sn_degrees)[(CpDef_Xeh_CountOfBlocks - 1 - i) * sizeof(t_bPoly)]),
					Cp_XehMath_LoadInt(i + 1))));
	}

	Cp_XehMath_Store(
		Cp_XehMath_Sub(ccc_n, sum),
		&((char*)blocks_out)[(CpDef_Xeh_CountOfBlocks - 1) * sizeof(t_bPoly)]);
#else
	for (i = 0; i < countOfBlocks; i++) {
		ccc_n = Cp_XehMath_Sub(Cp_XehMath_Load(&((const char*)blocks)[i * sizeof(t_bPoly)]), multRes);
		Cp_XehMath_Store(ccc_n, &((char*)blocks_out)[i * sizeof(t_bPoly)]);
		multRes = Cp_XehMath_MultByReductPoly(multRes);
	}

	t_bPoly sum = { 0 };
	for (i = 0; i < countOfBlocks - 1; i++) {
		/*c_i*/multRes = Cp_XehMath_Sub(
			Cp_XehMath_Load(&((const char*)blocks_out)[i * sizeof(t_bPoly)]),
			ccc_n);
		Cp_XehMath_Store(multRes, &((char*)blocks_out)[i * sizeof(t_bPoly)]);

		sum = Cp_XehMath_Add(
			sum,
			Cp_XehMath_Mult(
				/*c_i*/multRes,
				Cp_XehMath_Add(
					Cp_XehMath_Load(&((const char*)tau_3Sn_degrees)[(countOfBlocks - 1 - i) * sizeof(t_bPoly)]),
					Cp_XehMath_LoadInt(i + 1))));
	}

	Cp_XehMath_Store(
		Cp_XehMath_Sub(ccc_n, sum),
		&((char*)blocks_out)[(countOfBlocks - 1) * sizeof(t_bPoly)]);
#endif
	
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehImpl_Internal_EncBlocks(
	const void* blocks, 
	const int countOfBlocks, 
	void* context, 
	void* blocks_out) 
{
	int i;
#if CpDef_Xeh_SizeOfSector
	for (i = 0; i < CpDef_Xeh_CountOfBlocks; i++) {
		Cp_XehEnc_EncBlock_K1(
			&((const char*)blocks)[i * sizeof(t_bPoly)], 
			context, 
			(void*)&((const char*)blocks_out)[i * sizeof(t_bPoly)]);
	}
#else
	for (i = 0; i < countOfBlocks; i++) {
		Cp_XehEnc_EncBlock_K1(
			&((const char*)blocks)[i * sizeof(t_bPoly)],
			context, 
			(void*)&((const char*)blocks_out)[i * sizeof(t_bPoly)]);
	}
#endif
}

static inline CpDef_Xeh_FuncKernelSse2 void Cp_XehImpl_Internal_DecBlocks(
	const void* blocks, 
	const int countOfBlocks, 
	void* context, 
	void* blocks_out) 
{
	int i;
#if CpDef_Xeh_SizeOfSector
	for (i = 0; i < CpDef_Xeh_CountOfBlocks; i++) {
		Cp_XehEnc_DecBlock_K1(
			&((const char*)blocks)[i * sizeof(t_bPoly)],
			context, 
			(void*)&((const char*)blocks_out)[i * sizeof(t_bPoly)]);
	}
#else
	for (i = 0; i < countOfBlocks; i++) {
		Cp_XehEnc_DecBlock_K1(
			&((const char*)blocks)[i * sizeof(t_bPoly)],
			context, 
			(void*)&((const char*)blocks_out)[i * sizeof(t_bPoly)]);
	}
#endif
}