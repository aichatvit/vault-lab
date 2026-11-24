#pragma once

#define CpDef_XehMath_Intrin
#define CpDef_Xeh_SizeOfSector /*512*/4096
#define CpDef_XehEnc_Test

#include "../Xeh.h"

static inline CpDef_Xeh_FuncKernelSse2 int Cp_XehTests_Encrypt_Sector() {

	//const int sectorLen = 512;
	char* sectorBuf = malloc(CpDef_Xeh_SizeOfSector);
	for (int i = 0; i < CpDef_Xeh_SizeOfSector; i++)
		sectorBuf[i] = 1;
	char* degreesBuf = malloc(CpDef_Xeh_SizeOfSector);
	for (int i = 0; i < CpDef_Xeh_SizeOfSector; i++)
		degreesBuf[i] = 0;
	char* bufEnc = malloc(CpDef_Xeh_SizeOfSector);
	for (int i = 0; i < CpDef_Xeh_SizeOfSector; i++)
		bufEnc[i] = 0;
	char* bufDec = malloc(CpDef_Xeh_SizeOfSector);
	for (int i = 0; i < CpDef_Xeh_SizeOfSector; i++)
		bufDec[i] = 0;
	const int sectorNumb = 1024;

	Cp_Xeh_EncSector(sectorBuf, 0, sectorNumb, NULL, degreesBuf, bufEnc);
	Cp_Xeh_DecSector(bufEnc, 0, sectorNumb, NULL, degreesBuf, bufDec);

	for (int i = 0; i < CpDef_Xeh_SizeOfSector; i++)
		if (bufDec[i] != sectorBuf[i])
			return -1;

	free(sectorBuf);
	free(degreesBuf);
	free(bufEnc);
	free(bufDec);

	return 0;
}

#undef CpDef_XehEnc_Test
#undef CpDef_Xeh_SizeOfSector
#undef CpDef_XehMath_Intrin