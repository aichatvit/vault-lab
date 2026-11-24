#pragma once

#if defined(CpDef_Xeh_EnableFuncKernelSse2)
	#define CpDef_Xeh_FuncKernelSse2 __attribute__((target("sse2")))
#else
	#define CpDef_Xeh_FuncKernelSse2
#endif
//__attribute__((target("sse2")))