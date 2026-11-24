#pragma once

#if defined CpDef_XehCodes_Base
#include "CodesBase.h"
#elif defined CpDef_XehCodes_Custom
#else
#include "CodesBase.h"
#endif

static inline t_code Cp_XehCodes_Ok(void* context) {
	return Cp_XehCodes_Impl_Ok(context);
}
static inline /*_Bool*/bool Cp_XehCodes_IsOk(const t_code code, void* context) {	return Cp_XehCodes_Impl_IsOk(code, context);
}

static inline t_code Cp_XehCodes_InputSeqLen(const long long len, void* context) {
	return Cp_XehCodes_Impl_InputSeqLen(len, context);
}
