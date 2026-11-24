#pragma once

//CodesBase

/*typedef*/ enum Cp_XehCodes_Impl_EnumCodesBase
{
	ECBase_ok,
	ECBase_inputSeqLen
};

typedef enum Cp_XehCodes_Impl_EnumCodesBase t_code;

static inline t_code Cp_XehCodes_Impl_Ok(void* context) {
	return /*Cp_XehCodes_Impl_EnumCodesBase::*/ECBase_ok;
}
static inline /*_Bool*/bool Cp_XehCodes_Impl_IsOk(const t_code code, void* context) {
	return code == ECBase_ok;
}

static inline t_code Cp_XehCodes_Impl_InputSeqLen(const long long len, void* context) {
	return ECBase_inputSeqLen;
}