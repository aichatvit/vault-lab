
#include "../../Common/mStringHelper.h"
/*return func_createCryptoContextBySignSeq(initParams.getKkp().data(), initParams.getKkp().size(),
				initParams.getPass().data(), initParams.getSeq().data(), initParams.getSeq().size(),
				initParams.getSign().data(), initParams.getSign().size(), &error_out);*/

struct SigSeqParams {
	int32_t typeOfParams;
	bool needRandomBlock;
	const void* seq;
	uint32_t lenOfSeq;
	const void* kkp;
	uint32_t lenOfKkp;
	const mchar* passToKkp;
	uint32_t lenOfPassToKkp;
	const void* sign;
	uint32_t lenOfSign;
};