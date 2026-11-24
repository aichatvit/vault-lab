
#include <cstdint>

struct SeqParams {
	int32_t typeOfParams;
	bool needRandomBlock;
	void* seq;
	uint32_t lenOfSeq;
};