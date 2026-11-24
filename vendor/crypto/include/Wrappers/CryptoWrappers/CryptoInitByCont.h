#pragma once

#include <vector>

#include "InitMethodType.h"
#include "../../Common/mstring.h"

class CryptoInitByCont {
public:
	static constexpr InitMethodType initType{ InitMethodType::cont };

	bool mNeedToBlock;
	std::vector<std::uint8_t> mKkp;
	const mstring mPass;
	
	CryptoInitByCont(std::vector<std::uint8_t>&& kkp, const mstringView& pass_, bool needBlockByRand_ = false) :
		mNeedToBlock(needBlockByRand_), mKkp(std::move(kkp)), mPass(pass_)
	{
	}
	CryptoInitByCont(const void* kkp, const std::uint32_t lenOfKkp, const mchar* pass_, bool needBlockByRand_ = false) :
		mNeedToBlock(needBlockByRand_), 
		mKkp(static_cast<const std::uint8_t*>(kkp), static_cast<const std::uint8_t*>(kkp) + lenOfKkp), 
		mPass(pass_)
	{
	}
};