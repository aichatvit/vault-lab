#pragma once

#include <cstdint>
#include <vector>
#include <tuple>

#include "InitMethodType.h"
#include "../../Common/mstring.h"

class CryptoInitBySignSeq
{
	std::vector<uint8_t> seq;
	std::vector<uint8_t> kkp;
	std::vector<uint8_t> sign;
	const mstring pass;
	bool needToBlock;

public:
	CryptoInitBySignSeq(std::vector<uint8_t>&& seq_, std::vector<uint8_t>&& kkp_, std::vector<uint8_t>&& sign_,
		const mstringView& pass_, bool needToBlock_ = false)
		: seq(std::move(seq_)), kkp(std::move(kkp_)), sign(std::move(sign_)), pass(pass_), needToBlock(needToBlock_)
	{
	}
	CryptoInitBySignSeq(const uint8_t* seq_, size_t sizeOfSeq, const uint8_t* kkp_, size_t sizeOfKkp, const uint8_t* sign_, 
		size_t sizeOfSign, const mstringView& pass_, bool needToBlock_ = false)
		: seq(sizeOfSeq), kkp(sizeOfKkp), sign(sizeOfSign), pass(pass_), needToBlock(needToBlock_)
	{
		std::copy_n(seq_, sizeOfSeq, seq.data());
		std::copy_n(kkp_, sizeOfKkp, kkp.data());
		std::copy_n(sign_, sizeOfSign, sign.data());
	}
	template<typename TSeq, typename TKkp, typename TSign>
	CryptoInitBySignSeq(TSeq& seq, TKkp& kkp, TSign& sign, const mstringView& pass_, bool needToBlock_ = false)
		: CryptoInitBySignSeq(static_cast<const uint8_t*>(seq.data()), seq.size(), 
			static_cast<const uint8_t*>(kkp.data()), kkp.size(), 
			static_cast<const uint8_t*>(sign.data()), sign.size(), pass_, needToBlock_)
	{
	}		
		

	static constexpr InitMethodType initType{ InitMethodType::bySignSeq };

	[[nodiscard]] const std::vector<uint8_t>& getSeq() const
	{
		return seq;
	}
	[[nodiscard]] const std::vector<uint8_t>& getKkp() const
	{
		return kkp;
	}
	[[nodiscard]] const std::vector<uint8_t>& getSign() const
	{
		return sign;
	}
	[[nodiscard]] mstringView getPass() const
	{
		return mstringView{ pass };
	}
	[[nodiscard]] bool getNeedBlock() const 
	{
		return needToBlock;
	}
};