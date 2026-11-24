#pragma once

#include <cstdint>
#include <vector>
#include <tuple>

#include "InitMethodType.h"

class CryptoInitBySeq
{
	std::vector<uint8_t> seq{};
	bool needBlockByRand{};
public:
	CryptoInitBySeq() = default;
	CryptoInitBySeq(std::vector<uint8_t>&& seq_, bool needBlockByRand_ = false)
		: seq(std::move(seq_)), needBlockByRand(needBlockByRand_)
	{
	}

	static constexpr InitMethodType initType{ InitMethodType::bySeq };

	std::tuple<uint8_t*, size_t, bool> getSeqTuple()
	{
		return std::tuple<uint8_t*, size_t, bool>(seq.data(), seq.size(), needBlockByRand);
		//return std::make_tuple<uint8_t*, size_t, bool>(seq.data(), seq.size(), ds);
	}
};