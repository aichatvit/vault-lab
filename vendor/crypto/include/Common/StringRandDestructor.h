#pragma once

#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>

#include "../../Abstractions/RandomBase.h"

template<typename TStr>
class StringRandDestructor {
public:
	TStr str;
	std::shared_ptr<RandomBase> rand;

	StringRandDestructor(TStr&& str_, std::shared_ptr<RandomBase>&& rand_) :
		str(std::move(str_)), rand(std::move(rand_)) {
		assert(!str.empty());
		assert(rand != nullptr);
	}
	/*StringRandDestructor(const TStr& str_, const std::shared_ptr<RandomBase>& rand_) :
		str(str_), rand(rand_) {
		assert(!str.empty());
		assert(rand != nullptr);
	}*/
	StringRandDestructor(TStr&& str_, const std::shared_ptr<RandomBase>& rand_) :
		str(str_), rand(rand_) {
		assert(!str.empty());
		assert(rand != nullptr);
	}
	operator const TStr& () const {
		return str;
	}
	operator TStr& () {
		return str;
	}
	operator std::shared_ptr<RandomBase> () const {
		return rand;
	}

	~StringRandDestructor() {
		if constexpr (std::is_same_v<TStr, std::string>) {
			rand->GenerateRandomBytes(reinterpret_cast<uint8_t*>(str.data()), str.size());
		}
		else if constexpr (std::is_same_v<TStr, std::wstring>) {
			rand->GenerateRandomBytes(reinterpret_cast<uint8_t*>(str.data()), str.size() * sizeof(wchar_t));
		}
		else if constexpr (std::is_same_v<TStr, std::vector<uint8_t>>) {
			rand->GenerateRandomBytes(reinterpret_cast<uint8_t*>(str.data()), str.size());
		}
		else if constexpr (std::is_same_v<TStr, std::vector<char>>) {
			rand->GenerateRandomBytes(reinterpret_cast<uint8_t*>(str.data()), str.size());
		}
		else {
			static_assert(std::is_same_v<TStr, std::vector<char>>);
		}
	}
};