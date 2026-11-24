#pragma once

//#include "CryptoWrappers/BaseCrypt.h"
#include <cassert>
#include <type_traits>

template<typename TFunc = void, typename TByteSeq = void>
class LibMemoryOwner
{
	using type_func_destroyMemory = TFunc;

	TByteSeq* ptr_raw{};
	size_t sizeOfMem{};
	TFunc func_destroyMemory{};
	void* cryptoContext{};

public:
	LibMemoryOwner() = default;
	LibMemoryOwner(TFunc func_destroyMemory_, void* cryptoContext_, TByteSeq* ptr_raw_, size_t size_) :
		ptr_raw(ptr_raw_), sizeOfMem(size_), func_destroyMemory(func_destroyMemory_), cryptoContext(cryptoContext_)
	{
		static_assert(std::is_pointer_v<TFunc>);

		assert(func_destroyMemory_ != nullptr);
		assert(cryptoContext != nullptr);
		assert(ptr_raw_ != nullptr);
		assert(size_ != 0);
	}
	~LibMemoryOwner()
	{
		dispose();
	}
	LibMemoryOwner(const LibMemoryOwner<TFunc>& obj) = delete;
	LibMemoryOwner(LibMemoryOwner<TFunc>&& obj) noexcept
	{
		ptr_raw = obj.ptr_raw;
		obj.ptr_raw = nullptr;
		sizeOfMem = obj.sizeOfMem;
		obj.sizeOfMem = 0;
		func_destroyMemory = obj.func_destroyMemory;
		obj.func_destroyMemory = nullptr;
	}
	LibMemoryOwner<TFunc>& operator=(const LibMemoryOwner<TFunc>& obj) = delete;
	LibMemoryOwner<TFunc>& operator=(LibMemoryOwner<TFunc>&& obj)
	{
		dispose();

		ptr_raw = obj.ptr_raw;
		obj.ptr_raw = nullptr;
		sizeOfMem = obj.sizeOfMem;
		obj.sizeOfMem = 0;
		func_destroyMemory = obj.func_destroyMemory;
		obj.func_destroyMemory = nullptr;

		return *this;
	}

	[[nodiscard]] void* data()
	{
		return ptr_raw;
	}
	[[nodiscard]] const void* data() const
	{
		return ptr_raw;
	}
	[[nodiscard]] size_t size() const
	{
		return sizeOfMem;
	}
	void release()
	{
		ptr_raw = nullptr;
		sizeOfMem = 0;
	}

private:
	void dispose()
	{
		if (ptr_raw == nullptr || sizeOfMem == 0)
			return;

		const auto res_destroyMemory = func_destroyMemory(cryptoContext, ptr_raw, static_cast<uint32_t>(sizeOfMem));
		assert(res_destroyMemory);
		ptr_raw = nullptr;
		sizeOfMem = 0;
	}
};