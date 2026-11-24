#pragma once

#include <cassert>
#include <memory>
#include "../../Abstractions/SymmetricAlgoritmBase.h"

class SymContext
{
public:
	//std::shared_ptr<SymmetricAlgoritmBase> alg;
	SymmetricAlgoritmBase* alg;
	SymmetricEncrypter* encrypter;

	//SymContext() = default;
	/*SymContext(SymmetricEncrypter* encrypter_, std::shared_ptr<SymmetricAlgoritmBase>& alg_)
		: alg(alg_), encrypter(encrypter_)
	{
		assert(encrypter_);
	}*/
	SymContext(SymmetricEncrypter* encrypter_, SymmetricAlgoritmBase* alg_)
		: alg(alg_), encrypter(encrypter_)
	{
		assert(encrypter_);
	}
};
