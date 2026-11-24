#pragma once

#include <map>
#include <string_view>
#include <exception>

#include "SharedErrors.h"

#define STRING(s) #s

class ErrorsStringGetter {
public:
	using type_argErrorUnderType = std::underlying_type_t<SharedErrors::Errors>;
	using type_ErrorsUnderType = std::underlying_type_t<SharedErrors::Errors>;

	std::map<type_argErrorUnderType, const std::string_view> map_argumentErrors{};
	std::map<type_ErrorsUnderType, const std::string_view> map_Errors{};

	void init() {
		initMaps();
	}

	static constexpr std::string_view getStr_argErrors(const type_argErrorUnderType argError) {
		switch (argError)
		{
		case 1: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::cryptoContext));
			return std::string_view{ STRING(cryptoContext) }; }
		case 2: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::algDef));
			return std::string_view{ STRING(algDef) }; }
		case 3: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::inputSeq));
			return std::string_view{ STRING(inputSeq) }; }
		case 4: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::outputSeq));
			return std::string_view{ STRING(outputSeq) }; }
		case 5: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::key));
			return std::string_view{ STRING(key) }; }
		case 6: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::container));
			return std::string_view{ STRING(container) }; }
		case 7: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::pass));
			return std::string_view{ STRING(pass) }; }
		case 8: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::signSeq));
			return std::string_view{ STRING(signSeq) }; }
		case 9: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::iv));
			return std::string_view{ STRING(iv) }; }
		case 10: {
			assert(argError == static_cast<type_argErrorUnderType>(SharedErrors::Errors::params));
			return std::string_view{ STRING(params) }; }
		default:
			return std::string_view{};
		}
	}

	static constexpr std::string_view getStr_errors(const type_ErrorsUnderType error) {
		constexpr type_ErrorsUnderType firstVal{ /*static_cast<type_ErrorsUnderType>(SharedErrors::Errors::__max)*/11 };
		switch (error)
		{
		case firstVal + 0: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::invalidOperation));
			return std::string_view{ STRING(invalidOperation) }; }
		case firstVal + 1: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importKkpByPass));
			return std::string_view{ STRING(importKkpByPass) }; }
		case firstVal + 2: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importByAsymmetricEncrypter));
			return std::string_view{ STRING(importByAsymmetricEncrypter) }; }
		case firstVal + 3: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::cryptoObjCreate));
			return std::string_view{ STRING(cryptoObjCreate) }; }
		case firstVal + 4: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::cryptoObjInit));
			return std::string_view{ STRING(cryptoObjInit) }; }
		case firstVal + 5: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportKkpByPass));
			return std::string_view{ STRING(exportKkpByPass) }; }
		case firstVal + 6: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::initCryptoBySeq));
			return std::string_view{ STRING(initCryptoBySeq) }; }
		case firstVal + 7: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::AsymmetricEnc));
			return std::string_view{ STRING(AsymmetricEnc) }; }
		case firstVal + 8: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::AsymmetricDec));
			return std::string_view{ STRING(AsymmetricDec) }; }
		case firstVal + 9: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importPublicDataToAsymmetricContext));
			return std::string_view{ STRING(importPublicDataToAsymmetricContext) }; }
		case firstVal + 10: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::asymmetricImportByPass));
			return std::string_view{ STRING(asymmetricImportByPass) }; }
		case firstVal + 11: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::asymmetricExportByPass));
			return std::string_view{ STRING(asymmetricExportByPass) }; }
		case firstVal + 12: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportPublicData));
			return std::string_view{ STRING(exportPublicData) }; }
		case firstVal + 13: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::seqCheck));
			return std::string_view{ STRING(seqCheck) }; }
		case firstVal + 14: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::randGen));
			return std::string_view{ STRING(randGen) }; }
		case firstVal + 15: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::compHash));
			return std::string_view{ STRING(compHash) }; }
		case firstVal + 16: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::compHmac));
			return std::string_view{ STRING(compHmac) }; }
		case firstVal + 17: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::noAlg));
			return std::string_view{ STRING(noAlg) }; }
		case firstVal + 18: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importPublicDataToDiffHellmanContext));
			return std::string_view{ STRING(importPublicDataToDiffHellmanContext) }; }
		case firstVal + 19: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importPublicDataToSignContext));
			return std::string_view{ STRING(importPublicDataToSignContext) }; }
		case firstVal + 20: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportPublicDataFromDiffHellmanContext));
			return std::string_view{ STRING(exportPublicDataFromDiffHellmanContext) }; }
		case firstVal + 21: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportPublicDataFromSignContext));
			return std::string_view{ STRING(exportPublicDataFromSignContext) }; }
		case firstVal + 22: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::deriveKeyMaterial));
			return std::string_view{ STRING(deriveKeyMaterial) }; }
		case firstVal + 23: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportDeriveKeyMaterial));
			return std::string_view{ STRING(exportDeriveKeyMaterial) }; }
		case firstVal + 24: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::getAdditionalPrivateParams));
			return std::string_view{ STRING(getAdditionalPrivateParams) }; }
		case firstVal + 25: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::setAdditionalPrivateParams));
			return std::string_view{ STRING(setAdditionalPrivateParams) }; }
		case firstVal + 26: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::sign));
			return std::string_view{ STRING(sign) }; }
		case firstVal + 27: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::verifySign));
			return std::string_view{ STRING(verifySign) }; }
		case firstVal + 28: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::setSymKey));
			return std::string_view{ STRING(setSymKey) }; }
		case firstVal + 29: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::symEnc));
			return std::string_view{ STRING(symEnc) }; }
		case firstVal + 30: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportSymKeyByPass));
			return std::string_view{ STRING(exportSymKeyByPass) }; }
		case firstVal + 31: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importSymKeyByPass));
			return std::string_view{ STRING(importSymKeyByPass) }; }
		case firstVal + 32: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportSymKeyByAssymEnc));
			return std::string_view{ STRING(exportSymKeyByAssymEnc) }; }
		case firstVal + 33: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importSymKeyByAssymEnc));
			return std::string_view{ STRING(importSymKeyByAssymEnc) }; }
		case firstVal + 34: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::exportSymKeyBySymAlg));
			return std::string_view{ STRING(exportSymKeyBySymAlg) }; }
		case firstVal + 35: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::importSymKeyBySymAlg));
			return std::string_view{ STRING(importSymKeyBySymAlg) }; }
		case firstVal + 36: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::symmGetData));
			return std::string_view{ STRING(symmGetData) }; }
		case firstVal + 37: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::noSymmMode));
			return std::string_view{ STRING(noSymmMode) }; }
		case firstVal + 38: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::blockByRandom));
			return std::string_view{ STRING(blockByRandom) }; }
		/*case firstVal + 39: {
			assert(error == static_cast<type_ErrorsUnderType>(SharedErrors::Errors::__max));
			return std::string_view{ STRING(__max) }; }*/
		default:
			return std::string_view{};
		}
	}
	//static constexpr int32_t checkFuncs() {
	//	for (type_argErrorUnderType i = 1; i < static_cast<type_argErrorUnderType>(SharedErrors::Errors::__max) /*- 1*/; i++)
	//	{
	//		if (getStr_argErrors(i).empty())
	//			return i;
	//	}
	//	for (type_ErrorsUnderType i = static_cast<type_ErrorsUnderType>(SharedErrors::Errors::__max);
	//		i < static_cast<type_ErrorsUnderType>(SharedErrors::Errors::__max) - 1; i++) {
	//		if (getStr_errors(i).empty())
	//			return i;
	//	}
	//	return 0;
	//}

private:
	void initMaps() {
		for (type_argErrorUnderType i = 1; i < static_cast<type_argErrorUnderType>(SharedErrors::Errors::__max) - 1; i++)
			map_argumentErrors.insert({ i, getStr_argErrors(i) });
		for (type_ErrorsUnderType i = static_cast<type_ErrorsUnderType>(SharedErrors::Errors::__max);
			i < static_cast<type_ErrorsUnderType>(SharedErrors::Errors::__max) - 1; i++)
			map_Errors.insert({ i, getStr_errors(i) });
	}
};

static_assert(!ErrorsStringGetter::getStr_argErrors(ErrorsStringGetter::type_argErrorUnderType{ 1 }).empty());
static_assert(!ErrorsStringGetter::getStr_errors(ErrorsStringGetter::type_ErrorsUnderType{ 30 }).empty());
//static_assert(ErrorsStringGetter::checkFuncs() == 0);