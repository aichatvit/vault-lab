/** @file SeqCheckerFuncs.h
 * \brief Функции проверки последовательности на случайность.
 * С помощью данной проверки можно убедится в качестве выработанной последовательности из различных источников.
 * Проверенную случайную последовательность можно использовать, например, для инициализации ключом симметричного контекста.
 */
#pragma once

#include <cstdint>

#include "../Common/mstring.h"
#include "../Common/SharedLibFuncsAtr.h"

extern "C"
{
	/*EXPORT void* CDECL createInstance_SequenceChecker(void* cryptoContext, int32_t* error_out);
	EXPORT bool CDECL deleteSequenceChecker(void* cryptoContext, void* seqCheckerInst);*/

	/**
	 * \brief Проверяет последовательность на случайность. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param seq Последовательность для проверки на случайность.
	 * \param lenOfSeq Длина последовательности.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Булевый флаг обозначающий успешность пройденной проверки последовательности на случайность.
	 * Если значение true - последовательность считается успешность, если false - последовательность не является случайной.
	 */
	EXPORT bool CDECL checkSequence_port(void* cryptoContext, void* seq, uint32_t lenOfSeq, int32_t* error_out);
	//EXPORT bool CDECL checkSequence(void* seqCheckerInst, int32_t* error_out);
}