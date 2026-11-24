/** @file HashFuncs.h
 * \brief Функции для генерации хеш последовательности.
 *
 * Преобразует входную последовательность в последовательность определенной длины. Хеш используется для реализации
 * обеспечения целостности (например в алгоритмах hmac), цифровой подписи (ЭЦП).
 *
 * Для использования хэш функций требуется создать крипто контекст с указанием идентификатора алгоритма и требуемой длины
 * выходной последовательности. Возможные длины выходной последовательности указаны в документации к используемому алгоритму.
 */
#pragma once

#include <cstdint>
#include "../Common/SharedLibFuncsAtr.h"

extern "C"
{
/**
	 * \brief Создает контекст хэш алгоритма. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param algDef Идентификатор алгоритма для вычисления хэш значения. Из файла HashAlgDef.
	 * \param hashLen Длина выходного хэш значения.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контекст хэш алгоритма.
	 */
	EXPORT void* CDECL createHashInst(void* cryptoContext, int32_t algDef, int32_t hashLen, int32_t* error_out);
/**
	 * \brief Удаляет контекст хэш алгоритма. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param hashInst Контекст хэш алгоритма.
	 * \return Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL deleteHashInst(void* cryptoContext, void* hashInst);

/**
	 * \brief Вычисляет хэш значение от входной последовательности. Не является потокобезопасной.
	 * \param hashInst Контекст хэш алгоритма.
	 * \param seq Входная последовательность.
	 * \param lenOfSeq Длина входной последовательности.
	 * \param result Выходное хэш значение.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL compHash(void* hashInst, const void* seq, uint32_t lenOfSeq, void* result, int32_t* error_out);
/**
	 * \brief Вычисляет хэш значение без предварительного создания криптографического контекста. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param algDef Идентификатор алгоритма для вычисления хэш значения. Из файла HashAlgDef.
	 * \param hashLen Длина выходного хэш значения.
	 * \param seq Входная последовательность.
	 * \param lenOfSeq Длина входной последовательности.
	 * \param result Выходное хэш значение.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL compHash_port(void* cryptoContext, int32_t algDef, int32_t hashLen, void* seq,
		uint32_t lenOfSeq, void* result, int32_t* error_out);

/**
	 * \brief Обновляет выходное хэш значение в контексте. Не является потокобезопасной.
	 * \param hashInst Контекст хэш алгоритма.
	 * \param seq Входная последовательность.
	 * \param lenOfSeq Длина входной последовательности.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL updateHash(void* hashInst, void* seq, uint32_t lenOfSeq, int32_t* error_out);
/**
	 * \brief Возвращает финальный результат вычисленного хэш значения из контекста. Не является потокобезопасной.
	 * \param hashInst Контекст хэш алгоритма.
	 * \param result Указатель на выходное хэш значение.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL finalResult(void* hashInst, void* result, int32_t* error_out);
}