/** @file HmacFuncs.h
 * \brief Функции для генерации HMAC.
 *
 * HMAC специальный код, сгенерированный с использованием секретного ключа, для проверки
 * целостности информации. Обычно такой код располагается вместе с передаваемой информацией для проверки на другой стороне.
 * Если передаваемая информация была изменена, то hmac будет отличаться. Для работы алгоритма необходим секретный ключ,
 * который будет известен обоим сторонам участвующих в передачи информации.
 *
 * Для использования функций необходимо создать крипто контекст. Для получения информации о специальных параметрах,
 * используемых в алгоритме hmac, есть специальная функция Hmac_getData().
 * 
 */
#pragma once

#include <cstdint>
#include "../Common/SharedLibFuncsAtr.h"
#include "HmacData.h"

extern "C"
{
/**
	 * \brief Заполняет структуру с информацией об размерах ключей для инициализации алгоритма hmac. Функция потокобезопасна.
	 * \param algDef Идентификатор алгоритма hmac. Файл HmacAlgDef.h
	 * \param hmacLen Длина выходного значения hmac. Файл HmacAlgDef.h
	 * \param data Указатель на структуру, с информацией об размерах ключей, для заполнения.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL Hmac_getData_KeySizes(int32_t algDef, int32_t hmacLen, HmacData_KeySizes* data, int32_t* error_out);
/**
	 * \brief Заполняет структуру с информацией об алгоритме hmac. Функция потокобезопасна.
	 * \param hmacContext Контекст для вычисления значения hmac.
	 * \param data Указатель на структуру для заполнения.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL Hmac_getData(const void* hmacContext, HmacData* data, int32_t* error_out);
/**
	 * \brief Создает контекст для вычисления значения hmac с входным ключом. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param algDef Идентификатор алгоритма hmac. Файл HmacAlgDef.h
	 * \param hmacLen Длина выходного значения hmac. Файл HmacAlgDef.h
	 * \param key Ключ для инициализации контекста hmac.
	 * \param lenOfKey Длина ключа в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контекст для вычисления значения hmac.
	 */
	EXPORT void* CDECL createHmacInst_key(void* cryptoContext, int32_t algDef, int32_t hmacLen, void* key, uint32_t lenOfKey, 
		int32_t* error_out);
/**
	 * \brief Создает контекст для вычисления значения hmac. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param algDef Идентификатор алгоритма hmac. Файл HmacAlgDef.h
	 * \param hmacLen Длина выходного значения hmac. Файл HmacAlgDef.h
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контекст для вычисления значения hmac.
	 */
	EXPORT void* CDECL createHmacInst(void* cryptoContext, int32_t algDef, int32_t hmacLen, int32_t* error_out);
/**
	 * \brief Удаляет контекст для вычисления значения hmac. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param hmacInst Контекст для вычисления значения hmac.
	 * \return Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL deleteHmacInst(void* cryptoContext, void* hmacInst);

/**
	 * \brief Устанавливает ключ в контекст. Не является потокобезопасной.
	 * \param hmacContext Контекст для вычисления значения hmac.
	 * \param key Ключ.
	 * \param lenOfKey Длина ключа в байтах.
	 * \param error_out Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL setKeyInst(void* hmacContext, void* key, uint32_t lenOfKey, int32_t* error_out);

/**
	 * \brief Вычисляет значение hmac от входной последовательности. Не является потокобезопасной.
	 * \param hmacInst Контекст для вычисления значения hmac.
	 * \param seq Входная последовательность.
	 * \param lenOfSeq Длина входной последовательности.
	 * \param result Указатель на память в которую будет записано вычисленное значение hmac.
	 * \param error_out Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL compHmac(void* hmacInst, void* seq, uint32_t lenOfSeq, void* result, int32_t* error_out);

/**
	 * \brief Обновляет значение hmac в контексте от входной последовательности. Не является потокобезопасной.
	 * \param hmacInst Контекст для вычисления значения hmac.
	 * \param seq Входная последовательность.
	 * \param lenOfSeq Длина входной последовательности.
	 * \param error_out Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL updateHmac(void* hmacInst, void* seq, uint32_t lenOfSeq, int32_t* error_out);
/**
	 * \brief Вычисляет конечное значение hmac. Не является потокобезопасной.
	 * \param hmacInst Контекст для вычисления значения hmac.
	 * \param result Указатель на память в которую будет записано вычисленное значение hmac.
	 * \param error_out Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL finalHmac(void* hmacInst, void* result, int32_t* error_out);
}