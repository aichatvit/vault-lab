/** @file AssymetricEncryptionFuncs.h 
* Функции ассиметричного шифрования крипто-плагина. 
*/
#pragma once

#include <cstdint>

#include "../Common/mstring.h"
#include "../Common/SharedLibFuncsAtr.h"

extern "C"
{
/**
	 * \brief Создает контекст ассиметричного шифрования. Функция потокобезопасна.
	 * \param cryptoContext Главный контекст криптоплагина.
	 * \param algDef Идентификатор алгоритма. Берется из AsymmetricAlgDef.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контекст ассиметричного шифрования.
	 */
	EXPORT void* CDECL createAsymmetricContext(void* cryptoContext, int32_t algDef, int32_t* error_out);
/**
	 * \brief Удаляет контекст ассиметричного шифрования. Функция потокобезопасна.
	 * \param cryptoContext Главный контекст криптоплагина.
	 * \param asymmetricContext Контекст ассиметричного шифрования.
	 * \return Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой. 
	 */
	EXPORT bool CDECL destroyAsymmetricContext(void* cryptoContext, void* asymmetricContext);

/**
	 * \brief Импортирует публичные параметры в контекст ассиметричного алгоритма. Например открытый ключ. Не является потокобезопасной.
	 * \param asymmetricContext Контекст ассиметричного шифрования.
	 * \param data Указатель на последовательность байт с открытыми параметрами, которые требуется импортировать.
	 * \param lenOfData Длина последовательности.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL importPublicData(void* asymmetricContext, const uint8_t* data, uint32_t lenOfData, int32_t* error_out);
/**
	 * \brief Экспортирует открытые параметры из контекста ассиметричного алгоритма. Например открытый ключ. Не является потокобезопасной.
	 * \param asymmetricContext Контекст ассиметричного шифрования.
	 * \param includeAll Флаг, определяющий будут ли все, в зависимости от реализации, открытые параметры контекста ассиметричного
	 * алгоритма экспортироваться при вызове этой функции. Если true - то экспортироваться будут все открытые параметры.
	 * \param lenOfData_out Указатель для длины выходной последовательности. По нему будет записана длина.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на выходную последовательность.
	 */
	EXPORT void* CDECL exportPublicData(void* asymmetricContext, bool includeAll, uint32_t* lenOfData_out, int32_t* error_out);

/**
	 * \brief Импортирует пару ключей в защищенном на пароле контейнере в контекст ассиметричного алгоритма. Не является потокобезопасной.
	 * \param asymmetricContext Контекст ассиметричного алгоритма.
	 * \param pass Пароль для защищенного контейнера с парой ключей.
	 * \param container Указатель на контейнер.
	 * \param lenOfContainer Длина контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL asymm_importKeyByPass(void* asymmetricContext, const mchar* pass, 
		const uint8_t* container, uint32_t lenOfContainer, int32_t* error_out);
/**
	 * \brief Экспортирует пару ключей из ассиметричного контекста в защищенном контейнере на пароле. Не является потокобезопасной.
	 * \param asymmetricContext Контекст ассиметричного алгоритма.
	 * \param pass Пароль для защиты контейнера.
	 * \param lenOfContainer_out Выходная длина контейнера.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на созданный контейнер с парой ключей из ассиметричного контекста.
	 */
	EXPORT void* CDECL asymm_exportKeyByPass(void* asymmetricContext, const  mchar* pass, uint32_t* lenOfContainer_out, 
		int32_t* error_out);

/**
	 * \brief Шифрует последовательность с использованием ассиметричного алгоритма. Функция потокобезопасна, если одновременно с ней не вызываются ни какие функции кроме encrypt и decrypt.
	 * \param asymmetricContext Контекст ассиметричного алгоритма.
	 * \param data Указатель на последовательность байтов для шифрования.
	 * \param lenOfData Длина последовательности.
	 * \param destLen_out Длина выходной последовательности.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на выходную зашифрованную последовательность.
	 */
	EXPORT void* CDECL encrypt(void* asymmetricContext, const uint8_t* data, uint32_t lenOfData, uint32_t* destLen_out,
		int32_t* error_out);
/**
	 * \brief Расшифровывает входную последовательность байт. Функция потокобезопасна, если одновременно с ней не вызываются ни какие функции кроме encrypt и decrypt.
	 * \param asymmetricContext Контекст ассиметричного алгоритма.
	 * \param data Указатель на последовательность байтов для расшифрования.
	 * \param lenOfData Длина последовательности для расшифрования.
	 * \param destLen_out Указатель на длину, куда будет записана длина результирующий расшифрованной последовательности.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на выходную расшифрованную последовательность.
	 */
	EXPORT void* CDECL decrypt(void* asymmetricContext, const uint8_t* data, uint32_t lenOfData, uint32_t* destLen_out,
		int32_t* error_out);
}

