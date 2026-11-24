/** @file SymmetricFuncs.h
 * @brief Функции симметричного шифрования.
 *
 * При шифровании используется один секретный ключ. Использование предполагается совместно с конкретными режимами шифрования,
 * например, CBC. Режимы шифрования обеспечивают дополнительную защиту с учетом особенности,
 * что шифрование происходит блоками одинаковой длины.
 *
 * Работа с конкретным алгоритмом симметричного шифрования начинается с создания его контекста и выбора режима.
 * Этот контекст будет использоваться во всех функциях. При создании контекста,
 * сразу генерируется секретный ключ с использованием ПДСЧ. Когда контекст симметричного шифрования больше не нужен,
 * его необходимо удалить с помощью специальной функции, которая предназначен именно для этого типа контекста.
 *
 * Реализованы операции экспорта и импорта этого ключа в в виде защищенных контейнеров.
 * Контейнеры могут быть защищены разными способами,
 * например, с использованием пароля или другого симметричного контекста. Есть возможность получения специальных параметров
 * для выбранного алгоритма и режима шифрования. 
 */

#pragma once

#include <cstdint>

#include "../Common/SharedLibFuncsAtr.h"
#include "../Common/mstring.h"
#include "SymmAlgData.h"


extern "C"
{

/**
	 * \brief Возвращает данные о симметричном алгоритме. Функция потокобезопасна.
	 * \param symInst Контекст симметричного шифрования.
	 * \param algData_out Указатель на выходную структуру с данными.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sym_getData(void* symInst, SymmAlgData* algData_out, int32_t* error_out);
	/**
	 * \brief Импортирует ключ в контейнере защищенном на другом симметричном алгоритма (контексте). Не является потокобезопасной.
	 * \param symInst Контекст симметричного шифрования.
	 * \param symInst_export Контекст для импорта и защиты контейнера.
	 * \param container Контейнер с симметричны ключом.
	 * \param lenOfContainer Длина контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sym_importKeyBySymAlg(void* symInst, void* symInst_export, const uint8_t* container,
		uint32_t lenOfContainer, int32_t* error_out);
	/**
	 * \brief Экспортирует ключ в контейнере защищенном на другом симметричном алгоритма (контексте). Не является потокобезопасной.
	 * \param symInst Контекст симметричного шифрования.
	 * \param symInst_export Контекст для экспорта и защиты контейнера.
	 * \param lenOfContainer_out Выходная длина контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контейнер с ключом.
	 */
	EXPORT void* CDECL sym_exportKeyBySymAlg(void* symInst, void* symInst_export, uint32_t* lenOfContainer_out, int32_t* error_out);
	/**
	 * \brief Импортирует ключ в контейнере, защищенном ассиметричным алгоритмом или паре ключей. Не является потокобезопасной.
	 * \param symInst Контекст симметричного шифрования.
	 * \param assymetricEncrypterInst Контекст для ассиметричного шифрования.
	 * \param container Контейнер с симметричны ключом.
	 * \param lenOfContainer Длина контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sym_importKeyByAssymetricEncrypter(void* symInst, void* assymetricEncrypterInst, const uint8_t* container,
		uint32_t lenOfContainer, int32_t* error_out);
	/**
	 * \brief Экспортирует ключ в контейнере, защищенном ассиметричным алгоритмом или паре ключей. Не является потокобезопасной.
	 * \param symInst Контекст симметричного шифрования.
	 * \param assymetricEncrypterInst Контекст для ассиметричного шифрования.
	 * \param lenOfContainer_out Выходная длина контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контейнер с симметричны ключом.
	 */
	EXPORT void* CDECL sym_exportKeyByAssymetricEncrypter(void* symInst, void* assymetricEncrypterInst, 
		uint32_t* lenOfContainer_out, int32_t* error_out);
	/**
	 * \brief Импортирует к контекст ключ в защищенном на пароле контейнере. Не является потокобезопасной.
	 * \param symInst Контекст симметричного шифрования.
	 * \param pass Пароль для контейнера.
	 * \param container Контейнер с симметричным ключом.
	 * \param lenOfContainer Длина контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sym_importKeyByPass(void* symInst, const mchar* pass, const uint8_t* container, uint32_t lenOfContainer,
		int32_t* error_out);
	/**
	 * \brief Экспортирует ключ шифрования в контейнере, защищенном на пароле. Не является потокобезопасной.
	 * \param symInst Контекст симметричного шифрования.
	 * \param pass Пароль для контейнера.
	 * \param lenOfContainer_out Выходная длина контейнера.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контейнер с симметричным ключом.
	 */
	EXPORT void* CDECL sym_exportKeyByPass(void* symInst, const  mchar* pass, uint32_t* lenOfContainer_out, int32_t* error_out);
	/**
	 * \brief Расшифровывает входную последовательность байт. Функция потокобезопасна.
	 * \param symInst Контекст симметричного шифрования.
	 * \param data Последовательность байт для расшифрования.
	 * \param lenOfData Длина последовательности. Длина должна быть кратна размеру блока.
	 * \param result Указатель на память куда запишется результат.
	 * \param lenOfResult Длина буфера для результирующей последовательности. Длина должна быть кратна размеру блока.
	 * \param iv Вектор инициализации.
	 * \param lenOfIv Длина вектора инициализации.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sym_decrypt(void* symInst, const uint8_t* data, uint32_t lenOfData, uint8_t* result, uint32_t lenOfResult,
		const uint8_t* iv, uint32_t lenOfIv, int32_t* error_out);
	/**
	 * \brief Шифрует указанную последовательность байт. Функция потокобезопасна.
	 * \param symInst Контекст симметричного шифрования.
	 * \param data Последовательность байт для шифрования.
	 * \param lenOfData Длина последовательности.
	 * \param result Указатель на память куда запишется результат.
	 * \param lenOfResult Длина буфера для результирующей последовательности. Длина должна быть кратна размеру блока.
	 * \param iv Вектор инициализации.
	 * \param lenOfIv Длина вектора инициализации.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sym_encrypt(void* symInst, const uint8_t* data, uint32_t lenOfData, uint8_t* result, uint32_t lenOfResult,
		const uint8_t* iv, uint32_t lenOfIv, int32_t* error_out);
	/**
	 * \brief Устанавливает симметричный ключ в контекст. Не является потокобезопасной.
	 * \param symInst Контекст симметричного шифрования.
	 * \param key Симметричный ключ, который требуется установить в контекст.
	 * \param lenOfKey Длина ключа в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sym_setKey(void* symInst, const uint8_t* key, uint32_t lenOfKey, int32_t* error_out);
	EXPORT void* CDECL sym_getKey(void* symInst, uint32_t* len_out, int32_t* error_out);
	/**
	 * \brief Удаляет контекст симметричного шифрования. Функция потокобезопасна.
	 * \param cryptoContext Главный крипто контекст.
	 * \param symInst Контекст симметричного шифрования.
	 * \return Булевый флаг обозначающий результат проверки удаления контекста.
	 * Если значение true - контекст удален успешно, если false - произошла ошибка.
	 */
	EXPORT bool CDECL sym_deleteInst(void* cryptoContext, void* symInst);
	/**
	 * \brief Создает контекст для симметричного шифрования. Не является потокобезопасной.
	 * \param cryptoContext Главный крипто контекст.
	 * \param algDef Идентификатор алгоритма симметричного шифрования.
	 * \param mode Режим симметричного шифрования.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контекст для симметричного шифрования.
	 */
	EXPORT void* CDECL sym_createSymAlgInstance(void* cryptoContext, int32_t algDef, int32_t mode, int32_t* error_out);
	EXPORT void* CDECL sym_createSymAlgInstance_pass(void* cryptoContext, const char * pass, uint32_t lenOfPass, 
		const uint8_t* salt, uint32_t lengthOfSalt, int32_t* error_out);
}