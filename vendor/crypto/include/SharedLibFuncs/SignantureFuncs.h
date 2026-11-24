/** @file SignantureFuncs.h
 * @brief Функции формирования и проверки подписи. Данные функции используются для формирования и проверки
 * электронной цифровой подписи.
 *
 * Подпись необходима для проверки подлинности или авторства передаваемой информации.
 * При формировании подписи используется пара ключей: открытый и закрытый. Когда информация подписана,
 * любой обладающий отрытым ключом может проверить эту подпись.
 *
 * Для работы с данными функциями требуется создать контекст с идентификатором конкретного алгоритма подписи.
 * При создании контекста, с использованием ПДСЧ, вырабатывается ключ подписи (приватный ключ)
 * и ключ проверки подписи (открытый ключ). Поддерживается экспорт ключевой информации в виде контейнеров, защищенных паролем.
 */
#pragma once

#include <cstdint>

#include "../Common/SharedLibFuncsAtr.h"
#include "../Common/mstring.h"

extern "C"
{
/**
	 * \brief Экспортирует открытые параметры алгоритма из контекста для проверки подписи. Не является потокобезопасной.
	 * \param signContext Контекст для проверки подписи.
	 * \param len_out Выходная длина последовательности байтов с открытыми параметрами экспортированными из контекста.
	 * \param includeAllPublicData Если значение true - будут экспортироваться все открытые параметры,
	 * если false - то будет экспортироваться только открытый ключ.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на выходную последовательность с открытыми параметрами.
	 */
	EXPORT void* CDECL sign_exportPublicData(void* signContext, uint32_t* len_out, bool includeAllPublicData, 
		int32_t* error_out);
	/**
	 * \brief Импортирует открытые параметры алгоритма в контекст для проверки подписи. Не является потокобезопасной.
	 * \param signContext Контекст для проверки подписи.
	 * \param publicData Открытые параметры.
	 * \param lenOfPublicData Длина последовательности с открытыми параметрами в байтах.
	 * \param includeAllPublicData Если значение true - будут импортироваться все параметры,
	 * если false - то будет импортироваться только открытый ключ.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL sign_importPublicData(void* signContext, void* publicData, uint32_t lenOfPublicData,
		bool includeAllPublicData, int32_t* error_out);
	/**
	 * \brief Проверяет подпись для входной последовательности байтов. Не является потокобезопасной.
	 * \param signContext Контекст для проверки подписи.
	 * \param dataRawPtr Указатель на последовательность байтов от которой была взята подпись.
	 * \param sizeOfData Длина последовательности.
	 * \param signRawPtr Указатель на подпись.
	 * \param sizeOfSign Длина подписи в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Булевый флаг обозначающий результат проверки подписи для входной последовательности.
	 * Если значение true - проверка прошла успешно и подпись верна, 
	 * если false - подпись не верна и проверка завершилась ошибкой.
	 */
	EXPORT bool CDECL sign_verify(void* signContext, uint8_t* dataRawPtr, uint32_t sizeOfData, uint8_t* signRawPtr,
		uint32_t sizeOfSign, int32_t* error_out);
	/**
	 * \brief Создает подпись для указанной последовательности байтов. Не является потокобезопасной.
	 * \param signContext Контекст для проверки подписи.
	 * \param dataRawPtr Указатель на последовательность байтов.
	 * \param sizeOfData Длина последовательности.
	 * \param sizeOfSign_out Указатель на выходную длину подписи в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на созданную подпись последовательности.
	 */
	EXPORT void* CDECL sign(void* signContext, const uint8_t* dataRawPtr, uint32_t sizeOfData, uint32_t* sizeOfSign_out,
		int32_t* error_out);
	/**
	 * \brief Экспортирует ключевую пару из контекста в защищенном контейнере на пароле. Не является потокобезопасной.
	 * \param signContext Контекст для проверки подписи.
	 * \param pass Пароль для контейнера.
	 * \param len_out Указатель на выходную длину контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на созданный контейнер с ключевой парой из контекста.
	 */
	EXPORT void* CDECL sign_exportByPass(void* signContext, const mchar* pass, uint32_t* len_out, int32_t* error_out);
	/**
	 * \brief Импортирует пару ключей в защищенном на пароле контейнере. Не является потокобезопасной.
	 * \param signContext Контекст для проверки подписи.
	 * \param container Контейнер с парой ключей, защищенный на пароле.
	 * \param lenOfContainer Длина контейнера в байтах.
	 * \param pass Пароль.
	 * \return Код ошибки.
	 */
	EXPORT bool CDECL sign_importByPass(void* signContext, void* container, size_t lenOfContainer,
		const mchar* pass, int32_t* error_out);
	/**
	 * \brief Создает контекст для проверки подписи. Не является потокобезопасной.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param algDef Идентификатор алгоритма проверки подписи. Файл SignAlgDef.h.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на контекст для проверки подписи.
	 */
	EXPORT void* CDECL sign_createSignAlgInstanse(void* cryptoContext, int32_t algDef, int32_t* error_out);
	/**
	 * \brief Удаляет контекст для проверки подписи. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param signContext Контекст для проверки подписи.
	 * \return Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL sign_deleteSignInst(void* cryptoContext, void* signContext);
}