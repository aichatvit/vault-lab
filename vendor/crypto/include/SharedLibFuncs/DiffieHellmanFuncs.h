/** @file DiffieHellmanFuncs.h
 * Функции согласования ключа.
 *
 * Функции согласования ключа используются для выработки секретного ключа между участниками обмена информации
 * с использованием асимметричной криптографии (пары открытого и закрытого ключа). Секретный ключ, в дальнейшем,
 * может быть использован для симметричного шифрования. Для работоспособности алгоритма участники, обязательно, должны иметь
 * открытый ключ противоположной стороны, но, в зависимости от реализации, могут быть и другие параметры,
 * которые необходимо предварительно согласовать.
 *
 * Для использования функций согласования ключа требуется создание специального крипто контекста
 * с указанием идентификатора требуемого алгоритма. Поддерживается возможность импорта пары открытого и закрытого ключа в контейнере,
 * а так же одного открытого ключа в незащищенном виде. Процедура экспорта ключа, полученного в результате работы алгоритма,
 * возвращает его в защищенном контейнере на пароле. Далее можно выполнить импорт этого контейнера в контекст симметричного шифрования.
 */
#pragma once

//DiffieHellmanFuncs
#include <cstdint>

#include "../Common/SharedLibFuncsAtr.h"
#include "../Common/mstring.h"

extern "C"
{
/**
	 * \brief Устанавливает секретные параметры в контекст. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param memory Секретные параметры.
	 * \param size Длина последовательности с секретными параметрами.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL DiffieHellman_setAdditionalPrivateParams(void* diffContext, const void* memory, uint32_t size, int32_t* error_out);
	/**
	 * \brief Возвращает секретные параметры из контекста согласования ключа. Эти параметры зависят от реализации. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param size_out Выходная длина возвращаемой последовательности.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Секретные параметры.
	 */
	EXPORT void* CDECL DiffieHellman_getAdditionalPrivateParams(void* diffContext, uint32_t* size_out, int32_t* error_out);
	/**
	 * \brief Экспортирует согласованный симметричный ключ в контейнере на пароле. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param pass Пароль для контейнера.
	 * \param len_out Длина контейнера в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Выходной контейнер.
	 */
	EXPORT void* CDECL DiffieHellman_exportDerivedKeyMaterialByPass(void* diffContext, const mchar* pass, uint32_t* len_out, 
		int32_t* error_out);
	/**
	 * \brief Выполняет итерацию согласования ключа. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param seq Входная последовательность для итерации.
	 * \param lenOfSeq Длина последовательности.
	 * \param len_out Выходная длина выходной последовательности.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \param finish Указывает, является ли итерация согласования ключа последней для данной стороны процесса.
	 * \return Выходная последовательность, предназначенная для передачи на другую сторону для продолжения процесса согласования.
	 */
	EXPORT void* CDECL DiffieHellman_deriveKeyMaterial(void* diffContext, void* seq, uint32_t lenOfSeq, uint32_t* len_out,
		int32_t* error_out, bool* finish);
	/**
	 * \brief Экспортирует открытые параметры из контекста. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param includeAllPublicData Указывает на то, нужно ли экспортировать все открытые параметры или нужно, например,
	 * экспортировать только открытый ключ.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Открытые параметры.
	 */
	EXPORT void* CDECL DiffieHellman_exportPublicData(void* diffContext, bool includeAllPublicData, uint32_t* len_out, 
		int32_t* error_out);
	/**
	 * \brief Импортирует открытые параметры, например открытый ключ, в контекст. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param publicData Указатель на последовательность байт, содержащую открытые параметры для контекста согласования ключей.
	 * \param lenOfPublicData Длина последовательности.
	 * \param includeAllPublicData Указывает на то, нужно ли импортировать все открытые параметры или нужно, например,
	 * импортировать только открытый ключ.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 */
	EXPORT bool CDECL DiffieHellman_importPublicData(void* diffContext, void* publicData, uint32_t lenOfPublicData,
		bool includeAllPublicData, int32_t* error_out);
	/**
	 * \brief Экспортирует ассиметричную пару в защищенном контейнере. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param pass Пароль для контейнера.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контейнер с парой ключей.
	 */
	EXPORT void* CDECL DiffieHellman_exportByPass(void* diffContext, const mchar* pass, uint32_t* size_out, int32_t* error_out);
	/**
	 * \brief Импортирует пару ключей в защищенном контейнере на пароле. Не является потокобезопасной.
	 * \param diffContext Контекст согласования ключей.
	 * \param container Защищенный контейнер.
	 * \param lenOfContainer Длина контейнера в байтах.
	 * \param pass Пароль от контейнера.
	 * \return Код ошибки.
	 */
	EXPORT bool CDECL DiffieHellman_importByPass(void* diffContext, const uint8_t* container, uint32_t lenOfContainer,
		const mchar* pass, int32_t* error_out);
	/**
	 * \brief Удаляет ассиметричный контекст. Функция потокобезопасна.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param diffContext Контекст согласования ключей.
	 * \return Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL DiffieHellman_deleteDiffHellInst(void* cryptoContext, void* diffContext);
	/**
	 * \brief Создает и инициализирует контекст для выработки согласованного ключа с использованием ассиметричной криптографии. Не является потокобезопасной.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param algDef Идентификатор алгоритма согласования ключа. Идентификаторы описываются в DiffieHellmanAlgDef.h
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контекст согласования ключей.
	 */
	EXPORT void* CDECL DiffieHellman_createDiffHellInst(void* cryptoContext, int32_t algDef, int32_t* error_out);
}
