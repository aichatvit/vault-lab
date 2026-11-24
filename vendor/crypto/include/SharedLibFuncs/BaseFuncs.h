/** @file BaseFuncs.h
 * Базовые функций криптоплагина.
 *
 * Функции необходимые для начала работы с крипто плагином. Тут есть функции для инициализации главного контекста плагина,
 * для освобождения памяти, выделенной при работе криптоплагина. Так же есть функции, которые работают в portable режиме,
 * без использования сторонних крипто контекстов.
 *
 * Инициализация крипто плагина. Инициализация крипто плагина происходит, в общем случае, с помощью случайной последовательности.
 * Эта последовательность должна быть случайной и может, например, браться от БДСЧ. После инициализации плагина,
 * все случайные последовательности вырабатываемы внутри него происходят с помощью специального алгоритма.
 * При создании ключевого контейнера последовательность сохраняется в нем и
 * далее этот контейнер тоже может быть использован для инициализации главного контекста плагина.
 */
#pragma once

#include <cstdint>

#include "../Common/mstring.h"
#include "../Common/SharedLibFuncsAtr.h"

extern "C"
{
/**
	 * \brief Создает контейнер симметричного ключа используя ассиметричную пару из ККП и пароль от него.
	 * Данной функции не требуются другие криптоконтексты, она работает в portable режиме. Не является потокобезопасной.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param kkp ККП.
	 * \param lenOfKkp Длина ККП в байтах. 
	 * \param pass Пароль от ККП.
	 * \param sizeOfContainer_out Выходная длина контейнера.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Контейнер симметричного ключа.
	 */
	EXPORT void* CDECL createSymKeyContainerOnKkp(void* cryptoContext, void* kkp, uint32_t lenOfKkp, const mchar* pass,
		uint32_t* sizeOfContainer_out, int32_t* error_out);

/**
	 * \brief Извлекает симметричный ключ из контейнера защищенного на ассиметричной паре из ККП на пароле. Не является потокобезопасной.
	 * Данной функции не требуются другие криптоконтексты, она работает в portable режиме.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param kkp ККП.
	 * \param lenOfKkp Длина ККП в байтах. 
	 * \param pass Пароль от ККП.
	 * \param symKeyContainer Контейнер симметричного ключа.
	 * \param lenOfSymKeyContainer Длина контейнера симметричного ключа.
	 * \param lenOfKey_out Длина выходного симметричного ключа.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на память в которой записан симметричный ключ, извлеченный из контейнера.
	 */
	EXPORT void* CDECL getSymKeyFromContainerOnKkp(void* cryptoContext, void* kkp, uint32_t lenOfKkp, const mchar* pass,
		void* symKeyContainer, uint32_t lenOfSymKeyContainer, uint32_t* lenOfKey_out,
		int32_t* error_out);
/**
	 * \brief Создает крипто контекст последовательностью, подписанной с использованием контейнера, защищенном на пароле. Функция потокобезопасна.
	 * \param containerBeginRawPtr Контейнер, защищенный на пароле, с помощью которого подписана последовательность для инициализации.
	 * \param sizeOfContainer Длина контейнера в байтах.
	 * \param pass Пароль для контейнера.
	 * \param seq_rand_rawPtr Случайная последовательность для инициализации крипто контекста.
	 * \param lenOfSeq Длина случайной последовательности в байтах.
	 * \param sign_rawPtr Подпись случайной последовательности.
	 * \param lenOfSign Длина подписи в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на созданный криптоконтекст.
	 */
	EXPORT void* CDECL createCryptoContextBySignSeq(const uint8_t* containerBeginRawPtr, uint32_t sizeOfContainer,
		const mchar* pass, const uint8_t* seq_rand_rawPtr, uint32_t lenOfSeq, const uint8_t* sign_rawPtr,
		uint32_t lenOfSign, int32_t* error_out);
/**
	 * \brief Создает и инициализирует крипто контекст с использованием ккп. Функция потокобезопасна.
	 * \param containerBeginRawPtr Контейнер для инициализации крипто контекста.
	 * \param sizeOfContainer Длина контейнера в байтах.
	 * \param pass Пароль для контейнера.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на созданный криптоконтекст.
	 */
	EXPORT void* CDECL createCryptoContextByKkp(uint8_t* containerBeginRawPtr, size_t sizeOfContainer, mchar* pass, int32_t* error_out);
/**
	 * \brief Создает главный криптоконтекст криптоплагина. Функция потокобезопасна.
	 * \param seq_bytes Последовательность байтов от БДСЧ для инициализации ПДСЧ плагина.
	 * \param lenOfSeq длина последовательности в байтах.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на созданный криптоконтекст.
	 */
	EXPORT void* CDECL createCryptoContext(const void* seq_bytes, uint32_t lenOfSeq, int32_t* error_out);
	EXPORT void* CDECL createCryptoContextByParams(const void* params, int32_t* error_out);
/**
	 * \brief Освобождает память выделенную для хранения главного крипто контекста. Функция потокобезопасна.
	 * \param cryptoContext Криптоконтекст.
	 * \return Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL destroyCryptoContext(void* cryptoContext);

/**
	 * \brief Создает защищенный контейнер с парой открытого и закрытого ключа на пароле. Не является потокобезопасной.
	 * Функция предназначена для создание контейнера без использвования других криптоконтекстов, в portable режиме.
	 * Далее, созданный контейнер может использваться, например, для инициализации криптоконтекста.
	 * \param cryptoContext Главный криптоконтекст.
	 * \param pass Пароль для защиты контейнера.
	 * \param sizeOfKkp_out Выходная длина криптоконтейнера.
	 * \param error_out Указатель на код ошибки. Сюда будет записан код ошибки.
	 * \return Указатель на память содержащую криптоконтейнер с ассиметричной парой, защищенный на пароле.
	 */
	EXPORT void* CDECL createKkp(void* cryptoContext, const mchar* pass, uint32_t* sizeOfKkp_out,
		int32_t* error_out);
/**
	 * \brief Освобождает память выделенную из криптоплагина. Функция потокобезопасна.
	 * \param cryptoContext Указатель на главный криптоконтекст.
	 * \param mem Указатель на память.
	 * \param length Длина в байтах.
	 * \return Булевый флаг обозначающий успешность операции. Если значение true - операция прошла успешно,
	 * если false - операция завершилась с ошибкой.
	 */
	EXPORT bool CDECL destroyMemory(void* cryptoContext, void* mem, uint32_t length);

	EXPORT void* CDECL getErrorsCodes(uint32_t* lengthInBytes_out, uint32_t flags, void* context);
}