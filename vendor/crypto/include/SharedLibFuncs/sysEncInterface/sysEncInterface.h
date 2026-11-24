#pragma once

#include <cstdint>

#include "../../Common/SharedLibFuncsAtr.h"

extern "C" {
	/**
	 * \brief Создает контейнер для симметричного ключа на пароле. 
	 * \param symKey Указатель на симметричный ключ.
	 * \param lenOfSymKey Длина симметричного ключа в байтах.
	 * \param pass Указатель на пароль для защиты контейнера.
	 * \param pass_encoding Идентификатор кодировки для пароля. На данный момент не используется.
	 * \param lenOfPass Длина пароля.
	 * \param buf_symKeyContainer_out Указатель на область памяти для записи контейнера. 
	 Если указатель равен нулю, в пареметре lenOfSymKeyContainer_out возвращается необходимое колличество байт.
	 * \param lenOfSymKeyContainer_out Указатель на необходимую длину в байтах области памяти для записи контейнера. 
	 Если параметр buf_symKeyContainer_out имеет значение null, то в lenOfSymKeyContainer_out записывается необходимое колличество байт.
	 * \param flags Дополниетельные флаги устанавливающие поведение функции. На данный момент не используется.
	 * \return Стутус код результата работы функции. Используются значения из перечисления ErrorCodes.
	 */
	EXPORT int32_t CDECL encSymKey(const void* symKey, const uint32_t lenOfSymKey, const char* pass, const int32_t pass_encoding,
		const uint32_t lenOfPass, void* buf_symKeyContainer_out, uint32_t* lenOfSymKeyContainer_out, const int32_t flags);
	/**
	 * \brief Извлекает симметричный ключ из контейнера на пароле. 
	 * \param symKeyContainer Указатель на защищенный контейнер на пароле.
	 * \param lenOfSymKeyContainer Длина контейнера в байтах.
	 * \param pass Указатель на пароль для защиты контейнера.
	 * \param pass_encoding Идентификатор кодировки для пароля. На данный момент не используется.
	 * \param lenOfPass Длина пароля.
	 * \param buf_symKey_out Указатель на область памяти для записи извлеченного симметричного ключа.
	 * \param lenOfSymKey Длина области памяти для записи симметричного ключа в байтах.
	 * \param flags Дополниетельные флаги устанавливающие поведение функции. На данный момент не используется.
	 * \return Стутус код результата работы функции. Используются значения из перечисления ErrorCodes.
	 */
	EXPORT int32_t CDECL decSymKey(const void* symKeyContainer, const uint32_t lenOfSymKeyContainer, const char* pass,
		const int32_t pass_encoding, const uint32_t lenOfPass, void* buf_symKey_out, uint32_t lenOfSymKey, 
		const int32_t flags);
	/**
	 * \brief Заполянет буфер случайной последовательностью.
	 * \param seq Указатель на буфер для записи случайной последовательноти.
	 * \param lenOfSeq Длина буфера в байтах.
	 * \param flags Дополниетельные флаги устанавливающие поведение функции. На данный момент не используется.
	 * \return Стутус код результата работы функции. Используются значения из перечисления ErrorCodes.
	 */
	EXPORT int32_t CDECL setRandomSeq(void* seq, const uint32_t lenOfSeq, const int32_t flags);

	/**
	 * \brief Реализует упрощенную версию функции симметричного шифрования входного буфера.
	 * \param algDef Идентификатор алгоритма шифрования. Для шифрования используется Кузнечик. 
	 Сам идентификатор на данный момент не используется.
	 * \param mode Идентификатор режима шифрования. Используется режим шифрования CBC. 
	 * Сам идентификатор на данный момент не используется.
	 * \param seqToEnc Указатель на буфер для шифрования.
	 * \param lenOfSeqToEnc_in_out Длина буфера для шифрования. 
	 Используется для утановки необходимой длины для размещения зашифрованной последовательности.
	 * \param key Указатель на симметричный ключ, на котором будет шифроваться буфер seqToEnc.
	 * \param keyLen Длина симметричного ключа.
	 * \param result_out Указатель на буфер для записи выходной зашифрованной последовательности.
	 * \param iv Указатель на вектор иниицализации, который будет использоваться при шифровании буфера seqToEnc.
	 * \param lenOfIv Длина вектора иниицализации в байтах.
	 * \param flags Дополниетельные флаги устанавливающие поведение функции. На данный момент не используется.
	 * \return Стутус код результата работы функции. Используются значения из перечисления ErrorCodes.
	 */
	EXPORT int32_t CDECL encBySymKey(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);
	/**
	 * \brief Реализует упрощенную версию функции симметричного расшифрования входного буфера.
	 * \param algDef Идентификатор алгоритма шифрования. Для шифрования используется Кузнечик.
	 Сам идентификатор на данный момент не используется.
	 * \param mode Идентификатор режима шифрования. Используется режим шифрования CBC.
	 * Сам идентификатор на данный момент не используется.
	 * \param seqToDec Указатель на буфер для расшифрования.
	 * \param lenOfSeqToDec Длина буфера для расшифрования.
	 Используется для утановки необходимой длины для размещения зашифрованной последовательности.
	 * \param key Указатель на симметричный ключ, на котором будет шифроваться буфер seqToEnc.
	 * \param keyLen Длина симметричного ключа.
	 * \param result_out Указатель на буфер для записи выходной расшифрованной последовательности.
	 * \param iv Указатель на вектор иниицализации, который будет использоваться при шифровании буфера seqToEnc.
	 * \param lenOfIv Длина вектора иниицализации в байтах.
	 * \param flags Дополниетельные флаги устанавливающие поведение функции. На данный момент не используется.
	 * \return Стутус код результата работы функции. Используются значения из перечисления ErrorCodes.
	 */
	EXPORT int32_t CDECL decBySymKey(const int32_t algDef, const int32_t mode, const void* seqToDec, const uint32_t lenOfSeqToDec, 
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);
	EXPORT int32_t CDECL encBySymKey_co(const int32_t algDef, const int32_t mode, const void* seqToEnc, uint32_t* lenOfSeqToEnc_in_out,
		const void* key, const uint32_t keyLen, void* result_out, const void* iv, const uint32_t lenOfIv, const int32_t flags);
	EXPORT int32_t CDECL decBySymKey_co(const void* container, const uint32_t len_of_container, const void* key, const uint32_t keyLen,
		void* result_out, uint32_t* result_len_in_out, const int32_t flags);
}