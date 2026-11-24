/** @file HmacAlgDef.h
 * @brief Идентификаторы поддерживаемых алгоритмов hmac.
 */

#pragma once

#include <cstdint>

/**
 * \brief Идентификаторы алгоритмов hmac.
 */
enum class HmacAlgDef : int32_t
{
	/**
	 * \brief Р 50.1.113_2016.
	 */
	HMAC_GOSTR3411_2012
};

/**
 * \brief Возможные значения длины выходной последовательности hmac.
 */
enum class HmacLen : int32_t
{
	/**
	 * \brief Длина выходной последовательности 32 байта.
	 */
	Hmac_256_bit,
	/**
	 * \brief Длина выходной последовательности 64 байта.
	 */
	Hmac_512_bit,
};