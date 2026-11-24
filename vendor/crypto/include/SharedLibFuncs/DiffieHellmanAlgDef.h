/** @file DiffieHellmanAlgDef.h
 * @brief Идентификаторы поддерживаемых алгоритмов согласования ключа.
 */

#pragma once

#include <cstdint>

enum class DiffieHellmanAlgDef : int32_t
{
	/**
	 * \brief Схема выработки общего ключа с аутентификацией «Эхинацея-3»
	 */
	Echinacea
};